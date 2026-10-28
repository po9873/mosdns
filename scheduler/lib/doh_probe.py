#!/usr/bin/env python3
# ============================================================
# DoH 上游真探测（纯标准库）
#
# 不走系统 resolver、不调 curl，直接按「连 IP -> TLS(SNI=host) ->
# POST /dns-query -> 解析 DNS 报文」的顺序走一遍。
# 目的只有一个：写进配置之前，先确认这条上游现在真的能解析域名，
# 而不是把一条已经死掉的地址固化进 config.yaml。
#
# 命令行：
#   python3 doh_probe.py https://dns.alidns.com/dns-query
#   python3 doh_probe.py "https://dns.controld.com/dns-query 76.76.2.2"
#   python3 doh_probe.py --json https://a/x https://b/y
# ============================================================
import json
import socket
import ssl
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

DEFAULT_QNAME = "www.baidu.com"
DEFAULT_TIMEOUT = 6.0


def _wire_query(name, qtype=1, qid=None):
    """拼一个最小可用的 DNS 查询报文（单问题、RD=1）。"""
    if qid is None:
        qid = int.from_bytes(b"\x00\x00", "big") or 0x2A2A
    hdr = struct.pack(">HHHHHH", qid & 0xFFFF, 0x0100, 1, 0, 0, 0)
    q = b""
    for label in str(name).strip(".").split("."):
        lb = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode()
        if not lb or len(lb) > 63:
            raise ValueError("非法域名: %s" % name)
        q += bytes([len(lb)]) + lb
    q += b"\x00" + struct.pack(">HH", qtype, 1)
    return hdr + q, qid & 0xFFFF


def _dechunk(raw):
    out = b""
    while True:
        i = raw.find(b"\r\n")
        if i < 0:
            return out
        try:
            size = int(raw[:i].split(b";")[0].strip(), 16)
        except Exception:
            return out
        if size == 0:
            return out
        out += raw[i + 2:i + 2 + size]
        raw = raw[i + 2 + size + 2:]


def _http_body(raw):
    """从裸 HTTP 响应里取出 body，chunked / content-length 都处理。"""
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        return 0, b""
    lines = head.split(b"\r\n")
    status = 0
    try:
        status = int(lines[0].split(b" ")[1])
    except Exception:
        status = 0
    low = head.lower()
    if b"transfer-encoding:" in low and b"chunked" in low:
        body = _dechunk(body)
    elif b"content-length:" in low:
        for ln in lines[1:]:
            if ln.lower().startswith(b"content-length:"):
                try:
                    body = body[:int(ln.split(b":", 1)[1].strip())]
                except Exception:
                    pass
                break
    return status, body


def _rcode_of(payload, qid):
    if len(payload) < 12:
        return None, 0, "响应太短，不是 DNS 报文"
    rid, flags, qd, an = struct.unpack(">HHHH", payload[:8])
    if rid != qid:
        return None, 0, "响应 ID 不匹配"
    rcode = flags & 0x000F
    return rcode, an, None


_DEPRECATED_HINT = {
    2: "SERVFAIL（上游解析失败）",
    3: "NXDOMAIN（找不到该域名）",
    4: "NOTIMP（不支持该查询类型）",
    5: "REFUSED（上游拒绝服务）",
}


def _candidate_ips(host, port, boot=""):
    """按「手动 IP > IPv4 > IPv6」排好顺序，最多试 3 个。

    只试一个 IP 是不行的：容器里常常有 IPv6 地址却不通，
    第一跳拿到 v6 就直接判死，会把明明活着的上游误杀。
    """
    ips = []
    if boot:
        try:
            socket.inet_pton(socket.AF_INET6 if ":" in boot else socket.AF_INET, boot)
            ips.append(boot)
        except Exception:
            pass
    try:
        infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    except Exception as e:
        infos = []
        if not ips:
            raise e
    v4 = [i[4][0] for i in infos if i[0] == socket.AF_INET]
    v6 = [i[4][0] for i in infos if i[0] == socket.AF_INET6]
    for ip in v4 + v6:
        if ip not in ips:
            ips.append(ip)
    return ips[:3]


def _attempt(ip, host, port, scheme, path, qname, timeout):
    """对单个 IP 走一遍完整 DoH 查询。返回 (ok, err, rcode, answers, ms)。"""
    t0 = time.time()
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
    except Exception as e:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
        return False, "连不上 %s:%d（%s）" % (ip, port, getattr(e, "strerror", None) or e), None, 0, int((time.time() - t0) * 1000)

    try:
        body, qid = _wire_query(qname)
        req = (
            "POST %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: mosdns-ui/probe\r\n"
            "Accept: application/dns-message\r\n"
            "Content-Type: application/dns-message\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n\r\n" % (path, host, len(body))
        ).encode() + body
        sock.sendall(req)
        raw = b""
        while len(raw) < 262144:
            chunk = sock.recv(8192)
            if not chunk:
                break
            raw += chunk
            head, sep, rest = raw.partition(b"\r\n\r\n")
            if sep and b"content-length:" in head.lower():
                need = None
                for ln in head.split(b"\r\n"):
                    if ln.lower().startswith(b"content-length:"):
                        try:
                            need = int(ln.split(b":", 1)[1].strip())
                        except Exception:
                            need = None
                        break
                if need is not None and len(rest) >= need:
                    break
    except Exception as e:
        return False, "请求中断：%s" % (getattr(e, "strerror", None) or e), None, 0, int((time.time() - t0) * 1000)
    finally:
        try:
            sock.close()
        except Exception:
            pass

    if not raw:
        return False, "服务端没回任何数据", None, 0, int((time.time() - t0) * 1000)
    status, payload = _http_body(raw)
    if status != 200:
        return False, "HTTP %s（DoH 正常应返回 200）" % status, None, 0, int((time.time() - t0) * 1000)
    rcode, ans, bad = _rcode_of(payload, qid)
    if bad:
        return False, bad, None, 0, int((time.time() - t0) * 1000)
    if rcode != 0:
        return False, _DEPRECATED_HINT.get(rcode, "DNS 返回 rcode=%d" % rcode), rcode, ans, int((time.time() - t0) * 1000)
    if ans < 1:
        return False, "能连上但查不到 %s 的记录" % qname, rcode, ans, int((time.time() - t0) * 1000)
    return True, "", rcode, ans, int((time.time() - t0) * 1000)


def probe(entry, qname=DEFAULT_QNAME, timeout=DEFAULT_TIMEOUT):
    """探测一条上游，永远返回 dict，不抛异常。

    entry 形如 `https://host/dns-query` 或 `https://host/dns-query 1.2.3.4`
    （第二段是 dial_addr，强制走这个 IP，用于域名被污染的场景）。
    """
    line = str(entry or "").strip()
    res = {"line": line, "ok": False, "ms": 0, "err": "", "host": "", "ip": "", "rcode": None, "answers": 0}
    if not line:
        res["err"] = "空行"
        return res
    parts = line.split()
    url = parts[0]
    boot = parts[1].strip("[]") if len(parts) > 1 else ""
    u = urlparse(url)
    if u.scheme not in ("https", "http") or not u.hostname:
        res["err"] = "不是合法的 DoH 地址（需 http(s)://主机/路径）"
        return res
    host = u.hostname
    port = u.port or (443 if u.scheme == "https" else 80)
    path = u.path or "/dns-query"
    if u.query:
        path += "?" + u.query
    res["host"] = host

    try:
        ips = _candidate_ips(host, port, boot)
    except Exception as e:
        res["err"] = "域名解析不了：%s" % (getattr(e, "strerror", None) or e)
        return res
    if not ips:
        res["err"] = "域名解析不了：没有任何 A/AAAA 记录"
        return res

    errs = []
    for ip in ips:
        ok, err, rcode, ans, ms = _attempt(ip, host, port, u.scheme, path, qname, timeout)
        res["ip"] = ip
        if ok:
            res.update({"ok": True, "err": "", "rcode": rcode, "answers": ans, "ms": ms})
            return res
        errs.append("%s: %s" % (ip, err))
    res["err"] = "；".join(errs[:2])
    res["ms"] = 0
    return res


def probe_many(entries, qname=DEFAULT_QNAME, timeout=DEFAULT_TIMEOUT, workers=6):
    """并发探测，保持输入顺序返回。"""
    entries = [str(e).strip() for e in (entries or []) if str(e).strip()]
    if not entries:
        return []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(entries)))) as ex:
        return list(ex.map(lambda e: probe(e, qname, timeout), entries))


def pick_qname(entries, default=DEFAULT_QNAME):
    """国内上游查百度、国外上游查 google，跟启动探测保持一致。"""
    for e in entries or []:
        if not any(k in str(e) for k in ("223.5.5.5", "alidns", "dnspod", "qq.com", "114dns", "360")):
            return "www.google.com"
    return default


def main(argv):
    as_json = "--json" in argv
    items = [a for a in argv[1:] if a != "--json"]
    if not items:
        print("用法: doh_probe.py [--json] <entry> [entry...]", file=sys.stderr)
        return 2
    results = probe_many(items)
    if as_json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        for r in results:
            tag = "OK  " if r["ok"] else "FAIL"
            tgt = r["ip"] or r["host"]
            detail = ("%dms %d answers" % (r["ms"], r["answers"])) if r["ok"] else r["err"]
            print("%s %-52s %-22s %s" % (tag, r["line"], tgt, detail))
    return 0 if all(r["ok"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
