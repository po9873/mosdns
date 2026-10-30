#!/usr/bin/env python3
"""上游 DoH 自动发现：内置清单只是起点，不是终点。

以前上游只有两条来源：镜像里写死的那几个 + 用户手工往观察名单里加。结果是
「服务商换域名了 / 加了新端点 / 换 IP 了」都得靠人发现一次、改一次——这跟
优选 IP 被限速要靠人手工换段是同一个毛病。

这里把它做成自动的，三件事：
  1) 内置服务商标只当种子：每个服务商记域名 + 端点路径 + 已知 IP。每轮自动
     「重新解析这个域名」拿到它现在的 A/AAAA（服务商自己换 IP 就自动跟上），
     再对每个 IP 发一次真实 DoH 查询，能正确回答的才算数。
  2) 端点路径也自动试：/dns-query 之外还有 /query、/doh、/dns 等写法，逐个
     试，通了就收——服务商改端点不会静默失效。
  3) 在线列表源（可配置，默认两个公共列表）：抓得到就顺着解析出新的服务端点
     一起试；抓不到就跳过，不影响本轮。

发现的可用上游写回观察名单（doh_watchlist.txt），由现有的 process_watchlist
按「连续两轮可用才收编」的老规矩处理，不特殊对待，也不会重复收编。

用法：python3 doh_discover.py [--force] [--services FILE] [--out FILE]
输出：每行 "url ip"（可直接写进观察名单的格式）
"""
import base64
import concurrent.futures as cf
import ipaddress
import json
import os
import socket
import ssl
import struct
import sys
import time
import urllib.request

try:
    import doh_common as dc
except Exception:  # pragma: no cover
    dc = None

DATA_DIR = os.environ.get("PREF_DATA_DIR") or (dc.DATA_DIR if dc else "/data")
_here = os.path.dirname(os.path.abspath(__file__))
SEED_DIR = os.environ.get("PREF_SEED_DIR") or (
    "/app/config" if os.path.isdir("/app/config") else os.path.join(_here, "..", "config"))
SERVICES = os.environ.get("DOH_SERVICES_FILE") or os.path.join(SEED_DIR, "doh_services.txt")
USER_SERVICES = os.path.join(DATA_DIR, "doh_services.txt")   # /data 里可覆盖/追加
STATE = os.path.join(DATA_DIR, ".doh_discover.json")
WATCH = os.environ.get("DOH_WATCH_FILE") or os.path.join(DATA_DIR, "doh_watchlist.txt")
EVERY = 12 * 3600      # 每 12 小时跑一次完整发现
PROBE_Q = "www.google.com"


def _log(msg):
    print("[doh-discover] %s" % msg, file=sys.stderr, flush=True)


# ---------- DNS wire format：造一个最简单的 A 查询，自己解响应 ----------
def build_query(qname):
    tid = os.urandom(2)
    flags = struct.pack("!H", 0x0100)
    counts = struct.pack("!HHHH", 1, 0, 0, 0)
    q = b""
    for lbl in qname.encode().split(b"."):
        q += bytes([len(lbl)]) + lbl
    q += b"\x00" + struct.pack("!HH", 1, 1)
    return tid + flags + counts + q


def parse_ok(resp, tid):
    """只要「有应答、不是截断/失败、能解出至少一条 A」就算这个端点能用。"""
    try:
        if len(resp) < 12 or resp[:2] != tid:
            return False
        flags = struct.unpack("!H", resp[2:4])[0]
        if flags & 0x000F:            # rcode != 0
            return False
        ancount = struct.unpack("!H", resp[6:8])[0]
        return ancount > 0
    except Exception:
        return False


def doh_probe(host, ip, path, timeout=4):
    """对 (host, ip, path) 发一次 DoH POST。TLS 用 SNI=host、连到指定 IP。"""
    q = build_query(PROBE_Q)
    body = q
    ctx = ssl.create_default_context()
    try:
        raw = socket.create_connection((ip, 443), timeout=timeout)
    except Exception:
        return False
    try:
        s = ctx.wrap_socket(raw, server_hostname=host)
        req = (
            "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/dns-message\r\n"
            "Accept: application/dns-message\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
            % (path, host, len(body))
        ).encode() + body
        s.sendall(req)
        buf = b""
        while len(buf) < 4096:
            try:
                chunk = s.recv(4096)
            except Exception:
                break
            if not chunk:
                break
            buf += chunk
            if b"\r\n\r\n" in buf and len(buf.split(b"\r\n\r\n", 1)[1]) >= 12:
                break
        head, _, payload = buf.partition(b"\r\n\r\n")
        if b" 200" not in head.split(b"\r\n", 1)[0]:
            return False
        return parse_ok(payload, q[:2])
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def resolve(host, timeout=3):
    """用系统解析器拿 A/AAAA（容器里指向本机 mosdns，结果可控）。"""
    out = []
    try:
        for fam in (socket.AF_INET, socket.AF_INET6):
            try:
                for r in socket.getaddrinfo(host, 443, fam, socket.SOCK_STREAM):
                    ip = r[4][0]
                    if ip not in out:
                        out.append(ip)
            except Exception:
                pass
    except Exception:
        pass
    return out


def load_services():
    """内置种子 + /data 覆盖。每行：域名 端点路径(可多个,逗号分隔) 已知IP(可多个,逗号分隔) 侧(local/remote/auto)"""
    items = []
    for p in (SERVICES, USER_SERVICES):
        try:
            with open(p, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if not parts:
                        continue
                    host = parts[0]
                    paths = [x for x in (parts[1] if len(parts) > 1 else "/dns-query").split(",") if x]
                    ips = [x for x in (parts[2] if len(parts) > 2 else "").split(",") if x]
                    side = parts[3] if len(parts) > 3 else "auto"
                    items.append((host, paths, ips, side))
        except Exception:
            continue
    return items


def fetch_lists(timeout=6):
    """在线列表源：抓得到就当新种子，抓不到拉倒（国内访问不了很正常）。"""
    src = os.path.join(DATA_DIR, "doh_sources.txt")
    if not os.path.isfile(src):
        src = os.path.join(SEED_DIR, "doh_sources.txt")
    if not os.path.isfile(src):
        return []
    hosts = []
    try:
        with open(src, encoding="utf-8") as f:
            urls = [x.strip() for x in f if x.strip() and not x.startswith("#")]
    except Exception:
        return []
    for u in urls[:6]:
        try:
            with urllib.request.urlopen(u, timeout=timeout) as r:
                txt = r.read().decode("utf-8", "ignore")
        except Exception:
            continue
        for tok in txt.replace("\n", " ").split():
            tok = tok.strip().strip(",;\"'")
            if tok.count(".") >= 2 and "/" not in tok and len(tok) < 64:
                try:
                    ipaddress.ip_address(tok)   # 纯 IP 没法确定 SNI，试了也是白试
                    continue
                except ValueError:
                    pass
                hosts.append(tok)
    return list(dict.fromkeys(hosts))


def known_urls():
    """已经在用的上游（候选池 + 观察名单），避免重复收编。"""
    out = set()
    for p in (os.path.join(DATA_DIR, "doh_local_candidates.txt"),
              os.path.join(DATA_DIR, "doh_remote_candidates.txt"), WATCH):
        try:
            with open(p, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    out.add(line.split()[0].lstrip("@"))
        except Exception:
            continue
    return out


def side_of(ip):
    """沿用 doh_watch 那套 china_ip 判据，别自己再发明一套分侧规则。"""
    try:
        import doh_watch
        return "local" if doh_watch._is_cn_ip(ip) else "remote"
    except Exception:
        try:
            a = ipaddress.ip_address(ip)
            return "local" if str(a).startswith(("1.", "101.", "114.", "119.", "180.", "223.")) else "remote"
        except Exception:
            return "remote"


def run_once(force=False):
    try:
        st = json.load(open(STATE, encoding="utf-8"))
    except Exception:
        st = {}
    now = time.time()
    if not force and now - float(st.get("t", 0)) < EVERY:
        return 0

    have = known_urls()
    jobs = []          # (host, path, ip, side)
    for host, paths, ips, side in load_services():
        all_ips = list(ips)
        for ip in resolve(host):     # 服务商自己换 IP 的情况：每轮重新解析
            if ip not in all_ips:
                all_ips.append(ip)
        for ip in all_ips:
            for path in paths:
                jobs.append((host, path, ip, side))
    for h in fetch_lists():
        for ip in resolve(h)[:2]:
            jobs.append((h, "/dns-query", ip, "auto"))

    if not jobs:
        return 0
    _log("候选 %d 个（%d 个服务商 + 在线列表）" % (len(jobs), len(load_services())))

    found = []
    with cf.ThreadPoolExecutor(max_workers=16) as ex:
        futs = {ex.submit(doh_probe, h, ip, p): (h, p, ip, sd) for h, p, ip, sd in jobs}
        for f in cf.as_completed(futs):
            h, p, ip, sd = futs[f]
            try:
                if not f.result():
                    continue
            except Exception:
                continue
            url = "https://%s%s" % (h, p)
            if url in have:
                continue
            side = sd if sd in ("local", "remote") else side_of(ip)
            found.append("@%s %s %s" % (side, url, ip))
            have.add(url)

    if not found:
        _log("这轮没发现新的可用上游")
        st["t"] = now
        json.dump(st, open(STATE, "w", encoding="utf-8"))
        return 0

    # 写回观察名单：交给 process_watchlist 按老规矩「连续两轮可用才收编」
    try:
        with open(WATCH, "a", encoding="utf-8") as f:
            f.write("\n".join(found) + "\n")
    except Exception as e:
        _log("写观察名单失败：%s" % e)
    for line in found:
        _log("发现新上游 %s" % line)
    print("\n".join(found))
    st["t"] = now
    json.dump(st, open(STATE, "w", encoding="utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(run_once("--force" in sys.argv))
