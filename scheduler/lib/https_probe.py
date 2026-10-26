#!/usr/bin/env python3
# 对候选 IP 做「真实 HTTPS 校验」：SNI 与 Host 都用目标域名，
# 因此能发现 Cloudflare 1034（"Cloudflare is currently unable to resolve..."）、
# 证书不匹配、5xx 等「TCP 通但实际不可用」的 IP。
# 用法: python3 https_probe.py <domain> <port> <timeout> <concurrency>
# 输入(stdin): 每行 "ip" 或 "ip tcp_ms"
# 输出(stdout): "ip 状态 https_ms"  状态 = ok / cf1034 / cert / timeout / fail / http5xx
import concurrent.futures
import re
import socket
import ssl
import sys
import time

CF_ERR = re.compile(r"[Ee]rror(?:\s+code:?)?\s+(10\d\d)", re.I)
STATUS_RE = re.compile(r"^HTTP/1\.[01]\s+(\d{3})")


def read_head(ss, cap=24576):
    buf = b""
    while len(buf) < cap:
        try:
            d = ss.recv(4096)
        except Exception:
            break
        if not d:
            break
        buf += d
        if b"\r\n\r\n" in buf and len(buf) > 2048:
            break
    return buf


def check(item, domain, port, timeout):
    ip = item.split()[0]
    v6 = ":" in ip
    fam = socket.AF_INET6 if v6 else socket.AF_INET
    addr = (ip, port, 0, 0) if v6 else (ip, port)

    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    s = socket.socket(fam, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect(addr)
        try:
            ss = ctx.wrap_socket(s, server_hostname=domain)
        except ssl.SSLCertVerificationError:
            return ip, "cert", None
        except ssl.SSLError:
            return ip, "fail", None
        req = (
            "GET / HTTP/1.1\r\nHost: %s\r\n"
            "User-Agent: Mozilla/5.0 (compatible; mosdns-pref/1.0)\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n" % domain
        )
        ss.sendall(req.encode())
        raw = read_head(ss)
        dt = (time.time() - t0) * 1000.0
        text = raw.decode("utf-8", "replace")
        m = STATUS_RE.match(text)
        status = int(m.group(1)) if m else 0
        m2 = CF_ERR.search(text)
        if m2 and m2.group(1) == "1034":
            return ip, "cf1034", dt
        if m2:
            return ip, "cf" + m2.group(1), dt
        if status == 0:
            return ip, "fail", None
        if status >= 500:
            return ip, "http%d" % status, dt
        return ip, "ok", dt
    except socket.timeout:
        return ip, "timeout", None
    except Exception:
        return ip, "fail", None
    finally:
        try:
            s.close()
        except Exception:
            pass


def main():
    if len(sys.argv) < 4:
        return
    domain = sys.argv[1]
    port = int(sys.argv[2])
    timeout = float(sys.argv[3])
    conc = max(1, int(sys.argv[4])) if len(sys.argv) > 4 else 4

    items = [l.strip() for l in sys.stdin if l.strip()]
    if not items:
        return

    with concurrent.futures.ThreadPoolExecutor(max_workers=conc) as ex:
        for ip, st, ms in ex.map(lambda i: check(i, domain, port, timeout), items):
            print("%s %s %s" % (ip, st, "-" if ms is None else "%.1f" % ms))


if __name__ == "__main__":
    main()
