#!/usr/bin/env python3
# 对候选 IP 做「真实 HTTPS 校验 + 真实速度测量」：SNI 与 Host 都用目标域名，
# 因此能发现 Cloudflare 1034、证书不匹配、5xx 等「TCP 通但实际不可用」的 IP。
#
# 为什么不能只看延迟：TCP 握手快不等于能用/不慢。真正决定体验的是
#   TTFB（发出请求到收到响应头）和 下载吞吐（KB/s）。
# 所以这里同时测两样，输出给调度器写进 meta，界面直接显示速度。
#
# 用法: python3 https_probe.py <domain> <port> <timeout> <concurrency>
# 输入(stdin): 每行 "ip" 或 "ip tcp_ms"
# 输出(stdout): "ip 状态 ttfb_ms speed_kbps"
#   状态 = ok / cf1034 / cf10xx / cert / timeout / fail / http5xx
#   ttfb_ms / speed_kbps 未知时输出 "-"
import concurrent.futures
import re
import socket
import ssl
import sys
import time

CF_ERR = re.compile(r"[Ee]rror(?:\s+code:?)?\s+(10\d\d)", re.I)
STATUS_RE = re.compile(r"^HTTP/1\.[01]\s+(\d{3})")

BODY_CAP = 65536      # 最多读 64KB 用于估算速度，够准又不拖时间
BODY_MIN = 4096       # 少于 4KB 的响应体太小，算出来的速度没意义
BODY_BUDGET = 4.0     # 读 body 最多再花 4 秒


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
            return ip, "cert", None, None
        except ssl.SSLError:
            return ip, "fail", None, None
        req = (
            "GET / HTTP/1.1\r\nHost: %s\r\n"
            "User-Agent: Mozilla/5.0 (compatible; mosdns-pref/1.0)\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n" % domain
        )
        ss.sendall(req.encode())

        # ---- 读到响应头为止：TTFB ----
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 24576:
            try:
                d = ss.recv(4096)
            except Exception:
                break
            if not d:
                break
            buf += d
        ttfb = (time.time() - t0) * 1000.0

        head, _, body_head = buf.partition(b"\r\n\r\n")
        text = head.decode("utf-8", "replace")
        m = STATUS_RE.match(text)
        status = int(m.group(1)) if m else 0
        m2 = CF_ERR.search(buf.decode("utf-8", "replace"))
        if m2 and m2.group(1) == "1034":
            return ip, "cf1034", ttfb, None
        if m2:
            return ip, "cf" + m2.group(1), ttfb, None
        if status == 0:
            return ip, "fail", None, None
        if status >= 500:
            # 5xx 也顺手测速度，方便判断是节点挂了还是单纯慢
            return ip, "http%d" % status, ttfb, None

        # ---- 继续读 body：算下载吞吐 ----
        got = len(body_head)
        t_dl = time.time()
        deadline = t_dl + BODY_BUDGET
        while got < BODY_CAP and time.time() < deadline:
            try:
                d = ss.recv(16384)
            except Exception:
                break
            if not d:
                break
            got += len(d)
        span = time.time() - t_dl
        speed = None
        if got >= BODY_MIN and span > 0.001:
            speed = (got / 1024.0) / span
        return ip, "ok", ttfb, speed
    except socket.timeout:
        return ip, "timeout", None, None
    except Exception:
        return ip, "fail", None, None
    finally:
        try:
            s.close()
        except Exception:
            pass


def fmt(v, nd=0):
    if v is None:
        return "-"
    return ("%." + str(nd) + "f") % v


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
        for ip, st, ttfb, speed in ex.map(lambda i: check(i, domain, port, timeout), items):
            print("%s %s %s %s" % (ip, st, fmt(ttfb), fmt(speed)))


if __name__ == "__main__":
    main()
