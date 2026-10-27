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

# 吞吐样本可信门槛：只有真的传完 ≥32KB，算出来的 KB/s 才拿来判断「这台是不是慢了」。
# 为什么：同一个 IP、同一个地址，实测有 158 / 289 / 532 KB/s 三种结果——
# 64KB 是「一个 TCP 窗口就能塞完」的量，样本跨度只有 0.1~0.4s，抖动全落在里面，
# 用它判「变慢」会天天误触发全量重探（用户要的是「能用就别折腾」）。
# 小于门槛的样本仍然会显示（前面加 ~），只是不当判决依据。
SPEED_TRUST_BYTES = 32768


def _attempt(ip, domain, port, timeout):
    """跑一次完整探测，返回 (状态, ttfb_ms, speed_kbps, 是否估算)。"""
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
            return "cert", None, None, False
        except ssl.SSLError:
            return "fail", None, None, False
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
            return "cf1034", ttfb, None, False
        if m2:
            return "cf" + m2.group(1), ttfb, None, False
        if status == 0:
            return "fail", None, None, False
        if status >= 500:
            # 5xx 也顺手测速度，方便判断是节点挂了还是单纯慢
            return "http%d" % status, ttfb, None, False

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
        est = False
        if got >= BODY_MIN and span > 0.001:
            speed = (got / 1024.0) / span
            est = got < SPEED_TRUST_BYTES
        return "ok", ttfb, speed, est
    except socket.timeout:
        return "timeout", None, None, False
    except Exception:
        return "fail", None, None, False
    finally:
        try:
            s.close()
        except Exception:
            pass


def check(item, domain, port, timeout, samples=1):
    """对单个 IP 探测；samples>1 时多测几次取「最好的一次」。

    为什么要多测：单次吞吐会抖动（实测同一 IP 158/289/532 KB/s），拿一次结果
    就判「慢了」会误触发全量重探。只要任意一次证明它不慢，就不算慢。
    返回 (ip, 状态, ttfb, speed, 是否估算)。
    """
    ip = item.split()[0]
    best = None          # (状态, ttfb, speed, est)
    for _ in range(max(1, int(samples))):
        st, ttfb, speed, est = _attempt(ip, domain, port, timeout)
        if best is None:
            best = (st, ttfb, speed, est)
            continue
        if st == "ok" and best[0] != "ok":
            # 有一次能打开就算能用（别因一次抖动就判死）
            best = (st, ttfb, speed, est)
            continue
        if st != best[0] and best[0] == "ok":
            continue
        # 同状态（都 ok 或都失败）：响应取更快的，吞吐取更大的
        b_st, b_ttfb, b_sp, b_est = best
        nt = b_ttfb
        if ttfb is not None and (nt is None or ttfb < nt):
            nt = ttfb
        nsp, nest = b_sp, b_est
        if speed is not None:
            if nsp is None:
                nsp, nest = speed, est
            elif est != nest:
                # 可信样本永远优先于估算样本
                if not est:
                    nsp, nest = speed, est
            elif speed > nsp:
                nsp, nest = speed, est
        best = (st, nt, nsp, nest)
    return ip, best[0], best[1], best[2], best[3]


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
    samples = max(1, int(sys.argv[5])) if len(sys.argv) > 5 else 1

    items = [l.strip() for l in sys.stdin if l.strip()]
    if not items:
        return

    with concurrent.futures.ThreadPoolExecutor(max_workers=conc) as ex:
        for ip, st, ttfb, speed, est in ex.map(
                lambda i: check(i, domain, port, timeout, samples), items):
            sp = fmt(speed)
            if sp != "-" and est:
                sp = "~" + sp          # ~ 表示样本太小，只作参考、不参与「变慢」判定
            print("%s %s %s %s" % (ip, st, fmt(ttfb), sp))


if __name__ == "__main__":
    main()
