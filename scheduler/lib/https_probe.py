#!/usr/bin/env python3
# 对候选 IP 做「真实 HTTPS 校验 + 真实速度测量」：SNI 与 Host 都用目标域名，
# 因此能发现 Cloudflare 1034、证书不匹配、5xx 等「TCP 通但实际不可用」的 IP。
#
# 为什么不能只看延迟：TCP 握手快不等于能用/不慢。真正决定体验的是
#   TTFB（发出请求到收到响应头）和 下载吞吐（KB/s）。
# 所以这里同时测两样，输出给调度器写进 meta，界面直接显示速度。
#
# 用法: python3 https_probe.py <domain> <port> <timeout> <concurrency> [samples] [path] [expect]
# 输入(stdin): 每行 "ip" 或 "ip tcp_ms"
# 输出(stdout): "ip 状态 ttfb_ms speed_kbps"
#   状态 = ok / wrong / blocked / busy / cf1034 / cf10xx / cert / timeout / fail / http5xx
#
# 为什么能传 path/expect：不同服务「能用」的样子不一样。
#   Google 翻译的根路径 / 本来就回 404（前端节点就这样），拿 GET / 判断，
#   会把所有真能用的翻译 IP 全判死；必须请求真实接口
#   /translate_a/single 并要求正文里出现译文 JSON，才算「真能用」。
#   expect 不合 → 状态 wrong（能连、证书也对，但这个地址不提供该服务）。
#   ttfb_ms / speed_kbps 未知时输出 "-"
import concurrent.futures
import re
import socket
import ssl
import sys
import time

CF_ERR = re.compile(r"[Ee]rror(?:\s+code:?)?\s+(10\d\d)", re.I)
STATUS_RE = re.compile(r"^HTTP/1\.[01]\s+(\d{3})")
LOC_RE = re.compile(r"(?im)^location:\s*(\S+)")

# 探针必须伪装成真实浏览器：Google 系对非浏览器 UA 直接回 429「Sorry...」，
# CloudFront 对脚本 UA 回 202/403 挑战页。用自造 UA 会被当成「这个 IP 不能用」，
# 实测却恰恰相反——同一 IP 换浏览器 UA 立刻返回 200 真内容/真译文。
# 探针的职责是「模拟用户浏览器能不能用」，所以 UA 必须和浏览器一致。
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
BROWSER_HDRS = ("User-Agent: %s\r\n"
                "Accept: */*\r\n"
                "Accept-Language: zh-CN,zh;q=0.9,en;q=0.8\r\n"
                "Connection: close\r\n\r\n" % BROWSER_UA)


def _same_site(host_a, host_b):
    """同站判定：只接受完全相同或仅差 www 前缀的跳转。

    以前按「末两段相同」粗略比较，结果 api.github.com 301 → github.com
    被当成同站跳转放行——网页边缘冒充 API 边缘全是从这个口子漏进来的。
    http→https 已由请求本身保证；域名 → www.域名 / www.域名 → 域名 这类
    正常跳转继续放行；其余（含子域跳父域、兄弟域）一律视为「不承载本服务」。"""
    a = host_a.strip(".").lower()
    b = host_b.strip(".").lower()
    if a == b:
        return True
    return a == "www." + b or b == "www." + a

BODY_CAP = 262144     # 最多读 256KB 用于估算速度
BODY_MIN = 4096       # 少于 4KB 的响应体太小，算出来的速度没意义
BODY_BUDGET = 6.0     # 读 body 最多再花 6 秒

# 吞吐样本可信门槛：只有真的传完 ≥32KB，算出来的 KB/s 才拿来判断「这台是不是慢了」。
# 为什么：同一个 IP、同一个地址，实测有 158 / 289 / 532 KB/s 三种结果——
# 64KB 是「一个 TCP 窗口就能塞完」的量，样本跨度只有 0.1~0.4s，抖动全落在里面，
# 用它判「变慢」会天天误触发全量重探（用户要的是「能用就别折腾」）。
# 小于门槛的样本仍然会显示（前面加 ~），只是不当判决依据。
SPEED_TRUST_BYTES = 32768


def _attempt(ip, domain, port, timeout, path="/", expect=None, strict_redirect=True):
    """跑一次完整探测，返回 (状态, ttfb_ms, speed_kbps, 是否估算)。

    strict_redirect：是否把「跳去别的站点」判成 wrong。

    只有探的是**该服务专属路径**（/v2/、/raw/...）时才该严格：那种路径正确
    应答本身就说明这个 IP 承载该服务，跳走 = 假边缘。

    探根路径 / 时必须关掉：很多服务首页天然跳产品页，ghcr.io 就是活例——
    GET / → 301 https://github.com/features/packages（registry 正常行为），
    被判跨站跳转后守护把刚优选出来的好 IP 全拉黑了，面板直接「没有优选结果」。
    """
    v6 = ":" in ip
    fam = socket.AF_INET6 if v6 else socket.AF_INET
    addr = (ip, port, 0, 0) if v6 else (ip, port)

    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    # 必须声明 ALPN，和浏览器一致。实测（google 翻译节点 8.138.x / 47.95.x）：
    # 握手不带 ALPN 时，对端会按「默认虚拟主机」应答，给出的是不相干域名
    # （CN=yaoqianmeiyong.site）的证书 → 被判定为 cert，浏览器访问实际正常。
    # 带上 http/1.1 之后证书就是正常 Google 证书，请求也能拿到真实结果。
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except Exception:
        pass

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
            "GET %s HTTP/1.1\r\nHost: %s\r\n%s" % (path or "/", domain, BROWSER_HDRS)
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
        if status == 429:
            # 对方限速：只是这一会儿忙，不代表这个 IP 坏了，别拉黑、也别写进 hosts
            return "busy", ttfb, None, False
        if status == 400:
            # GitHub 的「Whoa there!」/「Bad request」都是 400：TCP 通、证书对、
            # TTFB 甚至很快，但整站打不开——是这个落地 IP 被对方风控盯上了。
            # 以前 400 落到下面当 ok，于是这种 IP 被优选写进 hosts，浏览器
            # 一直吃那张拦截页。校验请求的都是正常页面，正常页面不会回 400，
            # 所以一概判死，不再看正文（正文里到底写 Whoa 还是 Bad request 不重要）。
            return "blocked", ttfb, None, False
        if status == 421:
            # 421 Misdirected：证书对、TCP 通，但这个 IP 不服务这个域名。
            # 典型场景：CloudFront 上能服务 www.imdb.com 的 IP，对
            # m.media-amazon.com 回 421。必须判成不能用，否则会把海报域名
            # 指到一个根本不认它的 IP 上（页面打得开、图全裂）。
            return "wrong", ttfb, None, False
        if status in (301, 302, 303, 307, 308):
            # 跳走检测：Location 离开了本域名 → 这个 IP 不承载本服务。
            # 典型：假 GitHub 边缘对 avatars/objects.githubusercontent.com 回
            # 301 → github.com，证书还合法（*.githubusercontent.com 被伪造或
            # 泛域名共用），能骗过证书校验；浏览器头像/附件全被带到主站。
            # 同域跳转（如 http→https、加 www）属正常，放行。
            mloc = LOC_RE.search(text)
            if mloc and strict_redirect:
                loc = mloc.group(1).strip()
                host = loc.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
                if host and not _same_site(host, domain):
                    return "wrong", ttfb, None, False
        if status >= 500:
            # 5xx 也顺手测速度，方便判断是节点挂了还是单纯慢
            return "http%d" % status, ttfb, None, False

        # ---- 继续读 body：算下载吞吐；传了 expect 就边读边看内容对不对 ----
        # 注意：命中 expect 只是「内容判定通过」，不能就此停手。
        # 以前命中就 break，而 Google 首页的 <title> 在前 1KB 内，样本只有 1KB
        # → 速度永远是空的。这条路上「判定」和「测速」必须分开：判定通过后
        # 继续把样本读够（到 SPEED_TRUST_BYTES），速度才有意义。
        body = bytearray(body_head)
        got = len(body)
        needle = expect.encode() if expect else b""
        hit = bool(needle) and needle in body
        t_dl = time.time()
        deadline = t_dl + BODY_BUDGET
        while got < BODY_CAP and time.time() < deadline:
            if hit and got >= SPEED_TRUST_BYTES:
                break
            try:
                d = ss.recv(65536)
            except Exception:
                break
            if not d:
                break
            body += d
            got = len(body)
            if needle and not hit:
                # 只搜「新到的那段 + 一个 needle 长度的重叠区」，别每次全文重扫
                if needle in body[-(len(d) + len(needle)):]:
                    hit = True
        span = time.time() - t_dl

        # 能连上、证书也对，但拿不到该服务应有的内容 → 这个地址不提供该服务。
        # （典型：Google 前端节点对任何路径都回 404，看着「通」，实际翻译/搜索都不通。）
        if needle and not hit:
            return "wrong", ttfb, None, False

        # 2026-11-08：有些节点 TCP/TLS/证书全对、HTTP 200，但不管请求什么路径，
        # 正文都只有 "OK" 几个字节（浏览器整页就是一个白底 OK）。这类假节点以前
        # 被判 ok，于是面板全绿、用户时好时坏。只精确匹配极短的纯 OK 文本：
        # ghcr 的 401 空 body、Cloudflare 的 178B 首页等正常小响应都不受影响。
        # 只精确匹配「HTTP 200 + 1~8 字节、不含任何 HTML 标记的纯文本」：
        # OK / ok / error / null / denied 这类假节点一律判死，覆盖没有专属
        # 正文校验的 cf / tmdb / imdb / auto 四路（以前只认字面 "OK" 一种）。
        # 不受影响：ghcr 的 401 空 body、imdb 的 202 空 body（got=0）、
        # 301/302/404 重定向与错误页、Cloudflare 的 178B 首页（含 '<'）。
        if status == 200 and 0 < got <= 8:
            head = bytes(body).strip()
            if head and b"<" not in head and all(32 <= c < 127 for c in head):
                return "wrong", ttfb, None, False

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


def _speed_probe(ip, url, timeout=8, budget=6.0):
    """单独测一次下载吞吐：直连 ip，SNI/Host 用 URL 里的域名。

    为什么需要：有些路「能用的样子」本身就是个小响应——Cloudflare 首页 178B、
    TMDB 的 403 页 2.6KB、ghcr 的 401 空 body。拿这种响应算速度等于没算。
    所以这些路额外配一个「已知会吐大文件」的地址（PREF_SPEED_URL），只测速、
    不参与「能不能用」的判定。测的是同一个 IP、同一条链路，数值是可信的。

    Cloudflare 有官方测速端点 speed.cloudflare.com/__down?bytes=N，任何一个
    边缘 IP 都能服务（实测 v4/v6 均 200，270KB / 200~330KB/s）；
    TMDB 的图走 image.tmdb.org，一张 w500 海报约 160KB。
    返回 (speed_kbps, 样本字节数)，失败返回 (None, 0)。
    """
    m = re.match(r"^https?://([^/]+)(/.*)?$", url or "")
    if not m:
        return None, 0
    host = m.group(1)
    path = m.group(2) or "/"
    v6 = ":" in ip
    fam = socket.AF_INET6 if v6 else socket.AF_INET
    addr = (ip, 443, 0, 0) if v6 else (ip, 443)
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except Exception:
        pass
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(addr)
        ss = ctx.wrap_socket(s, server_hostname=host)
        req = ("GET %s HTTP/1.1\r\nHost: %s\r\n%s" % (path, host, BROWSER_HDRS))
        ss.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 24576:
            d = ss.recv(4096)
            if not d:
                break
            buf += d
        head, _, body = buf.partition(b"\r\n\r\n")
        m2 = STATUS_RE.match(head.decode("utf-8", "replace"))
        if not m2 or int(m2.group(1)) >= 400:
            return None, len(body)
        got = len(body)
        t0 = time.time()
        deadline = t0 + budget
        while got < BODY_CAP and time.time() < deadline:
            try:
                d = ss.recv(65536)
            except Exception:
                break
            if not d:
                break
            body += d
            got = len(body)
        span = time.time() - t0
        if got < BODY_MIN or span <= 0.001:
            return None, got
        return (got / 1024.0) / span, got
    except Exception:
        return None, 0
    finally:
        try:
            s.close()
        except Exception:
            pass


def check(item, domain, port, timeout, samples=1, path="/", expect=None, speed_url=None,
          strict_redirect=True):
    """对单个 IP 探测；samples>1 时多测几次取「最好的一次」。

    为什么要多测：单次吞吐会抖动（实测同一 IP 158/289/532 KB/s），拿一次结果
    就判「慢了」会误触发全量重探。只要任意一次证明它不慢，就不算慢。
    path / expect 用于「这个服务真实长什么样」的判定（见文件头说明）。
    strict_redirect 见 _attempt 的说明。
    返回 (ip, 状态, ttfb, speed, 是否估算)。
    """
    ip = item.split()[0]
    best = None          # (状态, ttfb, speed, est)
    for _ in range(max(1, int(samples))):
        st, ttfb, speed, est = _attempt(ip, domain, port, timeout, path, expect,
                                        strict_redirect)
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
    # 内容判定那一发拿到的是小响应（cf 首页 178B、tmdb 403 页 2.6KB）→ 没有速度。
    # 这一路如果配了测速地址，就再打一发大的，把带宽补上。
    if speed_url and best[2] is None:
        sp2, bytes2 = _speed_probe(ip, speed_url, timeout)
        if sp2 is not None:
            best = (best[0], best[1], sp2, bytes2 < SPEED_TRUST_BYTES)
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
    path = sys.argv[6] if len(sys.argv) > 6 and sys.argv[6] else "/"
    expect = sys.argv[7] if len(sys.argv) > 7 and sys.argv[7] else None
    speed_url = sys.argv[8] if len(sys.argv) > 8 and sys.argv[8] else None

    items = [l.strip() for l in sys.stdin if l.strip()]
    if not items:
        return

    with concurrent.futures.ThreadPoolExecutor(max_workers=conc) as ex:
        for ip, st, ttfb, speed, est in ex.map(
                lambda i: check(i, domain, port, timeout, samples, path, expect, speed_url), items):
            sp = fmt(speed)
            if sp != "-" and est:
                sp = "~" + sp          # ~ 表示样本太小，只作参考、不参与「变慢」判定
            print("%s %s %s %s" % (ip, st, fmt(ttfb), sp))


if __name__ == "__main__":
    main()
