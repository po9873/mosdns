#!/usr/bin/env python3
"""Google 翻译路固定映射自愈（强校验版）。

为什么存在：翻译「能不能用」不在网页壳，而在翻译后台接口。
translate.google.com 是一张纯 JS 壳，真正的翻译请求走
translate.googleapis.com/translate_a/single（网页端）和
translate-pa.googleapis.com/v1/translateHtml（Chrome 右键翻译）。
早先的探针只验「首页含 translate 字样」，结果把一批「只代理了网页壳、
后台翻译接口一律 403/404」的半吊子反代收了进去——页面能打开、翻译做
不出来，等于「看着能用实际不能用」。用户原话：假的你加载进去干嘛。

本脚本逐候选 IP 真实验证：必须「translate.googleapis.com 翻译接口真翻出
译文」且「网页壳能开」才收录。半吊子反代首页能开但接口 403/404，直接出局，
绝不被写进 hosts。某个域一个可用 IP 都没有时，沿用旧文件该域的行（失效回退），
避免把整个翻译域清空导致更糟；但如果连旧结果都没有，宁可该域回退上游解析，
也不写没验证过的 IP。

候选来源：本机 mosdns 当前解析（即用户上游实际吐的反代 IP）+ 历史 .gt.extra
里的 IP（上一轮验证过的）+ 公共 DNS 兜底。无论来源，每个 IP 都过同一套强校验。

用法: python3 gt_pin_refresh.py /data/prefs/.gt.extra
"""
import gzip
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pin_exempt  # noqa: E402

DATA_DIR = "/data"
PREF_DIR = os.path.join(DATA_DIR, "prefs")
LIB_DIR = os.path.dirname(os.path.abspath(__file__))

# 翻译路候选池（社区源反代 IP，4000+ 个）。gt_pin_refresh 每轮从中取一批做
# 强校验，循环推进自动覆盖全池——发现「真能翻」的反代就自动接入。
POOL_FILE = "/data/pool/gt.json"
PROBE_BATCH = 150          # 每轮取多少个订阅池候选实测（循环推进，覆盖全池）
PROBE_OFFSET_FILE = "/data/prefs/.gt.probe_offset"

RESOLVERS = ["223.5.5.5", "119.29.29.29", "180.76.76.76"]
TIMEOUT = 6.0
# 只留 2 个：一个域名写 4 个 IP 时，客户端会随机挑；只要其中有一个对某个
# 翻译域不服务，用户就是「这次能翻、下次不能」。全池实测有 177 个 IP 完整
# 支持 Chrome 内置翻译，冗余完全够，少写反而更稳。
TOP_N = 2
WORKERS = 16
RETRIES = 1          # 分层短路后单 IP 只花 1 个请求，不再重试（死 IP 重试纯浪费时间）

# 翻译接口实测参数：翻一个极短词，验证响应里回显了原文（证明真翻，不是 403/404 错误页）。
# client 必须是 dict-chrome-ex —— 那是 Chrome 浏览器翻译/划词翻译真实使用的接口。
# 血的教训二：同一个 IP，HTTP/2 下 client=gtx 一律 429「Sorry」、client=webapp 403，
# 只有 client=dict-chrome-ex 返回真译文 [[["你好","hello"...]]]。浏览器走的就是
# HTTP/2，早前拿 h1.1 + gtx 测出「能翻」，用户浏览器里却一定 429 —— 判定标准选错，
# 等于给自己发了一张假通行证。现在按浏览器的真实协议和真实 client 来判。
TL_DOMAIN = "translate.googleapis.com"
TL_PATH = "/translate_a/single?client=dict-chrome-ex&sl=en&tl=zh-CN&dt=t&q=hello"
TL_NEEDLE = b"hello"

# Chrome 内置翻译（右键「翻成中文」/整页翻译）真正打的三条请求。
# 只验 translate_a/single 会放过「只代理网页手动翻译」的半吊子节点；把这三
# 条一起纳入核心门槛，选出来的 IP 才是浏览器里真能用的。全池实测 177 个 IP
# 全部通过，不会把可用节点筛没了。
CHROME_T_PATH = "/translate_a/t?client=chrome&sl=en&tl=zh-CN&q=hello"
C5_T_PATH = "/translate_a/t?client=dict-chrome-ex&sl=en&tl=zh-CN&q=hello"
ELEMENT_PATH = "/translate_a/element.js"
ZH_NEEDLE = "你好".encode("utf-8")

# 翻译路只负责这 5 个域；静态资源域（gstatic）由 google 路统一管。
GT_DOMAINS = ["translate.google.com", TL_DOMAIN, "translate-pa.googleapis.com",
              "translate.googleusercontent.com", "clients5.google.com"]
# 浏览器真实请求走 HTTP/2，所以核心判定必须由 curl 强制 h2 完成。
# Python 标准库只有 h1.1，容器里也没有 h2/hpack 库，故用 curl 子进程（实测支持 h2）。
CURL = "/usr/bin/curl" if os.path.exists("/usr/bin/curl") else "curl"

# 探针必须伪装成真实浏览器。血的教训：Google 对非浏览器 UA 直接回 429
# 「Sorry...」，curl 默认 UA 一模一样；早前据此判定这些反代是「只代理网页壳
# 的半吊子」，全部判死、把 gt.hosts 清空，翻译才「用不了」。换浏览器 UA 后
# 同一批 IP 立刻返回真译文 [[["你好","hello"...]]]。探针模拟的就是用户浏览器，
# UA 必须与浏览器一致，否则测出来的不是用户看到的结果。
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

LOC_RE = re.compile(r"(?im)^location:\s*(\S+)")
STATUS_RE = re.compile(rb"^HTTP/1\.[01]\s+(\d{3})")


def log(msg):
    sys.stderr.write("[gt-pin] %s\n" % msg)


def banned_ips():
    try:
        bl = json.load(open(os.path.join(DATA_DIR, "blacklist.json")))
        now = time.time()
        return {ip for ip, v in bl.items() if (v.get("until") or 0) > now}
    except Exception:
        return set()


def _gunzip(b):
    if b[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(b)
        except Exception:
            return b
    return b


def dns_a(name, server):
    """极简 A 记录查询（不信包头计数，逐条解析到包尾）。"""
    try:
        q = struct.pack(">HHHHHH", 0x2233, 0x0100, 1, 0, 0, 0)
        for lab in name.split("."):
            q += struct.pack("B", len(lab)) + lab.encode()
        q += b"\x00" + struct.pack(">HH", 1, 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(4)
        s.sendto(q, (server, 53))
        data, _ = s.recvfrom(2048)
        s.close()
    except Exception:
        return []
    off = 12
    while off < len(data) and data[off]:
        off += data[off] + 1
    off += 5
    ips = []
    while off + 12 <= len(data):
        if data[off] & 0xC0:
            off += 2
        else:
            while off < len(data) and data[off]:
                off += data[off] + 1
            off += 1
        if off + 10 > len(data):
            break
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        if rtype == 1 and rdlen == 4:
            ips.append(".".join(str(b) for b in data[off:off + 4]))
        off += rdlen
    return ips


def local_resolve(name):
    """向本机 mosdns 查询，拿到用户上游实际吐的解析结果（含反代 IP）。"""
    try:
        out = subprocess.run(
            [sys.executable, os.path.join(LIB_DIR, "dnsq.py"), "127.0.0.1", "53", name, "A"],
            capture_output=True, text=True, timeout=10).stdout
        return [l.strip() for l in out.splitlines() if l.strip()]
    except Exception:
        return []


def https_check(ip, domain, path, *, expect=None, ok_codes=None, method="GET"):
    """对 ip 发 HTTPS 请求（SNI/Host=domain），返回 (ok?, ttfb_ms)。

    - 传 expect：body 必须含该字节串（用于「真能翻」判定）。
    - 传 ok_codes：状态码在该集合内即 ok（用于「资源域正常应答」判定）。
    - method：某些接口（如 translate-pa 的 translateHtml）只认 POST，
      GET 到它一律 404，会把真能用的 IP 误判——所以允许指定方法。
    - 3xx 跳到别的域名一律算不服务本域名（踢走）。
    """
    t0 = time.time()
    try:
        s = socket.create_connection((ip, 443), timeout=TIMEOUT)
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        try:
            ctx.set_alpn_protocols(["http/1.1"])
        except Exception:
            pass
        ss = ctx.wrap_socket(s, server_hostname=domain)
        cl = "Content-Length: 0\r\n" if method.upper() != "GET" else ""
        req = ("%s %s HTTP/1.1\r\nHost: %s\r\n"
               "User-Agent: %s\r\n"
               "Accept: */*\r\n"
               "Accept-Language: zh-CN,zh;q=0.9,en;q=0.8\r\n"
               "%s"
               "Connection: close\r\n\r\n" % (method, path, domain, BROWSER_UA, cl))
        ss.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 65536:
            d = ss.recv(4096)
            if not d:
                break
            buf += d
        ttfb = int((time.time() - t0) * 1000)
        head, _, body = buf.partition(b"\r\n\r\n")
        if expect:
            got = len(body)
            deadline = t0 + TIMEOUT
            while got < 131072 and time.time() < deadline:
                try:
                    d = ss.recv(8192)
                except Exception:
                    break
                if not d:
                    break
                body += d
                got = len(body)
                if expect in body:
                    break
        ss.close()
    except Exception:
        return False, None
    m = STATUS_RE.match(head)
    if not m:
        return False, ttfb
    try:
        status = int(m.group(1).decode("ascii"))
    except Exception:
        return False, ttfb
    if status in (301, 302, 303, 307, 308):
        lm = LOC_RE.search(head.decode("utf-8", "replace"))
        if lm:
            host = lm.group(1).strip().split("://", 1)[-1].split("/", 1)[0]
            host = host.split(":", 1)[0].strip(".").lower()
            if host and host != domain.lower():
                return False, ttfb  # 踢到别的域名 = 不服务本域名
        # 同域跳转按下方码/body 判定
    if ok_codes is not None:
        return status in ok_codes, ttfb
    if expect is not None:
        try:
            return expect in _gunzip(body), ttfb
        except Exception:
            return expect in body, ttfb
    return status == 200, ttfb


def h2_check(ip, domain, path, *, expect=None, ok_codes=None, method="GET"):
    """用 curl 强制 HTTP/2 校验，返回 (ok?, 耗时ms)。

    为什么必须 h2：浏览器请求 Google 走的就是 HTTP/2。同一个 IP 在 h1.1 下
    返回 200 真译文、在 h2 下返回 429「Sorry」——用 h1.1 判定等于给用户发了
    一张假通行证（测着能用、打开浏览器就失败）。所以核心判定只认 h2：
    没协商成 h2 的直接判不通过，宁可回退上游，也不写「h1.1 能通」的假可用 IP。

    Python 标准库只有 h1.1、容器里也没 h2/hpack 库，故走 curl 子进程
    （容器 curl 8.14.1 带 nghttp2，实测支持 --http2）。
    """
    t0 = time.time()
    url = "https://%s%s" % (domain, path)
    cmd = [CURL, "-sS", "--http2", "--compressed",
           "--connect-timeout", "3", "--max-time", "8",
           "-A", BROWSER_UA,
           "-H", "Accept-Language: zh-CN,zh;q=0.9,en;q=0.8",
           "--resolve", "%s:443:%s" % (domain, ip),
           "-o", "-",
           "-w", "\n__META__%{http_version} %{http_code}",
           url]
    if method.upper() != "GET":
        cmd[-1:-1] = ["-X", method.upper(), "-d", ""]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=12)
    except Exception:
        return False, None
    ttfb = int((time.time() - t0) * 1000)
    out = p.stdout or b""
    idx = out.rfind(b"\n__META__")
    if idx < 0:
        return False, ttfb
    meta = out[idx + len(b"\n__META__"):].split()
    body = out[:idx]
    if len(meta) < 2:
        return False, ttfb
    ver = meta[0].decode("ascii", "replace")
    try:
        status = int(meta[1])
    except Exception:
        return False, ttfb
    if ver != "2":
        return False, ttfb          # 没走上 h2 = 浏览器真实体验不可信
    if ok_codes is not None:
        return status in ok_codes, ttfb
    if expect is not None:
        return expect in body, ttfb
    return status == 200, ttfb


def core_ok(r):
    """核心门槛：网页壳 + 手动翻译接口 + Chrome 内置翻译三件套，全部真通过。

    分层短路后结果里可能缺键，一律用 .get 判定，否则会 KeyError。"""
    need = (TL_DOMAIN, "translate.google.com", "_chrome_t", "_clients5_t", "_element")
    return all(bool(r.get(k, (False,))[0]) for k in need)


def check_ip(ip):
    """返回 dict: 域名 -> (ok, ttfb)。核心门槛在 main 里组合判定。

    每个域都用「真实用户会请求的那个真实路径」判定——这是关键：
    静态资源域（gstatic/clients5）根路径本来就回 404，拿 / 当判据会把
    所有真能用的 IP 判死（实测 generate_204 与真实字体文件都是 200/204）。
    spec 四元组 = (path, expect_bytes, ok_codes, method)。

    实测参考（8.134.173.202 上验证）：
      www.gstatic.com/generate_204        -> 204
      ssl.gstatic.com/generate_204        -> 204
      fonts.gstatic.com/s/roboto/...woff2 -> 200 (15744B)
      translate-pa POST /v1/translateHtml  -> 403（接口存在但无 key）
      clients5.google.com/                -> 404（该站无首页，属正常）
    """
    specs = {
        # 核心①：翻译接口真翻出译文（半吊子 403/404，不含 hello -> 失败）
        TL_DOMAIN: (TL_PATH, TL_NEEDLE, None, "GET"),
        # 核心②：网页壳能开（纯 JS 壳，但至少得含 translate 字样）
        "translate.google.com": ("/", b"translate", None, "GET"),
        # Chrome 右键翻译接口：只认 POST，无 key 时真接口回 403（存在即证明承载）
        "translate-pa.googleapis.com": ("/v1/translateHtml", None, {400, 403, 200}, "POST"),
        # 资源/静态域：必须用真实资源路径（根路径 404 是正常的，不能拿来判定）
        "translate.googleusercontent.com": ("/", None, {200, 403, 404}, "GET"),
        "clients5.google.com": ("/", None, {200, 204, 403, 404}, "GET"),
        # gstatic 三个静态域不再由翻译路写：google 路的 PREF_EXTRA_DOMAINS 已经
        # 管着它们。两边各写一行会让 all.hosts 里同一域名出现两条不同 IP 的记录，
        # 客户端拿到哪条全看合并顺序——这是「时好时坏」的第二个来源。
    }
    res = {}
    # —— 分层短路（省负载，用户明确要求）：订阅池里绝大多数候选是死 IP，
    # 若对每个都硬测 8 个域，一轮要跑十几分钟。核心①不通就立刻返回，
    # 只花 1 个请求的代价；核心②不过也不再测剩下 6 个域。
    # 核心①②都走 HTTP/2 —— 浏览器用 h2，h1.1 能通不代表用户能用。
    # h2 一次请求就同时验证了 TCP、证书、协议、内容，所以不必再额外跑 h1.1。
    for dom in (TL_DOMAIN, "translate.google.com"):
        path, expect, codes, method = specs[dom]
        ok, ttfb = h2_check(ip, dom, path, expect=expect, method=method)
        res[dom] = (ok, ttfb)
        if not ok:
            return res
    # Chrome 内置翻译三件套：必须真出译文 / 真拿到 element.js，才准进 hosts。
    # 同样用 h2（浏览器走 h2），判据与用户实际体验一致。
    for key, dom, path, expect, codes in (
        ("_chrome_t", TL_DOMAIN, CHROME_T_PATH, ZH_NEEDLE, None),
        ("_clients5_t", "clients5.google.com", C5_T_PATH, ZH_NEEDLE, None),
        ("_element", TL_DOMAIN, ELEMENT_PATH, None, {200}),
    ):
        ok, ttfb = h2_check(ip, dom, path, expect=expect, ok_codes=codes)
        res[key] = (ok, ttfb)
        if not ok:
            return res
    for dom, (path, expect, codes, method) in specs.items():
        if dom in res:
            continue
        ok, ttfb = https_check(ip, dom, path, expect=expect, ok_codes=codes, method=method)
        res[dom] = (ok, ttfb)
    return res


def candidates():
    bad = banned_ips()
    out = []
    seen = set()
    add = lambda ip: (ip not in bad and ip not in seen) and (seen.add(ip) or out.append(ip))
    # ① 本机 mosdns 当前解析（用户上游实际吐的反代 IP）
    for dom in ("translate.google.com", "translate.googleapis.com", "translate-pa.googleapis.com"):
        for ip in local_resolve(dom):
            add(ip)
    # ② 历史 .gt.extra（上一轮验证过的反代 IP，跨轮延续 + 兜底）
    try:
        for ln in open(os.path.join(PREF_DIR, ".gt.extra"), errors="replace"):
            for ip in ln.split()[1:]:
                add(ip)
    except Exception:
        pass
    # ③ 订阅池 gt.json（社区源反代 IP，4000+ 个）：这是翻译路最该用的候选源，
    #    之前漏掉了，只在本地解析的半吊子里打转。改为「每轮取一批、循环推进」
    #    自动覆盖全池，强校验筛选出真能翻的即自动接入——正是「上游给半吊子就
    #    换来源」的思路，全程 mosdns 自己跑，不依赖人工提供任何 IP。
    try:
        d = json.load(open(POOL_FILE, errors="replace"))
        allips = list(d.get("ips", {}).keys())
        n = len(allips)
        if n:
            off = 0
            try:
                off = int(open(PROBE_OFFSET_FILE, errors="replace").read().strip() or 0)
            except Exception:
                off = 0
            batch = allips[off:off + PROBE_BATCH]
            if not batch:
                batch = allips[:PROBE_BATCH]
                off = 0
            for ip in batch:
                add(ip)
            try:
                open(PROBE_OFFSET_FILE, "w").write(str((off + PROBE_BATCH) % n))
            except Exception:
                pass
            log("从订阅池取第 %d~%d 个候选（共 %d）参与本轮强校验" % (off + 1, min(off + PROBE_BATCH, n), n))
    except Exception:
        pass
    # 说明：不查公共 DNS 兜底（理由同上）。候选保留「本机解析 + 历史 .gt.extra
    # + 订阅池分批」三类自动来源，不依赖人工提供任何 IP。
    return out


def main():
    out_file = sys.argv[1] if len(sys.argv) > 1 else os.path.join(PREF_DIR, ".gt.extra")
    cooldown_file = out_file + ".cooldown"
    COOLDOWN = 30 * 60  # 落空后冷却 30 分钟：无可用 IP 时不必每轮重测，省负载

    def mark_cooldown():
        try:
            open(cooldown_file, "w").write(str(int(time.time())))
        except Exception:
            pass

    def in_cooldown():
        try:
            t = int(open(cooldown_file).read().strip() or 0)
            return (time.time() - t) < COOLDOWN
        except Exception:
            return False

    # 先收集旧 .gt.extra 里的已选 IP（下面「稳定优先」判定与冷却跳过都依赖它）
    old_ips = []
    try:
        for ln in open(out_file, encoding="utf-8", errors="replace"):
            for ip in ln.split()[1:]:
                if ip not in old_ips:
                    old_ips.append(ip)
    except Exception:
        pass

    # 没有任何已选 IP（.gt.extra 空）且处于落空冷却期：跳过本轮重测，
    # 等上游吐出真能翻的反代再试，避免无可用 IP 时每轮空转刷负载。
    if not old_ips and in_cooldown():
        log("无已选 IP 且在落空冷却期内，跳过本轮重测（约 %d 分钟后重试）" % (COOLDOWN // 60))
        return

    # —— 稳定优先：已选 IP 仍真能翻就直接沿用，不重测、不重写 ——
    # 用户要求：mosdns 不必每次轮询都重跑全量强校验，只有当前 IP 失效（翻
    # 不出来了）才重新探测换 IP。故先轻量复核旧结果里的 IP，全活着就沿用，
    # 既有「真实可用」的保证，又不会无谓地每轮重跑。
    if old_ips:
        def quick(ip):
            try:
                r = check_ip(ip)
            except Exception:
                return ip, False, None
            ts = [t for k, (o, t) in r.items() if o and t is not None]
            return ip, core_ok(r), (min(ts) if ts else None)
        alive = []
        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            for ip, ok, ms in ex.map(quick, old_ips):
                if ok:
                    alive.append((ms if ms is not None else 99999, ip))
        if alive:
            # 不能直接 return「沿用旧文件」：旧文件可能还带着 gstatic 三行、
            # 每域 4 个混杂 IP。每轮都规范化重写成「5 个翻译域 + 同一组
            # TOP_N 个 IP」，这样旧包袱一次就被清掉，之后始终保持一致。
            alive.sort()
            picked = [ip for _, ip in alive[:TOP_N]]
            tmp = out_file + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write("\n".join(" ".join([d] + picked) for d in GT_DOMAINS) + "\n")
            os.replace(tmp, out_file)
            for d in GT_DOMAINS:
                try:
                    pin_exempt.update(d, picked)
                except Exception:
                    pass
            log("旧 IP 全接口复核通过(%d个)，规范化为统一 2 个：%s"
                % (len(alive), " ".join(picked)))
            return
        log("旧 IP 已失效(全接口复核未过)，重新探测候选以换 IP")

    cands = candidates()
    log("候选 %d 个，开始强校验（必须真能翻出译文）" % len(cands))

    results = {}   # domain -> [(ttfb, ip)]，只收录通过核心门槛的 IP
    core_pass = []  # 通过核心门槛的 IP 列表
    ip_best = {}    # ip -> 最快一次 TTFB，用于选出全局统一的一组 IP

    # 每 IP 并发校验；核心门槛（接口能翻+网页能开）未过则至多补测一遍
    # （应对抖动/偶发 429），通过即收。绝不把半吊子反代收进任何翻译域。
    # 注意：早期版本在这里额外白跑了一遍 executor（结果未使用），已移除，
    # 否则每候选被测 3 遍，自动轮询会被严重拖慢。
    def worker(ip):
        last = None
        for _ in range(RETRIES):
            r = check_ip(ip)
            if core_ok(r):
                return r
            last = r
        return last

    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for ip, r in zip(cands, ex.map(worker, cands)):
            if r is None:
                continue
            # 只有核心门槛过的 IP 才允许进入任何翻译域的映射，杜绝半吊子反代
            if core_ok(r):
                core_pass.append(ip)
                ttfbs = [ttfb for k, (ok, ttfb) in r.items() if ok and ttfb is not None]
                ip_best[ip] = min(ttfbs) if ttfbs else 99999
                for dom, (ok, ttfb) in r.items():
                    if dom.startswith("_"):     # 内部判据键，不是域名
                        continue
                    if ok and ttfb is not None:
                        results.setdefault(dom, []).append((ttfb, ip))

    log("通过核心门槛（接口能翻+网页能开）的 IP: %d" % len(core_pass))

    # 只写翻译域；gstatic 静态域交给 google 路，避免 all.hosts 里出现同名两行。
    domains = GT_DOMAINS

    # 全局选最快的 TOP_N 个 IP，所有翻译域统一用这一组。以前每个域各自按自己
    # 的 TTFB 挑，结果同一次翻译里 5 个域名落到 5 组不同节点，任一节点掉线就
    # 整次失败——这正是「一次能翻、一次不能」的第三个来源。
    global_ips = [ip for ip, _ in sorted(ip_best.items(), key=lambda kv: kv[1])[:TOP_N]]

    lines = []
    for dom in domains:
        ok_ips = [ip for _, ip in sorted(results.get(dom, [])) if ip in global_ips]
        ips = ok_ips[:TOP_N] or global_ips
        # 不拿旧 .gt.extra 里没验证过的 IP 补位（用户原话：假的别加载）。
        if ips:
            lines.append(" ".join([dom] + ips))
            try:
                pin_exempt.update(dom, ips)
            except Exception:
                pass

    if not lines:
        # 关键：不清空。以前一轮探测落空就把 .gt.extra 清空、整路回退上游解析
        # （上游给的是被污染的 IP），再加 30 分钟冷却 = 翻译最长半小时不可用，
        # 用户看到的就是「一时可用一时不可用」。上一轮结果是逐 IP 真翻验证过的，
        # 比「回退上游」可靠得多；保留它，只记日志并冷却，等下轮再找新 IP。
        mark_cooldown()
        log("本轮无 IP 通过全接口强校验，保留上一轮 .gt.extra（不清空、不回退上游）")
        return
    tmp = out_file + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    os.replace(tmp, out_file)
    print(json.dumps({"domains": len(lines),
                      "core_ips": len(core_pass)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
