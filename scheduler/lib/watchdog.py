#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""换 IP 看门狗：定时巡检「当前正在生效」的 IP，发现 1034 立刻换掉。

与优选流程的分工：
  scheduler  负责「找新的」——按间隔重跑优选
  watchdog   负责「守住旧的」——几分钟一轮，专门盯 1034 / 证书 / 5xx，
             坏一个立刻从 hosts 摘掉，并从候选池补一个通过校验的进来

这就是「1034 一触发就换 IP」：不用等下一轮优选（默认 60 分钟），
默认 3 分钟内就会把坏 IP 换成可用的；找不到替补就撤下该路，绝不继续用坏 IP。

用法： python3 watchdog.py [--once]
"""
import ipaddress
import json
import os
import re
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import https_probe          # noqa: E402
import selfheal             # noqa: E402
import subs                 # noqa: E402

DATA_DIR = os.environ.get("PREF_DATA_DIR", "/data")
PREF_DIR = os.path.join(DATA_DIR, "prefs")
PID_FILE = os.path.join(DATA_DIR, "mosdns.pid")
LOCK_DIR = os.path.join(DATA_DIR, ".pref.lock")
STATE_FILE = os.path.join(DATA_DIR, "watchdog_state.json")
SNAP_FILE = os.path.join(DATA_DIR, "health_snapshot.json")
LOG_FILE = os.path.join(DATA_DIR, "pref.log")
SEED_DIR = "/app/config/seeds"
INTERVAL = int(os.environ.get("PREF_WATCHDOG_SEC", "180"))
# 单个探测超时：正常跨境首屏 <1s，3s 连不上就判这次不可用。
# 以前 6s × 131 个点 / 8 并发 ≈ 100 秒一轮，链路抖动时要 5 分钟以上。
TIMEOUT = float(os.environ.get("PREF_WATCHDOG_TIMEOUT", "3"))
MAX_STRIKES = int(os.environ.get("PREF_WATCHDOG_STRIKES", "3"))
# 「连续失败」对间歇性坏节点无效：它好一轮就把计数清零，永远攒不到阈值，
# 于是一直留在 hosts 里，浏览器随机撞上就是「时好时坏」（GitHub 这类跨境
# 节点最常见）。除 gt 外改按最近若干轮的失败率判定：偶发单次抖动不误换，
# 好一轮坏一轮的抖动节点一定换掉。
WINDOW_N = int(os.environ.get("PREF_WD_WINDOW", "6"))
WINDOW_BAD = int(os.environ.get("PREF_WD_BAD", "2"))
WINDOW_MIN = int(os.environ.get("PREF_WD_MIN", "3"))
WINDOW_SEC = int(os.environ.get("PREF_WD_WINDOW_SEC", "1800"))
PORT = int(os.environ.get("PREF_WATCHDOG_PORT", "443"))
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")
GT_GUARD_STATE = os.path.join(DATA_DIR, "gt_guard_state.json")
GT_GUARD_FLAG = os.path.join(DATA_DIR, ".gt_need_refresh")
GT_CURL = "/usr/bin/curl" if os.path.exists("/usr/bin/curl") else "curl"
GT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
         "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
# 镜像自愈巡检：每天一次，由 101 自己核对仓库状态，不依赖有人记得跑校验脚本。
IMG_GUARD_SEC = int(os.environ.get("PREF_IMG_GUARD_SEC", "86400"))
IMG_GUARD_STATE = os.path.join(DATA_DIR, "image_guard_state.json")
VERSIONS_FILE = "/app/VERSIONS"


def runtime_cfg():
    """巡检间隔/开关可以在界面上改，不用重启容器：每轮重新读 settings.json。"""
    sec, on = INTERVAL, True
    try:
        with open(SETTINGS_FILE, encoding="utf-8") as f:
            d = json.load(f)
        if isinstance(d.get("watchdog_sec"), (int, float)) and 30 <= int(d["watchdog_sec"]) <= 3600:
            sec = int(d["watchdog_sec"])
        if d.get("watchdog_enabled") is False:
            on = False
    except Exception:
        pass
    return sec, on

# 「明确不可用」只在证据确凿时成立（证书错 / CF 拦截页 / 421 跨站跳转）。
# 注意 health() 对资源域走专属判据，失败时返回的是 "wrongres"（响应码不符），
# 它和 "wrong" 只是前缀相同。以前用 startswith(("cf","cert","wrong")) 把
# wrongres 一起算成 HARD —— 一次跨境抖动就跳过 3 次窗口确认、立刻拉黑 6 小时。
# 结果 github 路黑名单被灌到 400+ 条，候选池被 candidates() 清空，守护每轮
# 只能打印「保留原行等下轮自己判」，等于自愈被自己的黑名单锁死。
HARD_PREFIX = ("cf", "cert")
HARD_EXACT = ("wrong",)


def is_hard(st):
    s = str(st or "")
    return s.startswith(HARD_PREFIX) or s in HARD_EXACT

# static.hosts 在 mosdns 的 hosts 插件里排在 all.hosts 前面、优先命中，
# 以前完全不在守护视野里：那里的 IP 坏了 101 发现不了。现在逐行纳入巡检。
STATIC_FILE = os.path.join(DATA_DIR, "static.hosts")
STATIC_STRIKES = int(os.environ.get("PREF_STATIC_STRIKES", "3"))
GT_MAIN_DOMAINS = ("translate.google.com", "translate.googleapis.com")
GT_STATIC_DEPS = ("translate.gstatic.com", "apis.google.com",
                  "csp.withgoogle.com", "fonts.googleapis.com")

# 定时优选每轮都「沿用不换」时，会在 write_route 之前就退出，于是
# PREF_EXTRA_DOMAINS / 自动发现里那些漏网域名永远补不进 hosts。实测：
# www.gstatic.com（Chrome 整页翻译的 CSS 域）就是这样漏掉的——没钉住就走
# 上游真实解析，三层 DNS 各缓存不同答案，101 上那些真实 IP 还连不上。
# 由守护每轮用「本路当前在用的 IP」自己实测补上，不改任何在用 IP。
# 值 = (域名, 真实资源路径)：静态资源域根路径 404/204 都属正常，必须打真实路径。
NEEDED_DEPS = {
    "google": (("www.gstatic.com", "/generate_204"),),
}

# hosts 行的合法性判定：域名 + 后面全是 IP。写文件前必须过这一关，
# 否则一句日志、一段残留文本就能把 all.hosts 写坏，mosdns 直接起不来。
RE_DOM = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]*[a-z0-9])?\.)+[a-z]{2,}$", re.I)


def is_ip(x):
    try:
        ipaddress.ip_address(str(x))
        return True
    except ValueError:
        return False

# Google 系域名专用判定：这些节点的根路径回什么都有可能（翻译首页 200、其他路径 404），
# 光看「HTTP 通不通」分不出好坏；而翻译接口有配额，巡检频繁调用会被 429，
# 反而把好 IP 判成坏的换掉。所以统一看首页标题（<title>Google…）。
_TRANS_DOMS = ("translate.googleapis.com", "translate.google.com")
_GOOGLE_DOMS = ("www.google.com", "www.google.com.hk")
# TMDB / IMDb 故意不做正文校验：它们前面有 Cloudflare / Amazon 的反爬，
# 批量探测时会连续返回挑战页，正文里有没有站点字样全凭对方心情，
# 拿它判反而会误杀一片好 IP。这两路只认「证书对 + 有响应」——
# CloudFront 对不认识域名的请求在 TLS 阶段就用默认证书，校验根本过不去。


# 每路专属探测规格：(路径, 正文必须出现的内容)。
#
# 守护巡检的默认规格是「根路径、不校验内容」，这对多数站够用，但对
# 「根路径不代表真实能力」的服务就是误杀机器。ghcr 是最典型的：
#   GET https://ghcr.io/       → 301 https://github.com/features/packages（跨站）
#   GET https://ghcr.io/v2/    → 401 + www-authenticate: Bearer realm=...（registry 正常应答）
# 守护拿根路径去探，撞上跨站 301 判 wrong，把优选刚验证通过的 IP 拉黑 6 小时
# 并撤下整条路，界面上就成了「还没有优选结果」——IP 好好的，是探针问错了问题。
#
# 所以：优选用什么标准，守护就必须用同一套标准。以后新增路时，如果它的
# 「能用」长在专属路径上（registry / API / raw），在这里补一行。
_ROUTE_SPEC = {
    "ghcr": ("/v2/", "UNAUTHORIZED"),
    # 翻译路：守护必须和优选问同一个问题。根路径 + 正文含 "translate" 只证明
    # 「网页壳能开」，证明不了翻译接口能翻；守护拿它判 ok，就会把「壳还在、
    # 翻译接口已经死了」的 IP 一直留在 hosts 里，面板显示正常、浏览器翻不出来。
    # 实测：好 IP 真翻译接口 -> ok，死 IP -> timeout，判据可靠。
    "gt": ("/translate_a/single?client=dict-chrome-ex&sl=en&tl=zh-CN&dt=t&q=hello", "hello"),
}


def spec_for(domain, route=None):
    """这一路该请求什么路径、正文里该出现什么（默认根路径，不校验内容）。

    翻译首页是纯 JS 壳，整页没有 <title>；搜索首页有 <title>Google。
    用这两种特征判断，既不用调翻译接口（有配额，巡检频繁会被 429 限速），
    也能把「能连但不提供该服务」的节点筛掉。
    """
    if route and route in _ROUTE_SPEC:
        return _ROUTE_SPEC[route]
    if domain == "github.com":
        # 2026-11-08 实测：140.82.113.21 / 140.82.114.21 / 140.82.112.22 这类节点
        # TCP、TLS、证书、HTTP 200 全对，但正文只有 4 字节 "OK"（浏览器整页就显示
        # 一个 OK）。旧判据 expect=None 只看状态码，把它们当成健康，于是 hosts 里
        # 一行 4 个 IP 有 3 个是假节点，浏览器随机命中 → 面板全绿、用户时好时坏。
        # 主站首页必须返回真正的 HTML；_attempt 找不到 needle 会返回 "wrong"，
        # 属于 HARD，守护当轮立即拉黑并由 101 实测补位，不用等 3 次连续失败。
        # www.github.com 正常回 301 且 body 为空，不能加这个校验，否则误杀。
        return "/", "<!DOCTYPE html"
    if domain in _TRANS_DOMS:
        return "/", "translate"
    if domain in _GOOGLE_DOMS:
        return "/", "<title>Google"
    return "/", None


def log(msg):
    # 前缀用中文，避免日志里一堆 [watchdog] 让人看不懂在干什么
    line = "[%s] 【守护】%s" % (time.strftime("%m-%d %H:%M:%S"), msg)
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def why_label(why):
    """把内部状态码翻成人话，日志里不出现 cf1034 这种裸代码。"""
    w = str(why or "")
    if w == "timeout":
        return "超时"
    if w == "fail":
        return "连不上"
    if w == "cert":
        return "证书不对"
    if w.startswith("cf10"):
        return "Cloudflare %s 错误" % w[2:]
    if w.startswith("http5"):
        return "源站 %s 错误" % w[4:]
    if w == "unverified":
        return "没通过 HTTPS 校验"
    return w or "打不开"


def jload(p, dft):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return dft


def jsave(p, obj):
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)
    os.replace(tmp, p)


def _do_reload_locked():
    """调用者必须持有 _reload_lock。"""
    try:
        pid = int(open(PID_FILE).read().strip())
        os.kill(pid, signal.SIGTERM)
        _reload_state["last"] = time.time()
        log("已请求重载 mosdns（pid %d）" % pid)
        return True
    except Exception:
        return False


def _reload_worker():
    """冷却期内的多次写 hosts 合并成一次重载，绝不丢掉任何一次变更。"""
    while True:
        time.sleep(2)
        with _reload_lock:
            if (not _reload_state["pending"]
                    or time.time() - _reload_state["last"] < RELOAD_MIN_SEC):
                continue
            _reload_state["pending"] = False
            _do_reload_locked()


def reload_mosdns(force=False):
    """合并重载：RELOAD_MIN_SEC 内多次变更只重启一次 DNS。

    --once 模式没有常驻 worker，直接同步重载；主动自愈（5 分钟限频）用
    force=True 立即生效，不必等合并窗口结束。
    """
    with _reload_lock:
        if force or not _reload_state["worker"]:
            return _do_reload_locked()
        if time.time() - _reload_state["last"] < RELOAD_MIN_SEC:
            _reload_state["pending"] = True
            return False
        _reload_state["pending"] = False
        return _do_reload_locked()


def read_hosts(path):
    """返回 (domain, [ip...])，格式与 mosdns hosts 一致：域名在前。

    只认真正能解析成 IP 的字段；文件被写进过别的东西（日志、注释）时，
    这里不会把它当成 IP 拿去探测，更不会原样写回去。
    """
    try:
        raw = open(path, encoding="utf-8", errors="replace").read().splitlines()
    except Exception:
        return None, []
    for ln in raw:
        p = ln.split()
        if len(p) < 2:
            continue
        dom = p[0]
        if not RE_DOM.match(dom):
            continue
        ips = []
        for x in p[1:]:
            try:
                ips.append(str(ipaddress.ip_address(x)))
            except ValueError:
                continue
        if ips:
            return dom, ips
    return None, []


def read_lines(path):
    """按行读 hosts 文件，返回 [(domain, [ips...])...]，保持原顺序。

    一路 hosts 通常不止一行：主域名 + 同一批节点服务的附加域名
    （tmdb 有 api/image/auth，github 有 raw/codeload/avatars…）。
    只取第一行再去整体重写，会把其余域名整片删掉——之前就是这样
    把 tmdb 从 6 行写成 1 行、github/cf 也各剩 1 行的。
    """
    out = []
    try:
        raw = open(path, encoding="utf-8", errors="replace").read().splitlines()
    except Exception:
        return out
    for ln in raw:
        p = ln.split()
        if len(p) < 2 or not RE_DOM.match(p[0]):
            continue
        ips = []
        for x in p[1:]:
            try:
                ips.append(str(ipaddress.ip_address(x)))
            except ValueError:
                continue
        if ips:
            out.append((p[0], ips))
    return out


def write_hosts(route, domain, ips, extra=None):
    """所有写 *.hosts 的线程统一串行，杜绝主巡检/哨兵互相覆盖。"""
    with _HOSTS_LOCK:
        return _write_hosts_unlocked(route, domain, ips, extra)


def _write_hosts_unlocked(route, domain, ips, extra=None):
    # all.hosts 是各路合并出来的，绝不能把它当成一路来回写：
    # 之前巡检到它（route 名就叫 all）就把整份合并文件压成了一行，
    # mosdns 起不来、全屋 DNS 一起挂。
    if route in ("all", ""):
        return
    if not RE_DOM.match(str(domain or "")):
        return
    ips = [i for i in ips if is_ip(i)]
    extra = [(d, [i for i in l if is_ip(i)]) for d, l in (extra or [])]
    extra = [(d, l) for d, l in extra if d != domain and l]
    path = os.path.join(PREF_DIR, "%s.hosts" % route)
    lines = []
    if ips:
        lines.append(" ".join([domain] + ips))
    for d, l in extra:
        lines.append(" ".join([d] + l))
    if not lines:
        try:
            os.remove(path)
        except Exception:
            pass
    else:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        os.replace(tmp, path)
    # 合并成 mosdns 实际读取的 all.hosts
    _rebuild_all_hosts()


def _has_ipv4(ips):
    """这一组 IP 里是否至少有一个 IPv4（A 记录）。"""
    for x in ips:
        try:
            if ipaddress.ip_address(x).version == 4:
                return True
        except ValueError:
            pass
    return False


def sanitize_hosts(rebuild=True):
    """剔除「纯 IPv6、无 IPv4」的 hosts 行——这是结构性废行，101 每轮自动清。

    背景：pref hosts 只写 A 记录（config 里 github_v4only 更把 AAAA 判 NODATA）。
    一旦某域名在 hosts 里只剩 IPv6，mosdns 的 hosts 插件对 A 查询会返回 NODATA，
    而 AAAA 又被 github_v4only 拒成空——该域名彻底解析不出来；更糟的是
    pref_hosts 排在 cache/上游之前，has_resp 成立直接 accept，永远走不到
    forward_remote 去拿正确的 IPv4。真实案例：raw.githubusercontent.com 被写成
    2606:50c0:8000::154，导致整站打不开。

    只删这类废行（本身有任何 IPv4 的行原样保留字段与顺序），是幂等且安全的。
    返回 (被剔除行数, 明细列表)；有改动时 rebuild 会同步重建 all.hosts，
    调用方负责重载 mosdns。
    """
    removed = 0
    details = []
    try:
        names = [n for n in os.listdir(PREF_DIR) if n.endswith(".hosts")]
    except Exception:
        return 0, []
    for name in names:
        path = os.path.join(PREF_DIR, name)
        try:
            raw = open(path, encoding="utf-8", errors="replace").read().splitlines()
        except Exception:
            continue
        keep, dropped = [], []
        for ln in raw:
            p = ln.split()
            if len(p) < 2 or not RE_DOM.match(p[0]):
                continue
            ips = []
            for x in p[1:]:
                try:
                    ips.append(str(ipaddress.ip_address(x)))
                except ValueError:
                    pass
            if not ips:
                continue
            if not _has_ipv4(ips):
                dropped.append(ln.strip())
                continue
            keep.append(" ".join([p[0]] + ips))
        if dropped:
            removed += len(dropped)
            details.extend("%s: %s" % (name, d) for d in dropped)
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write("\n".join(keep) + ("\n" if keep else ""))
            os.replace(tmp, path)
    if removed and rebuild:
        _rebuild_all_hosts()
    return removed, details


# ---- 固定 IP 缺口自愈 ------------------------------------------------------
# sanitize_hosts 会剔掉「纯 IPv6 无 IPv4」的废行，但剔完若没人补，这个域名就
# 裸奔到上游解析（本机实测 raw.githubusercontent.com 上游给的 185.199.x 只有
# 2/5~3/5 能打开，而固定映射里的 151.101.x 是 3/3）。
# 而 github 路一旦判定「在用 IP 全能用」就由粘滞守卫提前返回，不会再走
# write_route 把 *.fastly / *.extra 的固定映射追加回 hosts——于是被剔掉的域名
# 永远回不来。这里补上这一环：pin 文件里有、hosts 里没有的域名，按 pin 顺序
# 逐个做真实 HTTPS 校验（证书 + 状态码都过），第一个通过的就写回该路 hosts。
PIN_SUFFIXES = (".extra", ".fastly", ".api")
PIN_HEAL_INTERVAL = 600          # 秒；正常没有缺口时几乎不耗时间
PIN_HEAL_MAX_DOMAINS = 4         # 单轮最多补几个域名，避免一次探太久
PIN_HEAL_MAX_IPS = 6             # 每个域名最多试几个候选
_PIN_HEAL_STAMP = os.path.join(DATA_DIR, "pin_gap.stamp")


def _pin_spec(domain):
    """这个固定 IP 域名该请求什么路径、认哪些状态码。"""
    try:
        import fastly_pin_refresh as fpr
        spec = fpr.DOMAIN_SPECS.get(domain)
        if spec:
            return spec[0], set(spec[1])
    except Exception:
        pass
    path, _expect = spec_for(domain)
    return path or "/", {200}


def _probe_pin_ip(ip, domain, path, codes, timeout=6.0):
    """真连一次：TLS 校验证书（必须覆盖该域名）+ 看状态码是否在允许集合里。"""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ss:
                req = ("GET %s HTTP/1.1\r\nHost: %s\r\n"
                       "User-Agent: mosdns-watchdog\r\nConnection: close\r\n\r\n"
                       % (path, domain))
                ss.sendall(req.encode())
                buf = b""
                while b"\r\n" not in buf and len(buf) < 2048:
                    chunk = ss.recv(1024)
                    if not chunk:
                        break
                    buf += chunk
        line = buf.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        parts = line.split()
        if len(parts) >= 2 and parts[0].startswith("HTTP/"):
            return int(parts[1]) in codes
    except Exception:
        return False
    return False


def heal_pin_gaps(force=False):
    """把「pin 里有、hosts 里没有」的域名用已验证的固定 IP 补回去。

    返回 (补回个数, 明细)。有改动时已重建 all.hosts 并重载 mosdns。
    """
    now = time.time()
    if not force:
        try:
            last = float(open(_PIN_HEAL_STAMP, encoding="utf-8").read().strip() or 0)
        except Exception:
            last = 0.0
        if now - last < PIN_HEAL_INTERVAL:
            return 0, []
    try:
        names = sorted(os.listdir(PREF_DIR))
    except Exception:
        return 0, []

    have = set()
    for name in names:
        if name.endswith(".hosts"):
            for dom, _ips in read_lines(os.path.join(PREF_DIR, name)):
                have.add(dom)

    healed = []
    for name in names:
        if not name.startswith(".") or not any(name.endswith(s) for s in PIN_SUFFIXES):
            continue
        route = name[1:].split(".")[0]
        if not route or route == "all":
            continue
        for dom, ips in read_lines(os.path.join(PREF_DIR, name)):
            if len(healed) >= PIN_HEAL_MAX_DOMAINS:
                break
            if dom in have:
                continue
            v4 = [x for x in ips if is_ip(x) and ":" not in x]
            if not v4:
                continue
            path, codes = _pin_spec(dom)
            for ip in v4[:PIN_HEAL_MAX_IPS]:
                if _probe_pin_ip(ip, dom, path, codes):
                    healed.append((route, dom, ip))
                    have.add(dom)
                    break

    for route, dom, ip in healed:
        path = os.path.join(PREF_DIR, "%s.hosts" % route)
        try:
            rows = open(path, encoding="utf-8", errors="replace").read().splitlines()
        except Exception:
            rows = []
        rows = [ln for ln in rows if (ln.split()[:1] or [""])[0] != dom]
        rows.append("%s %s" % (dom, ip))
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                f.write("\n".join(rows) + "\n")
            os.replace(tmp, path)
        except Exception:
            continue

    if healed:
        _rebuild_all_hosts()
        reload_mosdns()
    try:
        with open(_PIN_HEAL_STAMP, "w", encoding="utf-8") as f:
            f.write(str(int(now)))
    except Exception:
        pass
    return len(healed), ["%s: %s <- %s" % (r, d, i) for r, d, i in healed]


# ---- 资源域错钉自愈 ------------------------------------------------------
# 粘滞守卫只认「TLS 握手成功 + 有 HTTP 应答」。GitHub 主站边缘 140.82.112.x
# 的证书同样覆盖部分 *.githubusercontent.com，对资源域却一律 301 踢回
# github.com——根路径看着「能用」，真实 blob 路径却 404。docker pull ghcr
# 就死在这里：manifest 拿到了，config/layer blob 报 unknown blob。
# heal_pin_gaps 只补「hosts 里没有的域名」，纠不了「域名在、IP 是错的」；
# 这里按 fastly_pin_refresh 的每域专属判据复核在用 IP，错钉自动换回
# 已验证的 Fastly 边缘，保证 ghcr 这类链路不用人工介入。
# 资源域自愈底线（2026-11-10 用户明确要求「坏了立刻换 / 多点冗余」）：
#   1) 坏钉立刻换：不等 600s 节流、不等主巡检 180s + 3 次失败窗口。
#      独立哨兵每 30s 复核一次，判据是每域专属 HTTP 状态码（fpr.check
#      内部已重试 2 次），一次 wrongres 就是硬证据。
#   2) 多点冗余：每个资源域至少 RESOURCE_MIN_IPS 个 101 实测通过的 IP；
#      坏一个只撤坏的那个，好 IP 全保留并立即补足，绝不留单点裸奔。
FASTLY_HEAL_INTERVAL = int(os.environ.get("PREF_FASTLY_HEAL_SEC", "30"))
RESOURCE_MIN_IPS = int(os.environ.get("PREF_RESOURCE_MIN_IPS", "3"))
RESOURCE_GUARD_SEC = int(os.environ.get("PREF_RESOURCE_GUARD_SEC", "30"))
# 撤坏钉要连续 2 轮实测不通：跨境 SYN 单次抖动不该让 9 个资源域每 30 秒
# 洗一次牌、每分钟重载两次 mosdns（那样反而比坏钉本身更不稳）。
# 30s 一轮 × 2 = 约 1 分钟内换掉真坏钉，仍是「立刻」级别。
RESOURCE_STRIKES = int(os.environ.get("PREF_RESOURCE_STRIKES", "2"))
# 整轮在用 IP 不通比例超过这个数 = 跨境出口在丢包，不是 IP 坏。
# 此时撤任何一个都是误杀，且候选必然也全 timeout，会把 3 个冗余压成 1 个
# （2026-11-11 00:00 实测回归：raw 被压成单点、连续访问 0/10）。
RESOURCE_OUTAGE_RATIO = float(os.environ.get("PREF_RESOURCE_OUTAGE_RATIO", "0.4"))
_FASTLY_HEAL_STAMP = os.path.join(DATA_DIR, "fastly_pin_heal.stamp")
_RESOURCE_LOCK = os.path.join(DATA_DIR, ".resource_heal.lock")
_RESOURCE_STATE = os.path.join(DATA_DIR, "resource_strikes.json")

# ---- 2026-11-11：把「被动救火」改成「主动验收」 --------------------------
# 1) 进程内统一写锁：主巡检(HEAL_LOCK)、资源哨兵(_RESOURCE_LOCK)、体验哨兵
#    是同一进程里三个线程，以前各拿各的锁同时写 github.hosts / all.hosts，
#    实测 23:43:44 主巡检写 3 个 IP、23:43:47 哨兵按旧行写回 2 个，互相覆盖。
_HOSTS_LOCK = threading.RLock()

# 2) 重载合并：以前每换一次钉就 SIGTERM mosdns，实测 23:25-23:44 十九分钟
#    重载 12 次；DNS 反复重启造成的中断本身就是「时好时坏」的一大来源。
RELOAD_MIN_SEC = int(os.environ.get("PREF_RELOAD_MIN_SEC", "60"))
_reload_lock = threading.Lock()
_reload_state = {"last": 0.0, "pending": False, "worker": False}

# 3) 体验哨兵：按 101 自身 DNS 真实访问，主动发现「用户打不开」并限频自愈。
#    内部判据全绿但用户网页打不开，以前只能等用户发现再叫人来查。
EXPERIENCE_GUARD_SEC = int(os.environ.get("PREF_EXPERIENCE_GUARD_SEC", "45"))
EXPERIENCE_HEAL_SEC = int(os.environ.get("PREF_EXPERIENCE_HEAL_SEC", "300"))
EXPERIENCE_STATUS = os.path.join(DATA_DIR, "health_status.json")
EXPERIENCE_PROBES = (
    ("github", "https://github.com/", "200"),
    ("raw", "https://raw.githubusercontent.com/jqtmviyu/"
            "Transmission-block-xunlei-pcdn/main/transmission_blacklist.gz", "200"),
    # 2026-11-11 实测：api.github.com 被钉到 GitHub Pages 段 185.199.110.133，
    # 全屋访问 GitHub API 返回 404 Pages 页，而通用判据一直判「能用」。
    ("api", "https://api.github.com/", "200"),
)


def _guard_final(cur, final, target, tested_fail, tested_total):
    """统一「不写瘦」保护，主巡检与资源哨兵共用同一套判据。

    返回 (最终行, 是否链路抖动, 是否补位不足)。抖动期间故意不换钉：
    那时所有候选也 timeout，换只会把 3 个冗余压成 1 个单点。
    """
    outage = (tested_total > 0
              and tested_fail / float(tested_total) >= RESOURCE_OUTAGE_RATIO)
    if outage:
        return list(cur), True, False
    if len(final) < len(cur) and len(final) < target:
        return list(cur), False, True
    return list(final), False, False


def _is_resource_domain(dom):
    try:
        import fastly_pin_refresh as fpr
        return dom in fpr.DOMAIN_SPECS
    except Exception:
        return False


def _clear_resource_false_blacklist(verified):
    """通用巡检曾把资源域真边缘（400/403/404）误判拉黑；专属判据复核
    通过的 IP 就解除，否则优选/候选池 6 小时内都不会再考虑这些好 IP。"""
    path = os.path.join(DATA_DIR, "blacklist.json")
    try:
        bl = json.load(open(path, encoding="utf-8"))
    except Exception:
        return 0
    n = 0
    for ip in set(verified):
        if bl.pop(ip, None) is not None:
            n += 1
    if n:
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(bl, f)
            os.replace(tmp, path)
        except Exception:
            pass
    return n


def resource_candidates(fpr, dom, skip):
    """资源域专用补位候选：pin 已验证 IP > Fastly 同段变体 > 公共 DNS 实时解析。

    主站段（140.82.x / 20.x）对这些域一律 301 踢回 github.com，绝不能拿来补位
    —— 以前 candidates() 给的几乎全是 github.com 主站 IP，守护只能反复打印
    「候选也不可用」。新解析不受历史黑名单约束（抖动误判的 wrongres 不该让
    候选池永久枯竭），后面照样要过 101 的 fpr.check 实测，真坏的通不过。
    """
    out = []
    # 刚被确认坏钉撤下的 IP 别又从 pin 文件里补回来（否则撤了又补、
    # 补了又撤，每轮白重载一次）。按域判断，同一 IP 对别的域仍可用。
    banned = set()
    try:
        st = json.load(open(_RESOURCE_STATE, encoding="utf-8"))
        rec = st.get(dom, {}) if isinstance(st, dict) else {}
        if isinstance(rec, dict):
            banned = {ip for ip, v in rec.items()
                      if isinstance(v, dict)
                      and int(v.get("n", 0) or 0) >= RESOURCE_STRIKES}
    except Exception:
        pass

    def add(seq):
        for ip in seq:
            if (is_ip(ip) and ":" not in ip and ip not in skip
                    and ip not in banned and ip not in out
                    and fpr.allow_blob_ip(dom, ip)):
                out.append(ip)

    try:
        for name in sorted(os.listdir(PREF_DIR)):
            if not name.startswith(".") or not any(name.endswith(s) for s in PIN_SUFFIXES):
                continue
            for d, ips in read_lines(os.path.join(PREF_DIR, name)):
                if d == dom:
                    add(ips)
    except Exception:
        pass
    add([x for x in fpr.SAMPLE_IPS if x.startswith(("151.101.", "185.199."))])
    try:
        for srv in fpr.PUBLIC_DNS:
            add(fpr.udp_dns_a(dom, srv))
    except Exception:
        pass
    return out


def heal_bad_fastly_pins(force=False):
    """资源域全量复核：坏钉立即换、好 IP 保留、冗余不足立即补。

    返回 (修正域名数, 明细)。只有 hosts 内容真变了才重建 all.hosts + reload。
    force=True 给独立哨兵用（跳过节流，但照样走互斥锁）。
    """
    now = time.time()
    if not force:
        try:
            last = float(open(_FASTLY_HEAL_STAMP, encoding="utf-8").read().strip() or 0)
        except Exception:
            last = 0.0
        if now - last < FASTLY_HEAL_INTERVAL:
            return 0, []
    # 哨兵与主巡检可能同时进来，写同一份 hosts 会互相覆盖；陈旧锁超时自清。
    try:
        os.mkdir(_RESOURCE_LOCK)
    except FileExistsError:
        try:
            if time.time() - os.path.getmtime(_RESOURCE_LOCK) > 180:
                os.rmdir(_RESOURCE_LOCK)
                os.mkdir(_RESOURCE_LOCK)
            else:
                return 0, []
        except Exception:
            return 0, []
    except Exception:
        pass
    try:
        return _heal_resource_pins(now)
    finally:
        try:
            os.rmdir(_RESOURCE_LOCK)
        except Exception:
            pass


def _heal_resource_pins(now):
    try:
        import fastly_pin_refresh as fpr
        specs = dict(fpr.DOMAIN_SPECS)
    except Exception:
        return 0, []

    # 各路 hosts 里资源域所在的行（同一域只处理第一次出现的位置）
    located = {}
    try:
        for name in sorted(os.listdir(PREF_DIR)):
            if not name.endswith(".hosts") or name == "all.hosts":
                continue
            for dom, ips in read_lines(os.path.join(PREF_DIR, name)):
                if dom not in specs or dom in located:
                    continue
                located[dom] = (name[:-6],
                                [x for x in ips if is_ip(x) and ":" not in x])
    except Exception:
        return 0, []
    if not located:
        return 0, []

    from concurrent.futures import ThreadPoolExecutor

    def _ok(item):
        dom, ip = item
        path, codes, jumps = specs[dom]
        # ghcr 层域名只认 151.101.x 资源段：185.199.x 根路径同样回 400，
        # 但下大层会截断/超时（docker 报 unknown blob），专属判据分不出。
        if not is_ip(ip) or ":" in ip or not fpr.allow_blob_ip(dom, ip):
            return False
        try:
            # 与 fastly_pin_refresh.main 同一套 check_retry（内部重试 2 次），
            # 单次跨境抖动不会立刻把一个好 IP 判死。
            return bool(fpr.check_retry(ip, dom, path, set(codes), set(jumps))[1])
        except Exception:
            return False

    # 1) 全部在用 IP 并发复核（以前只看第一行第一个 IP，坏钉藏在后面就漏了）
    checks = [(d, ip) for d, (_r, cur) in located.items() for ip in cur]
    with ThreadPoolExecutor(max_workers=16) as ex:
        oks = list(ex.map(_ok, checks))
    verdict = dict(zip(checks, oks))

    # 1b) 整批不通 = 链路抖动保护：这些 IP 来自不同域、不同段，一起挂
    #     只可能是跨境出口丢包。这时候既不能记失败也不能改 hosts。
    if len(checks) >= 6:
        failed = sum(1 for v in oks if not v)
        if failed / float(len(checks)) >= RESOURCE_OUTAGE_RATIO:
            log("资源域哨兵：本轮 %d/%d 在用 IP 不通，判定链路抖动，"
                "不动 hosts、不记失败" % (failed, len(checks)))
            try:
                with open(_FASTLY_HEAL_STAMP, "w", encoding="utf-8") as f:
                    f.write(str(int(now)))
            except Exception:
                pass
            return 0, []

    # 2) 失败计数：连续 RESOURCE_STRIKES 轮不通才确认是坏钉。
    #    单次抖动仍把 IP 留在行里（反正还有其它冗余 IP 兜底），
    #    避免「每 30 秒把 9 个域洗一遍 + 重载 mosdns」这种自伤式抖动。
    try:
        st_all = json.load(open(_RESOURCE_STATE, encoding="utf-8"))
        if not isinstance(st_all, dict):
            st_all = {}
    except Exception:
        st_all = {}
    # 撤下过的 IP 回来时不能背着旧账：15 分钟没更新的计数一律清掉
    for dom in list(st_all):
        rec = st_all[dom]
        if not isinstance(rec, dict):
            st_all.pop(dom, None)
            continue
        for ip in list(rec):
            v = rec[ip]
            if (not isinstance(v, dict)
                    or int(now) - int(v.get("ts", 0) or 0) > 900):
                rec.pop(ip, None)
        if not rec:
            st_all.pop(dom, None)
    confirmed = {}
    for dom, (_route, cur) in located.items():
        rec = st_all.setdefault(dom, {})
        for ip in cur:
            if verdict.get((dom, ip)):
                rec.pop(ip, None)
                continue
            old = rec.get(ip) if isinstance(rec.get(ip), dict) else {}
            n = int(old.get("n", 0) or 0)
            ts = int(old.get("ts", 0) or 0)
            # 哨兵与主巡检可能前后脚跑，同一次拥塞不能记成两票
            if int(now) - ts >= 15:
                n += 1
            rec[ip] = {"n": n, "ts": int(now)}
        confirmed[dom] = {
            ip for ip in cur
            if int((rec.get(ip) or {}).get("n", 0) or 0) >= RESOURCE_STRIKES
        }
        if confirmed[dom]:
            log("资源域哨兵：%s 连续 %d 轮实测不通，确认坏钉 %s（待补位）"
                % (dom, RESOURCE_STRIKES, " ".join(sorted(confirmed[dom]))))
    try:
        tmp = _RESOURCE_STATE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(st_all, f)
        os.replace(tmp, _RESOURCE_STATE)
    except Exception:
        pass

    # 3) 只有「确认坏钉 / 冗余不足」的域才需要探候选，正常一轮几乎零开销
    need_domains = []
    for dom, (_route, cur) in located.items():
        good = [ip for ip in cur if ip not in confirmed[dom]]
        if confirmed[dom] or len(good) < RESOURCE_MIN_IPS:
            need_domains.append(dom)
    cand_checks = []
    for dom in need_domains:
        skip = set(located[dom][1])
        for ip in resource_candidates(fpr, dom, skip)[:PIN_HEAL_MAX_IPS * 2]:
            if (dom, ip) not in cand_checks:
                cand_checks.append((dom, ip))
    if cand_checks:
        with ThreadPoolExecutor(max_workers=16) as ex:
            coks = list(ex.map(_ok, cand_checks))
        verdict.update(dict(zip(cand_checks, coks)))

    # 4) 逐域收敛：撤掉已确认的坏钉、留好 IP、补到至少 RESOURCE_MIN_IPS 个
    changed = []
    for dom, (route, cur) in located.items():
        good = [ip for ip in cur if ip not in confirmed[dom]]
        want = max(RESOURCE_MIN_IPS, len(cur))
        for d, ip in cand_checks:
            if d != dom or len(good) >= want:
                continue
            if verdict.get((dom, ip)) and ip not in good:
                good.append(ip)
        # 全军覆没（跨境整段抖动）绝不把行删空，也不拉黑，保留原行等下轮
        final = good if good else list(cur)
        if not good:
            log("资源域哨兵：%s 本轮候选全不通（链路抖动），保留原行等下轮" % dom)
        # 绝不把行写瘦：补位候选全 timeout 时若把 3 个 IP 压成 1 个，
        # 反而制造单点裸奔（比留着那个坏 IP 糟得多）。链路恢复后候选能
        # 测通，自然会把坏钉换掉并补回 3 个。
        if len(final) < len(cur):
            log("资源域哨兵：%s 补位不足，保留原 %d 个 IP 不动，等链路恢复"
                % (dom, len(cur)))
            continue
        if final == cur:
            continue
        with _HOSTS_LOCK:
            host_path = os.path.join(PREF_DIR, route + ".hosts")
            try:
                rows = open(host_path, encoding="utf-8", errors="replace").read().splitlines()
            except Exception:
                continue
            rows = [ln for ln in rows if (ln.split()[:1] or [""])[0] != dom]
            rows.append(" ".join([dom] + final))
            tmp = host_path + ".tmp"
            try:
                with open(tmp, "w", encoding="utf-8") as f:
                    f.write("\n".join(rows) + "\n")
                os.replace(tmp, host_path)
            except Exception:
                continue
        changed.append("%s: %s [%s] -> [%s]" % (route, dom,
                                                " ".join(cur), " ".join(final)))

    # 5) 复核通过的真边缘解除历史误拉黑（别让 400/404 误判挡住候选池）
    nb = _clear_resource_false_blacklist([ip for (_d, ip), ok in verdict.items() if ok])
    if nb:
        log("资源域自愈：解除 %d 个被通用巡检误拉黑的真边缘 IP" % nb)

    if changed:
        _rebuild_all_hosts()
        reload_mosdns()
    try:
        with open(_FASTLY_HEAL_STAMP, "w", encoding="utf-8") as f:
            f.write(str(int(now)))
    except Exception:
        pass
    return len(changed), changed


def _rebuild_all_hosts():
    """把各路 *.hosts 合并成 mosdns 实际读取的 all.hosts（串行）"""
    with _HOSTS_LOCK:
        return _rebuild_all_hosts_unlocked()


def _rebuild_all_hosts_unlocked():
    out = []
    try:
        for name in os.listdir(PREF_DIR):
            if not name.endswith(".hosts") or name == "all.hosts":
                continue
            for ln in open(os.path.join(PREF_DIR, name), encoding="utf-8", errors="replace"):
                p = ln.split()
                # 必须含至少一个 IPv4：纯 IPv6 行会让 A 查询 NODATA、域名彻底解析失败。
                if (len(p) >= 2 and RE_DOM.match(p[0])
                        and all(is_ip(x) for x in p[1:]) and _has_ipv4(p[1:])):
                    out.append(ln.strip())
    except Exception:
        pass
    allp = os.path.join(PREF_DIR, "all.hosts")
    tmp = allp + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(set(out))) + ("\n" if out else ""))
    os.replace(tmp, allp)


def purge_ips_everywhere(bad_ips):
    """拉黑后立刻把这些 IP 从所有路的 hosts 文件里撤下，并重建 all.hosts。

    只调 mark_bad 的话，这个 IP 之前 pin 在别的域名上的记录会一直残留，
    要等下一轮优选（最长一小时）才会被换掉——GitHub 曾因此整批域名
    （avatars/codeload/objects 等）跟着一个被打入黑名单的 IP 一起打不开。"""
    bad = set(bad_ips)
    if not bad:
        return
    try:
        names = [n for n in os.listdir(PREF_DIR)
                 if n.endswith(".hosts") and n != "all.hosts"]
    except Exception:
        return
    purged = False
    # 固定映射豁免：专属 IP（api.github.com 的 API 边缘等）被拉黑是因为对
    # 主域名不服务，但对豁免域名是好的（专属探针刚验证过），不撤。
    exempt = {}
    try:
        with open(os.path.join(DATA_DIR, "pin_exempt.json")) as f:
            _ex = json.load(f)
            exempt = _ex if isinstance(_ex, dict) else {}
    except Exception:
        pass
    for name in names:
        path = os.path.join(PREF_DIR, name)
        try:
            lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
        except Exception:
            continue
        out, hit = [], False
        for ln in lines:
            p = ln.split()
            if not p:
                continue
            keep = [x for x in p[1:]
                    if x not in bad or p[0] in exempt.get(x, [])]
            if len(keep) != len(p) - 1:
                hit = True
            if keep:
                out.append(" ".join([p[0]] + keep))
        if not hit:
            continue
        purged = True
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write("\n".join(out) + ("\n" if out else ""))
        os.replace(tmp, path)
    if purged:
        _rebuild_all_hosts()
def seed_ips(route):
    """该路的种子兜底 IP：内置 IP + 种子里写的域名用公共 DNS 实时解析。

    seeds/*.txt 从一开始就允许写域名（github.txt 的注释也这么承诺），但旧实现
    只收「形似 IP」的行，域名行被静默丢掉。结果 github 路种子常年只剩 2 个老
    IP，一旦它们全废，候选池就空了 —— 守护每轮都在实测，却压根没有可换的 IP，
    只能反复打印「候选暂不可用，下轮继续自己补」，用户看到的就是长期时好时坏。
    解析必须问公共 DNS，不能问 101 自己（自己会被 hosts 钉死，拿到的还是旧 IP）。
    """
    out, doms = [], []
    path = os.path.join(SEED_DIR, "%s.txt" % route)
    try:
        for ln in open(path, encoding="utf-8"):
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            tok = ln.split()[0]
            if tok.count(".") == 3 and tok.replace(".", "").isdigit():
                out.append(tok)
            elif ":" in tok:
                out.append(tok)
            elif "." in tok:
                doms.append(tok)
    except Exception:
        pass
    if doms:
        try:
            import fastly_pin_refresh as fpr
            for dom in doms:
                for srv in fpr.PUBLIC_DNS:
                    for ip in fpr.udp_dns_a(dom, srv):
                        if ":" not in ip and ip not in out:
                            out.append(ip)
        except Exception:
            pass
    return out


RESEED_INTERVAL = int(os.environ.get("PREF_RESEED_SEC", "600"))


def reseed_candidates(route, domain, force=False):
    """候选池枯竭时，用公共 DNS 实时解析主域补种，并写回 cfst 种子。

    不依赖仓库里的内置种子：即便种子里的老 IP 全废、订阅池为空、cfst 结果
    又扫错了段，101 也能自己拿到当前的真实入口 IP。解析出来的 IP 后面照样
    要过 health() 实测，被污染的 IP 通不过，不会写进 hosts。
    """
    stamp = os.path.join(DATA_DIR, ".reseed_%s_stamp" % route)
    now = int(time.time())
    if not force:
        try:
            last = int(open(stamp, encoding="utf-8").read().strip() or 0)
        except Exception:
            last = 0
        if now - last < RESEED_INTERVAL:
            return []
    try:
        with open(stamp, "w", encoding="utf-8") as f:
            f.write(str(now))
    except Exception:
        pass
    try:
        import fastly_pin_refresh as fpr
    except Exception:
        return []
    doms = ([domain, "www." + domain, "api." + domain]
            if domain == "github.com" else [domain])
    ips = []
    for d in doms:
        for srv in fpr.PUBLIC_DNS:
            for ip in fpr.udp_dns_a(d, srv):
                if ":" not in ip and ip not in ips:
                    ips.append(ip)
    if not ips:
        return []
    try:
        p = os.path.join(DATA_DIR, "cfst_%s_seed.txt" % route)
        old = open(p, encoding="utf-8").read().splitlines() if os.path.exists(p) else []
        head = [ln for ln in old[:2] if ln.startswith("#") or ln == domain]
        with open(p, "w", encoding="utf-8") as f:
            f.write("\n".join(head + ips) + "\n")
    except Exception:
        pass
    log("%s 路：候选池枯竭，公共 DNS 实时补种 %d 个真实入口 IP" % (route, len(ips)))
    return ips


def candidates(route, domain, skip, ignore_bad=False):
    """补位候选：cfst 实测排序 > 抖动回血 > 订阅池 > 种子，去掉已在用的和已拉黑的。

    ignore_bad=True 只给「候选池被黑名单整批清空」时的自救用：不过滤黑名单
    重取候选，但仍要过 101 同一套 HTTPS 复核，通过才写 hosts 并解除误判。
    """
    # 资源域必须走资源段候选：通用池里几乎全是 github.com 主站 IP，
    # 对 avatars/raw/objects 一律 301/404，守护会一直判「候选也不可用」。
    if _is_resource_domain(domain):
        try:
            import fastly_pin_refresh as fpr
            return resource_candidates(fpr, domain, set(skip))[:12]
        except Exception:
            pass
    bad_all = subs.load_bad()
    bad = set() if ignore_bad else subs._bad_set()
    out = []
    # CloudflareSpeedTest 在 101 容器内实测排序出来的 cf 候选优先补位：
    # 工具真的决定「坏了换哪个 IP」，但仍要过下面同一套 101 严格复核，
    # 全健康时粘滞守卫根本不会走到这里，不会因为「有更快的」就换。
    # 每一路都有自己的 cfst 排序种子（cf 沿用旧文件名），按路读取。
    cfst_seed = os.path.join(
        DATA_DIR, "cfst_seed.txt" if route == "cf" else "cfst_%s_seed.txt" % route)
    try:
        with open(cfst_seed, encoding="utf-8") as f:
            for line in f:
                ip = line.split("#", 1)[0].strip()
                parts = ip.split(".")
                # 种子首行是目标域名，别把它当 IP 收进去
                if len(parts) != 4 or not all(p.isdigit() for p in parts):
                    continue
                if ip not in skip and ip not in bad and ip not in out:
                    out.append(ip)
                    if len(out) >= 6:
                        break
    except Exception:
        pass
    # 候选池被跨境网关抖动整批打黑时，给「拉黑已满冷却的抖动类 IP」一次
    # 重新实测的机会。这不是解禁：补位仍要过 101 同一套 HTTPS 校验，
    # 通过才写 hosts，写进去后下一轮黑名单复核会自动把误判解除。
    for ip in selfheal.soft_retry_ips(bad_all):
        if ip not in skip and ip not in out:
            out.append(ip)
    for ip in subs.cmd_pool(route, 12, smart=True):
        if ip not in skip and ip not in bad and ip not in out:
            out.append(ip)
    for ip in seed_ips(route):
        if ip not in skip and ip not in bad and ip not in out:
            out.append(ip)
    # 上面四路全废时（种子老 IP 全坏 + 订阅池空 + cfst 扫错段），101 自己
    # 用公共 DNS 实时解析补种，别再守着一个空池子每轮空转。
    if len(out) < 6:
        for ip in reseed_candidates(route, domain):
            # 刚从公共 DNS 实时解析出来的真实入口，不受历史黑名单约束：
            # 那批 wrongres 正是抖动误判，拿它挡新解析等于让污染永久生效。
            # 后面照样要过 health() 实测，真坏的 IP 通不过、不会写进 hosts。
            if ip not in skip and ip not in out:
                out.append(ip)
    return out


def probe(ip, domain, route=None):
    """巡检只关心「能不能打开」，但 https_probe.check 现在返回 4 个字段
    （ip / 状态 / TTFB / 吞吐）。这里统一补成 4 元组，避免以后它再加字段
    又把守护线程整个搞崩（之前就崩过：too many values to unpack）。

    根路径不启用「跨站跳转 = 坏」的判定（strict_redirect=False）：
    根路径跳产品页是正常行为，拿来判死会误杀（ghcr 就是这么被撤的）。
    只有探专属路径（/v2/ 等）时，正确应答才是身份证明，跳走才算假边缘。
    """
    path, expect = spec_for(domain, route)
    # 翻译路统一打真实接口域名：gt.hosts 第一行主域名是 translate.google.com
    # （纯 JS 壳），真正承载翻译请求的是 translate.googleapis.com。守护由此与
    # gt_pin_refresh 用同一个域名 + 路径 + 判据，避免「两套标准互相打架」。
    probe_domain = "translate.googleapis.com" if route == "gt" else domain
    try:
        r = https_probe.check(ip, probe_domain, PORT, TIMEOUT, 1, path, expect,
                              strict_redirect=bool(path and path != "/"))
    except Exception:
        return ip, "fail", None, None
    r = tuple(r)
    if len(r) < 4:
        r = r + (None,) * (4 - len(r))
    return r[0], r[1], r[2], r[3]


# ---- 静态钉子（/data/static.hosts）纳入 101 巡检 --------------------------
# 这个文件在 mosdns 的 hosts 插件里排在 all.hosts 之前、优先命中，里面的
# IP 坏了以前守护看不见（Chrome 商店后端 / Windy / 翻译依赖域都钉在这里）。
def static_route(dom):
    """静态钉子坏了去哪一路的候选池找替补。"""
    if dom in GT_STATIC_DEPS or dom.startswith("translate"):
        return "gt"
    if "google" in dom or "gstatic" in dom or "withgoogle" in dom:
        return "google"
    if dom == "windy.com" or dom.endswith(".windy.com"):
        return "windy"          # 没有候选池：只监控，不删手工钉子
    return "auto"


def _private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True


def static_targets():
    """读静态钉子，返回 ([(域名, [IP...])...], [(route, 域名, IP)...])。

    内网地址（registry.linkease.net 192.168.6.34）不探也不换；注释行原样
    留在文件里。巡检时按该行自己的域名做 SNI，不套任何一路的专属判据。
    """
    rows, items = [], []
    try:
        raw = open(STATIC_FILE, encoding="utf-8", errors="replace").read().splitlines()
    except Exception:
        return rows, items
    for ln in raw:
        p = ln.split("#", 1)[0].split()
        if len(p) < 2 or not RE_DOM.match(p[0]):
            continue
        ips = [x for x in p[1:] if is_ip(x) and not _private(x)]
        if not ips:
            continue
        rows.append((p[0], ips))
        items += [("static", p[0], ip) for ip in ips]
    return rows, items


def _write_static(new_ips):
    """就地替换 IP 列表，注释与其它行原样保留；不建备份、不留中间文件。"""
    try:
        raw = open(STATIC_FILE, encoding="utf-8", errors="replace").read().splitlines()
    except Exception:
        return False
    out, hit = [], False
    for ln in raw:
        p = ln.split()
        if len(p) >= 2 and p[0] in new_ips and new_ips[p[0]]:
            nl = " ".join([p[0]] + new_ips[p[0]])
            out.append(nl)
            hit = hit or nl != ln.strip()
        else:
            out.append(ln)
    if not hit:
        return False
    tmp = STATIC_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")
    os.replace(tmp, STATIC_FILE)
    return True


def heal_static(state, rows, results):
    """静态钉子：能用就一字不改；连续打不开才撤下并 101 实测补位。

    刻意不调 subs.mark_bad()：翻译依赖域和 gt 主用组共用同一批 IP，一次
    偶发抖动不该把整组翻译节点拉进 6 小时黑名单。没有可用替补时原行保留
    不动（不删手工钉子），只记日志 —— 避免把 Windy 这类没有候选池的静态
    映射越修越空、把用户实测可达的入口弄丢。
    """
    if not rows:
        return False, 0
    new_ips, swapped = {}, 0
    for dom, ips in rows:
        # 翻译依赖域由 gt 路真翻自检 + gt_pin_refresh 统一同步：主域和依赖域
        # 必须永远同组。这里只把 101 实测结果留在快照里供查看，不单独改写，
        # 否则一次偶发抖动就能把整组翻译节点拆开，跟 gt 路自愈互相打架。
        if dom in GT_STATIC_DEPS:
            continue
        keep, dropped = [], []
        for ip in ips:
            ok, st, _ms, _sp = results.get(("static", dom, ip),
                                           (False, "fail", None, None))
            key = "static|%s|%s" % (dom, ip)
            if ok:
                state.pop(key, None)
                keep.append(ip)
                continue
            # 只按「这一行自己的域名 + 这个 IP」的真实请求判定。刻意不看
            # 全局黑名单：那是「对某个域名不服务」的结论，换个域名可能完全
            # 正常（翻译主组就常被别路标过），拿它撤静态行会误伤。
            n = int((state.get(key) or {}).get("fails", 0)) + 1
            state[key] = {"fails": n, "ts": int(time.time()), "reason": st}
            if n >= STATIC_STRIKES:
                dropped.append((ip, st))
            else:
                keep.append(ip)
        if not dropped:
            continue
        log("静态钉子 %s：%s 连续 %d 轮打不开（%s），开始 101 实测补位"
            % (dom, ",".join(d[0] for d in dropped), STATIC_STRIKES,
               why_label(dropped[0][1])))
        subs.add_event("swap", "static", dropped[0][0], str(dropped[0][1]), dom)
        need = max(0, len(ips) - len(keep))
        added = []
        if need:
            try:
                cands = candidates(static_route(dom), dom,
                                   set(ips) | {d[0] for d in dropped})[:12]
            except Exception:
                cands = []
            cr = _batch_health([("static", dom, c) for c in cands])
            for c in cands:
                if len(added) >= need:
                    break
                if cr.get(("static", dom, c), (False,))[0]:
                    added.append(c)
        final = keep + added
        if not final:
            log("静态钉子 %s：没有 101 实测通过的替补，原行保留不动" % dom)
            continue
        new_ips[dom] = final
        swapped += len(dropped)
        log("静态钉子 %s：撤下 %s，%s" % (
            dom, ",".join(d[0] for d in dropped),
            ("换成 " + ",".join(added)) if added else ("保留 %d 个可用" % len(keep))))
    if not new_ips:
        return False, 0
    return _write_static(new_ips), swapped


def gt_guard():
    """用浏览器真实请求验证「现在到底能不能翻」。

    h2 + Chrome UA + client=chrome，正文必须真出「你好」。不用 https_probe
    的 h1.1、也不只看 HTTP 通不通——那正是「面板全绿、浏览器翻不出来」的来源。
    检测只读、不改 hosts；连续两次失败才打标记，等锁空闲由 run_once 触发重选，
    避免偶发 429 / 抖动把好 IP 换掉。
    """
    try:
        rows = read_lines(os.path.join(PREF_DIR, "gt.hosts"))
        ip = rows[0][1][0] if rows and rows[0][1] else ""
    except Exception:
        ip = ""
    if not ip:
        return
    ok = False
    try:
        p = subprocess.run(
            [GT_CURL, "-sS", "--http2", "--compressed",
             "-A", GT_UA, "--connect-timeout", "3", "--max-time", "8",
             "--resolve", "translate.googleapis.com:443:%s" % ip,
             "-o", "-", "-w", "\n__META__%{http_code}",
             "https://translate.googleapis.com/translate_a/t?client=chrome"
             "&sl=en&tl=zh-CN&q=hello"],
            capture_output=True, timeout=12)
        out = p.stdout or b""
        ok = b"__META__200" in out and "你好".encode("utf-8") in out
    except Exception:
        ok = False
    st = jload(GT_GUARD_STATE, {})
    if ok:
        if st.get("fails"):
            log("翻译真翻自检恢复正常")
        st["fails"] = 0
        jsave(GT_GUARD_STATE, st)
        return
    st["fails"] = int(st.get("fails", 0)) + 1
    jsave(GT_GUARD_STATE, st)
    log("翻译真翻自检失败(%d 次) ip=%s" % (st["fails"], ip))
    if st["fails"] >= 2:
        try:
            with open(GT_GUARD_FLAG, "w") as f:
                f.write(str(int(time.time())))
        except Exception:
            pass


# ---- 全链路巡检：能用就不换，坏了才由 101 自己发现并补位 ------------------
# 旧逻辑只巡检每路 hosts 的第一行（github 路第一行是 api.github.com），
# 用户真正打开的 github.com 被钉在 static.hosts 里，守护根本没看 →
# 「面板全绿、浏览器打不开」。现在所有行、所有在用 IP 都进巡检。
SLOW_TTFB_MS = float(os.environ.get("PREF_SLOW_TTFB_MS", "3500"))
SLOW_SPEED_KBPS = float(os.environ.get("PREF_SLOW_SPEED_KBPS", "20"))
WD_CONC = int(os.environ.get("PREF_WD_CONC", "12"))
from concurrent.futures import ThreadPoolExecutor, as_completed  # noqa: E402


def health(ip, domain, route):
    """101 容器内按真实浏览器判据探一次。

    https_probe 对 <4KB 的响应不算速度、<32KB 的样本标 est=True（不可信），
    所以只拿可信样本判「慢到打不开」，不会误杀 API / 401 这类小页面。
    """
    # Fastly 资源域（avatars/raw/objects/pkg-containers/...）根路径本来就回
    # 400/403/404，通用判据把 400 一律判 blocked；而 GitHub 主站边缘对它们
    # 回 301（path="/" 时又不严格判跳转）反而算「能用」。结果守护把真边缘
    # 拉黑、把主站边缘换进来 —— ghcr 层文件被 301 踢到 github.com 后 404，
    # docker pull 报 unknown blob。这类域一律交给专属判据复核。
    try:
        import fastly_pin_refresh as fpr
        spec = fpr.DOMAIN_SPECS.get(domain)
    except Exception:
        spec = None
    if spec:
        path, codes, jumps = spec
        # 与哨兵/优选统一用 check_retry（内部 2 次重试），避免单次抖动
        # 把真边缘判成 wrongres 后撤下并拉黑 6 小时。
        ok = fpr.check_retry(ip, domain, path, set(codes), set(jumps))[1]
        if ok and not fpr.allow_blob_ip(domain, ip):
            # 185.199.x 根路径同样回 400，但下 ghcr 大层会截断/超时
            ok = False
        return (True, "ok", None, None) if ok else (False, "wrongres", None, None)
    # gt 路现在逐行巡检：只有主域（translate.google.com / translate.googleapis.com）
    # 打真翻接口，这是「真能翻」的唯一证明；其余附加域（googleusercontent /
    # clients5 / translate-pa…）用各自 SNI + 宽松判据。不能拿真翻接口去问静态
    # 资源域（会 404 判死），也不能套 "translate" / <title>Google 这类网页
    # 特征 —— 实测这些域根路径本来就是 404 纯错误页，套上会把在用 IP 全误杀。
    if route == "gt" and domain not in GT_MAIN_DOMAINS:
        path, expect, probe_domain = "/", None, domain
    else:
        path, expect = spec_for(domain, route)
        probe_domain = "translate.googleapis.com" if route == "gt" else domain
    try:
        r = tuple(https_probe.check(ip, probe_domain, PORT, TIMEOUT, 1, path, expect,
                                    strict_redirect=bool(path and path != "/")))
    except Exception:
        r = (ip, "fail", None, None, False)
    if len(r) < 5:
        r = r + (None,) * (5 - len(r))
    _ip, st, ms, sp, est = r[:5]
    if st != "ok":
        return False, st, ms, sp
    if ms is not None and ms > SLOW_TTFB_MS:
        return False, "slowttfb%.0f" % ms, ms, sp
    if not est and sp is not None and 0 < sp < SLOW_SPEED_KBPS:
        return False, "slowspeed%.0f" % sp, ms, sp
    return True, st, ms, sp


def _batch_health(items):
    """并发巡检。第一次判不行的再补探 2 次，任一次能开就算健康
    （能用就不换：别被一次跨境抖动误杀好 IP）。"""
    out = {}
    if not items:
        return out
    with ThreadPoolExecutor(max_workers=WD_CONC) as ex:
        futs = {ex.submit(health, ip, dom, route): (route, dom, ip)
                for route, dom, ip in items}
        for f in as_completed(futs):
            k = futs[f]
            try:
                out[k] = f.result()
            except Exception:
                out[k] = (False, "fail", None, None)
    retry = [k for k, v in out.items() if not v[0]]
    if retry:
        with ThreadPoolExecutor(max_workers=WD_CONC) as ex:
            futs = {ex.submit(health, k[2], k[1], k[0]): k
                    for k in retry for _ in range(2)}
            for f in as_completed(futs):
                k = futs[f]
                try:
                    r = f.result()
                    if r[0]:
                        out[k] = r
                except Exception:
                    pass
    return out


def window_strike(state, key, ok, st):
    """记一轮 101 实测结果，返回 (失败次数, 样本数, 是否该撤下)。

    成功轮不再清空历史：抖动 IP 正是靠「偶尔成功一次」把连续失败计数
    清零，才长期赖在 hosts 里。但「本轮能用」必须一律不换 —— 否则
    窗口里攒了旧失败，会在 IP 明明能开的这一轮把它撤下，变成洗牌。

    慢（slowttfb / slowspeed）不计入失败：一轮 157 个检查点并发探测时
    会把自己那条跨境链路挤爆，出现 5~15 秒的假慢；拿它当失败，就会把
    整批本来能用的 Google 域一起换掉。只有真连不上/超时/证书错才算。
    """
    now = int(time.time())
    rec = state.get(key) or {}
    hist = [(t, s) for t, s in rec.get("hist", [])
            if isinstance(t, int) and now - t < WINDOW_SEC]
    status = st or "fail"
    usable = bool(ok) or status.startswith("slow")
    if hist and now - hist[-1][0] < 60:
        # 同一轮里常驻守护和定时优选可能各跑一次；同一次拥塞不能记成两票，
        # 且这一轮只要有任何一次实测能用，就按「能用」记账。
        if hist[-1][1] != "ok":
            hist[-1] = (now, "ok" if usable else status)
    else:
        hist.append((now, "ok" if usable else status))
    hist = hist[-WINDOW_N:]
    bad = sum(1 for _t, s in hist if s != "ok")
    state[key] = {"hist": hist, "fails": bad, "ts": now,
                  "reason": "ok" if usable else status}
    # 本轮能用就不换；只有本轮确实打不开、且历史上也不稳定才撤下。
    return bad, len(hist), (not usable and len(hist) >= WINDOW_MIN
                            and bad >= WINDOW_BAD)


# 冗余自愈：每个主域记住「应该有几个在用 IP」。链路整体抖动时坏 IP 被撤下、
# 候选又全部测不过，hosts 会退化成单 IP；旧逻辑下一轮 need = len(ips)-len(keep)
# = 0，就算链路恢复了也永远不会自己补回冗余（必须人工介入）。现在把目标数
# 持久化，只要还缺，每轮都由 101 自己从候选池实测补，直到补够为止。
NO_REFILL_ROUTES = {"gt", "google", "auto"}  # 这几路天然单 IP，不补
REFILL_MIN = int(os.environ.get("PREF_REFILL_MIN", "3"))
REFILL_RETRY_SEC = int(os.environ.get("PREF_REFILL_RETRY_SEC", "300"))
HEAL_LOCK = os.path.join(DATA_DIR, ".wd_heal.lock")
HEAL_LOCK_STALE = 900
# 主域整行被撤空后，files 里就没这行了，守护永远不会自己把它加回来。
# 记住每路的主域，缺了就从候选池由 101 实测重建（auto 路主域动态，不重建）。
MAIN_DOMAINS = {
    "cf": "cloudflare.com",
    "google": "www.google.com",
    "gt": "translate.google.com",
    "github": "github.com",
    "ghcr": "ghcr.io",
    "tmdb": "www.themoviedb.org",
    "imdb": "www.imdb.com",
}


def reconcile_blacklist(files, static_rows, results, state):
    """101 每轮自己复核黑名单：把「误拉黑的在用 IP」自动解除，不用等人、不等 6h。

    只认本轮 101 自己发出的分域实测（results）；任一在用域判 BAD 就保留
    （例如某节点对 csp 域证书不匹配）。解除后同步清掉该 IP 的失败窗口，
    避免下一轮又按旧账重新拉黑。
    """
    try:
        bad = subs.load_bad()
        if not bad:
            return 0
        used = selfheal.build_used(files, static_rows)
        now = int(time.time())
        # 解除历史存 state（不写 blacklist，过期后自然失效）；30 分钟内
        # 不重复解除同一个 IP，避免补位探测把它再打黑后又立刻放出来。
        recent = {}
        for k, v in state.items():
            if k.startswith("unban|"):
                try:
                    recent[k.split("|", 1)[1]] = float(v)
                except (TypeError, ValueError):
                    pass
        freed = selfheal.plan_unban(bad, used, results,
                                    recent_unbans=recent)
        if not freed:
            return 0
        for ip in freed:
            bad.pop(ip, None)
            for k in [k for k in state if k.endswith("|" + ip)
                      and not k.startswith("unban|")]:
                state.pop(k, None)
            state["unban|" + ip] = now
        subs.jsave(subs.BLACK_FILE, bad)
        log("黑名单复核：%d 个在用 IP 本轮 101 实测全通过，自动解除（%s）"
            % (len(freed), ",".join(freed[:6])))
        return len(freed)
    except Exception as e:
        log("黑名单复核异常：%s" % e)
        return 0


def _local_rev():
    try:
        with open(VERSIONS_FILE, encoding="utf-8") as f:
            for ln in f:
                if ln.startswith("build_rev="):
                    return ln.strip().split("=", 1)[1]
    except Exception:
        pass
    return ""


def _push_warn(msg):
    """异常告警只发两行，同一状态只发一次（不刷屏）。"""
    try:
        cfg = (jload(SETTINGS_FILE, {}) or {}).get("push") or {}
        if not cfg.get("enabled") or not cfg.get("url"):
            return
        subprocess.run([sys.executable, os.path.join(HERE, "push.py"),
                        cfg["url"], "镜像异常", msg],
                       timeout=10, capture_output=True)
    except Exception:
        pass


def image_guard_async():
    """每天一次：101 自己核对镜像仓库状态，异常自动告警（无需人工跑脚本）。"""
    st = jload(IMG_GUARD_STATE, {})
    now = int(time.time())
    if now - int(st.get("ts", 0) or 0) < IMG_GUARD_SEC:
        return
    st["ts"] = now
    jsave(IMG_GUARD_STATE, st)

    def _run():
        try:
            s = selfheal.fetch_registry_state()
            level, msg = selfheal.image_status(s.get("ghcr"), s.get("mirror"),
                                               _local_rev(), s.get("rev"))
            key = "%s|%s|%s|%s" % (level, s.get("ghcr"), s.get("mirror"), s.get("rev"))
            cur = jload(IMG_GUARD_STATE, {})
            if level == "warn":
                log("镜像复核：%s" % msg)
                if cur.get("last") != key:
                    cur["last"] = key
                    jsave(IMG_GUARD_STATE, cur)
                    _push_warn(msg)
            elif cur.get("last"):
                cur["last"] = ""
                jsave(IMG_GUARD_STATE, cur)
        except Exception as e:
            log("镜像复核异常：%s" % e)
    threading.Thread(target=_run, daemon=True).start()


def _heal_once_impl(only_route=None):
    """巡检 + 精确补位 + 冗余自愈（不含真翻自检与互斥锁）。

    only_route：粘滞守卫只需要修自己那一路，传路名就只巡检这一路的 hosts，
    不再把全量 131 个检查点重跑一遍（这是优选一轮要 5 分钟的主因）。
    静态钉子和主域重建只在全量轮（常驻守护）里做。
    """
    state = jload(STATE_FILE, {})
    files = {}
    for name in sorted(os.listdir(PREF_DIR)):
        if not name.endswith(".hosts") or name == "all.hosts":
            continue
        route = name[:-6]
        if only_route and route != only_route:
            continue
        rows = read_lines(os.path.join(PREF_DIR, name))
        if rows:
            # 所有路（含 gt）逐行全量巡检；gt 主域由 health() 内部改打真翻接口，
            # 附加域用各自 SNI，避免「只查第一行」漏掉整批在用 IP。
            files[route] = (rows, rows)

    items = [(route, dom, ip) for route, (_rows, scan) in files.items()
             for dom, ips in scan for ip in ips]
    # 静态钉子一起并发巡检：它在 hosts 插件里优先于 all.hosts，必须同样受守护。
    # 单路补位轮跳过它（由常驻守护的全量轮负责），省掉一大半跨境探测。
    if only_route:
        static_rows, static_items = [], []
    else:
        static_rows, static_items = static_targets()
    results = _batch_health(items + static_items)
    # 只用本轮 101 自己的实测结果复核黑名单，且只在全量轮做（证据最全）：
    # 误拉黑的在用 IP 当场自动解除，本轮补位就能重新把它算进候选。
    if not only_route:
        reconcile_blacklist(files, static_rows, results, state)
    # 把这一轮 101 实测结果留档：定时优选粘滞守卫在 90 秒内直接复用，
    # 不再把同一批在用 IP 重复探一遍（省跨境连接，也不挤占其它设备带宽）。
    try:
        jsave(SNAP_FILE, {"ts": int(time.time()),
                          "results": {"%s|%s|%s" % k: list(v)
                                      for k, v in results.items()}})
    except Exception:
        pass
    checked = len(items)
    swapped = 0
    changed = False
    dropped_all = []

    # ---- 主域整行缺失：101 自己从候选池实测重建 ----
    # 链路整体抖动时旧逻辑会「全打不开、也没有可换的，已撤下这一行」，
    # 之后 files 里再没有这个域，守护永远不会把它加回来，只能人工重选。
    now = int(time.time())
    for route, dom in MAIN_DOMAINS.items():
        if route not in files:
            continue
        rows, scan = files[route]
        if any(d == dom for d, _ in scan):
            continue
        rkey = "rebuild|%s|%s" % (route, dom)
        if now - int((state.get(rkey) or {}).get("ts", 0) or 0) < REFILL_RETRY_SEC:
            continue
        state[rkey] = {"ts": now}
        cands = candidates(route, dom, set())[:12]
        cr = _batch_health([(route, dom, c) for c in cands])
        good = [c for c in cands
                if cr.get((route, dom, c), (False, "fail", None, None))[0]]
        if not good:
            log("%s 路：%s 主域整行缺失、候选暂不可用，101 下轮继续自己重建"
                % (route, dom))
            continue
        tkey = "target|%s|%s" % (route, dom)
        target = max(int((state.get(tkey) or {}).get("n", 0) or 0), REFILL_MIN)
        state[tkey] = {"n": target, "ts": now, "try_ts": 0}
        picked = good[:target]
        for c in picked:
            results[(route, dom, c)] = (True, "ok", None, None)
        rebuilt = [(dom, picked)] + rows
        write_hosts(route, dom, picked, rows)
        files[route] = (rebuilt, rebuilt)
        changed = True
        log("%s 路：%s 主域整行缺失，101 自己实测重建 %d 个 IP"
            % (route, dom, len(picked)))

    for route, (rows, scan) in files.items():
        new_rows = []
        for idx, (dom, ips) in enumerate(scan):
            keep, dropped = [], []
            is_main = (idx == 0)
            tkey = "target|%s|%s" % (route, dom)
            rec = state.get(tkey) or {}
            if is_main and route not in NO_REFILL_ROUTES:
                target = max(len(ips), int(rec.get("n", 0) or REFILL_MIN))
                state[tkey] = {"n": target, "ts": int(time.time()),
                               "try_ts": int(rec.get("try_ts", 0) or 0)}
            else:
                # 资源域必须保持多点冗余：以前 target=len(ips)，单点坏了只补回
                # 1 个，跨境一抖整个域就打不开。其余域沿用原有行数不动。
                target = (max(len(ips), RESOURCE_MIN_IPS)
                          if _is_resource_domain(dom) else len(ips))
            for ip in ips:
                ok, st, ms, sp = results.get((route, dom, ip),
                                             (False, "fail", None, None))
                key = "%s|%s|%s" % (route, dom, ip)
                if route == "gt":
                    # 翻译组 5 个域必须钉同一组 IP。单域偶发抖动不能按失败率
                    # 单独换掉，否则依赖域和主域会被拆到不同组，整页翻译又坏。
                    # gt 沿用「连续失败」+ gt_guard 真翻自检统一整组重选。
                    if ok:
                        state.pop(key, None)
                        state.pop("%s|%s" % (route, ip), None)
                        keep.append(ip)
                        continue
                    n = int((state.get(key) or {}).get("fails", 0)) + 1
                    state[key] = {"fails": n, "ts": int(time.time()), "reason": st}
                    if n >= MAX_STRIKES:
                        dropped.append((ip, st + "x%d" % n))
                    else:
                        keep.append(ip)
                    continue
                if is_hard(st):
                    state.pop(key, None)
                    dropped.append((ip, st))
                    continue
                # 资源域的快速换钉交给独立哨兵（30s 一轮 + 连续 2 次确认）；
                # 主巡检 180s 一轮仍走窗口确认，两套都必须防抖，否则单次
                # 跨境 SYN 抖动就会把 9 个域整批换掉 + 拉黑 6 小时。
                bad, total, drop = window_strike(state, key, ok, st)
                if drop:
                    dropped.append((ip, "%s %d/%d" % (st, bad, total)))
                else:
                    keep.append(ip)
                    state.pop("%s|%s" % (route, ip), None)
            need = max(0, target - len(keep))
            # 「纯冗余补齐」（本轮一个坏 IP 都没有）才限频：撤下坏 IP 时
            # 必须立刻尝试补位，不能因为限频把该换的漏掉。
            if need and not dropped and is_main and route not in NO_REFILL_ROUTES:
                now = int(time.time())
                # 只剩 1 个 IP 属于单点裸奔：跨境链路一抖就整站打不开，
                # 不能让它再等 5 分钟的「纯冗余补齐」限频。
                starving = len(keep) <= 1
                if (not starving and
                        now - int((state.get(tkey) or {}).get("try_ts", 0) or 0)
                        < REFILL_RETRY_SEC):
                    need = 0
                else:
                    state[tkey]["try_ts"] = now
            if not dropped and not need:
                new_rows.append((dom, keep))
                continue
            added = []
            if need:
                cands = candidates(route, dom, set(ips) | {d[0] for d in dropped})[:12]
                cr = _batch_health([(route, dom, c) for c in cands])
                for c in cands:
                    if len(added) >= need:
                        break
                    o, st2, _m, _s = cr.get((route, dom, c),
                                            (False, "fail", None, None))
                    if o:
                        added.append(c)
                        subs.cmd_bump(route, c, "ok")
                    elif is_hard(st2):
                        subs.mark_bad(c, st2, route)
            final = keep + added
            # ---- 链路抖动保护（主站也要有，资源域早就有了）----
            # 2026-11-11 实测：github.com 主站被巡检逐个撤成单点 140.82.113.3，
            # 而这颗钉子本身 6s 超时；内部判据却认为「已处理」，用户网页 0/10。
            # 整轮在用 IP 大面积不通 = 跨境出口丢包，此时撤任何一个都是误杀，
            # 候选也必然全 timeout，结果就是 3 个冗余被压成 1 个死钉。
            tested = [ip for ip in ips if (route, dom, ip) in results]
            nfail = sum(1 for ip in tested
                        if not results.get((route, dom, ip), (False,))[0])
            final, outage, thin = _guard_final(ips, final, target,
                                               nfail, len(tested))
            if outage:
                log("%s 路：%s 本轮 %d/%d 在用 IP 不通，判定链路抖动，"
                    "保留原行不动（不撤钉、不拉黑）"
                    % (route, dom, nfail, len(tested)))
                dropped = []
                added = []
            elif thin:
                # 绝不把行写瘦：候选全 timeout 时撤掉坏钉会压成单点死钉，
                # 比留着那颗坏钉更糟。链路恢复后候选能测通，自然补齐并换掉。
                log("%s 路：%s 补位不足，保留原 %d 个 IP 不动，等链路恢复"
                    % (route, dom, len(ips)))
                dropped = []
                added = []
            if not final:
                # 以前这里只打印一句「保留原行等下轮自己判」就结束。若黑名单
                # 被抖动污染到把候选池清空，下一轮还是同样的空池 —— 死循环，
                # 用户看到的「不能稳定打开」就是这么一直挂着没人修。
                # 现在先自救：忽略黑名单重取候选，用 101 同一套判据实测复核，
                # 通过才写回并顺手解除误拉黑。真的一条都探不通才保留原行。
                rescued = []
                try:
                    rc = candidates(route, dom, set(ips), ignore_bad=True)[:12]
                    rr = _batch_health([(route, dom, c) for c in rc])
                    for c in rc:
                        if rr.get((route, dom, c), (False, "fail", None, None))[0]:
                            subs.clear_bad(c)
                            subs.cmd_bump(route, c, "ok")
                            rescued.append(c)
                            if len(rescued) >= target:
                                break
                except Exception as e:
                    log("%s 路：%s 候选池自救复核异常：%s" % (route, dom, e))
                if rescued:
                    final = rescued
                    log("%s 路：%s 候选池被黑名单清空，101 实测自救补回 %s"
                        % (route, dom, " ".join(rescued)))
                else:
                    # 链路整体抖动，不是 IP 坏。绝不把整行删成空行（那样 DNS
                    # 会走上游真 IP，往往更糟），也不把这些 IP 写进黑名单。
                    final = list(ips)
                    log("%s 路：%s 本轮全测不通、自救复核也无可用 IP，保留原行等下轮再判"
                        % (route, dom))
                removed = []
            else:
                removed = [ip for ip, _ in dropped if ip not in final]
            for ip, why in dropped:
                if ip not in removed:
                    continue
                subs.mark_bad(ip, why, route)
                state.pop("%s|%s|%s" % (route, dom, ip), None)
                log("%s 路：%s 的 %s 打不开（%s），已加入黑名单，%d 小时内不再用"
                    % (route, dom, ip, why_label(why), subs.BAD_TTL_H))
                subs.add_event("swap", route, ip, why, dom)
            dropped_all += removed
            new_rows.append((dom, final))
            swapped += len(removed)
            if final != ips:
                changed = True
            if added and removed:
                log("%s 路：%s 打不开，换成 %s（新 IP 已实测通过）"
                    % (route, dom, ",".join(added)))
            elif added:
                log("%s 路：%s 冗余 %d/%d，101 自己实测补回 %s"
                    % (route, dom, len(keep), target, ",".join(added)))
            elif removed:
                if len(final) < target:
                    log("%s 路：%s 撤下打不开的保留 %d 个，仍缺 %d 个冗余，101 下轮继续自己补"
                        % (route, dom, len(final), target - len(final)))
                else:
                    log("%s 路：%s 撤下打不开的，保留 %d 个仍可用"
                        % (route, dom, len(final)))
            elif len(final) < target:
                log("%s 路：%s 候选暂不可用，仍缺 %d 个冗余，101 下轮继续自己补"
                    % (route, dom, target - len(final)))
        if not new_rows:
            continue
        if new_rows != rows:
            # 一轮巡检要探 100+ IP、耗时几分钟，期间资源哨兵可能已改写同一份
            # github.hosts。以磁盘最新内容重放资源域行，避免主巡检拿几分钟前的
            # 旧快照把哨兵刚换好的钉子覆盖回去（2026-11-11 23:43 实测竞态）。
            try:
                disk = dict(read_lines(os.path.join(PREF_DIR, "%s.hosts" % route)))
            except Exception:
                disk = {}
            fresh = []
            for d, l in new_rows[1:]:
                if _is_resource_domain(d) and disk.get(d):
                    fresh.append((d, list(disk[d])))
                else:
                    fresh.append((d, l))
            write_hosts(route, new_rows[0][0], new_rows[0][1], fresh)
            changed = True

    # 粘滞守卫「沿用不换」不会跑 write_route，漏网依赖域只能由守护补。
    if fill_missing_deps(only_route):
        changed = True
    if dropped_all:
        purge_ips_everywhere(dropped_all)
    static_changed, static_swapped = heal_static(state, static_rows, results)
    if static_changed:
        changed = True
        swapped += static_swapped
    try:
        jsave(STATE_FILE, state)
    except Exception:
        pass
    if changed:
        reload_mosdns()
    log("这轮巡检结束：检查 %d 个 IP（含静态钉子 %d 个），换掉 %d 个（其余都能正常打开）"
        % (checked + len(static_items), len(static_items), swapped))
    return swapped


def fill_missing_deps(only_route=None):
    """漏网依赖域由 101 自己发现并实测补上（沿用现有 IP，能用就不换）。

    写 hosts 的 write_route 里本来就会补 PREF_EXTRA_DOMAINS 和自动发现的
    域名，但粘滞守卫「全健康沿用」会在写之前退出，那些逻辑一次都不跑。
    这里不依赖定时优选：只取本路当前在用的 IP，用该域真实资源路径逐个
    实测（generate_204 而不是根路径），通过才追加一行。
    """
    changed = False
    for route, specs in NEEDED_DEPS.items():
        if only_route and only_route != route:
            continue
        path = os.path.join(PREF_DIR, "%s.hosts" % route)
        rows = read_lines(path)
        if not rows:
            continue
        have = {d for d, _ in rows}
        todo = [(d, p) for d, p in specs if d not in have]
        if not todo:
            continue
        ips = rows[0][1][:3]
        extra = list(rows[1:])
        touched = False
        for dom, probe_path in todo:
            good = []
            for ip in ips:
                try:
                    r = tuple(https_probe.check(ip, dom, PORT, TIMEOUT, 1,
                                                probe_path, None,
                                                strict_redirect=False))
                    if len(r) > 1 and r[1] == "ok":
                        good.append(ip)
                except Exception:
                    pass
            if not good:
                log("%s 路：依赖域 %s 实测没 IP 能服务，101 下轮继续自己补"
                    % (route, dom))
                continue
            extra.append((dom, good))
            log("%s 路：漏网依赖域 %s 由 101 实测补上（沿用 %s，未换任何在用 IP）"
                % (route, dom, ",".join(good)))
            touched = True
        if touched:
            write_hosts(route, rows[0][0], rows[0][1], extra)
            changed = True
    return changed


def heal_once(only_route=None):
    """对外入口：同一时间只允许一轮巡检跑完，避免常驻守护、粘滞守卫、
    手动验收三方并发改写 hosts（日志出现重复「换掉 N 个」就是这么来的）。
    only_route 非空时只巡检这一路，供粘滞守卫做精确补位，不再全量重扫。
    容器被强杀可能留下陈旧锁，超过 15 分钟自动清掉再跑一轮。
    """
    try:
        fd = os.open(HEAL_LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        try:
            if time.time() - os.path.getmtime(HEAL_LOCK) > HEAL_LOCK_STALE:
                os.remove(HEAL_LOCK)
                return heal_once(only_route)
        except OSError:
            pass
        log("已有巡检正在跑，本轮跳过（让那一轮自己完整跑完）")
        return 0
    try:
        os.write(fd, str(os.getpid()).encode())
        return _heal_once_impl(only_route)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.remove(HEAL_LOCK)
        except OSError:
            pass


# ---------------------------------------------------------------- 黑名单污染自愈
BL_HEAL_STAMP = os.path.join(DATA_DIR, ".blacklist_heal_stamp")
BL_HEAL_INTERVAL = int(os.environ.get("PREF_BL_HEAL_SEC", "1800"))
BL_HEAL_MAX = int(os.environ.get("PREF_BL_HEAL_MAX", "90"))
# 抖动 / 响应码不符是软失败，不能当永久故障；cert / cf / wrong 才是硬证据
BL_SOFT_REASONS = ("wrongres", "timeout", "fail", "busy", "blocked", "slow")


def _bl_probe_domain(ip):
    """资源段走 Fastly 专属判据，主站段走真页面判据。"""
    if ip.startswith(("151.101.", "185.199.")):
        return "raw.githubusercontent.com"
    return "github.com"


def heal_blacklist_pollution(force=False):
    """按 101 实测洗掉黑名单污染，返回 (解除条数, 明细)。

    1) hosts 里正在用的 IP 绝不能留在黑名单：否则故障补位时它自己被
       candidates() 排除，守护只能打印「保留原行等下轮自己判」，自愈被
       自己的黑名单锁死（2026-11-10 github 路 426 条污染就是这么卡住的）。
    2) 软失败条目每半小时用 101 同一套判据复核一次，通过即解除；硬故障
       （cert / cf / wrong）不动，等 6h TTL 自然过期。
    """
    now = int(time.time())
    d = subs.load_bad()
    if not isinstance(d, dict) or not d:
        return 0, []

    # 1) 所有 *.hosts 里在用的 IP，无条件解禁、每轮都做。
    #    这条绝不能被下面的 30 分钟节流挡住：在用 IP 一旦被抖动误判拉黑，
    #    半小时内故障补位都会把它自己排除掉。
    in_use = []
    try:
        for name in sorted(os.listdir(PREF_DIR)):
            if not name.endswith(".hosts") or name == "all.hosts":
                continue
            for _dom, ips in read_lines(os.path.join(PREF_DIR, name)):
                in_use.extend(ips)
    except Exception:
        pass
    freed = []
    for ip in set(in_use):
        if ip in d:
            d.pop(ip, None)
            freed.append("在用IP " + ip)

    # 2) 软失败复核才走节流：几十上百条 HTTPS 探测不能每轮都跑。
    review = bool(force)
    if not force:
        try:
            last = int(open(BL_HEAL_STAMP, encoding="utf-8").read().strip() or 0)
        except Exception:
            last = 0
        review = now - last >= BL_HEAL_INTERVAL
    if review:
        try:
            with open(BL_HEAL_STAMP, "w", encoding="utf-8") as f:
                f.write(str(now))
        except Exception:
            pass
        soft = [ip for ip, v in list(d.items())
                if isinstance(v, dict)
                and str(v.get("reason", "")).startswith(BL_SOFT_REASONS)][:BL_HEAL_MAX]

        def _check(ip):
            try:
                ok = health(ip, _bl_probe_domain(ip), "github")[0]
                return ip, ok
            except Exception:
                return ip, False

        try:
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=16) as ex:
                rs = list(ex.map(_check, soft))
        except Exception:
            rs = []
        for ip, ok in rs:
            if ok:
                d.pop(ip, None)
                freed.append("实测可用 " + ip)

    if freed:
        try:
            subs.jsave(subs.BLACK_FILE, d)
        except Exception:
            for item in freed:
                subs.clear_bad(item.split()[-1])
        log("黑名单自愈：按 101 实测/在用状态解除 %d 条，候选池已恢复" % len(freed))
    return len(freed), freed


def run_once():
    """常驻守护入口：先清废行 → 真翻自检 → 等优选锁释放 → 全量巡检补位。"""
    # hosts 废行自愈优先于一切：纯 IPv6 的行会把某域名钉成 NODATA，
    # 且因 pref_hosts 早于 cache/上游，这类域名永远解析不出来。放在最前面，
    # 保证即便本轮因优选锁/真翻自检提前 return，废行也照样被清掉。
    try:
        n_rm, det = sanitize_hosts()
        if n_rm:
            for d in det[:10]:
                log("hosts 自愈：剔除纯 IPv6 废行 %s" % d)
            log("hosts 自愈：本轮剔除 %d 条纯 IPv6 废行（这些域名回落上游解析 IPv4）" % n_rm)
            reload_mosdns()
    except Exception as e:
        log("hosts 自愈异常：%s" % e)
    # 黑名单污染先洗：抖动误判会把候选池清空，后面所有补位/纠钉都会
    # 因为「没可用 IP」空转。放在一切补位之前，保证自愈不会锁死自己。
    try:
        n_bl, bl_det = heal_blacklist_pollution()
        if n_bl:
            for item in bl_det[:10]:
                log("黑名单自愈：解除 %s" % item)
            log("黑名单自愈：本轮共解除 %d 条" % n_bl)
    except Exception as e:
        log("黑名单自愈异常：%s" % e)
    # 剔完还得补：pin 文件里有、hosts 里没有的域名，用已验证的固定 IP 写回，
    # 否则它就一直走上游解析（而固定 IP 才是真正稳定的那条）。
    try:
        n_fix, fix_det = heal_pin_gaps()
        if n_fix:
            for d in fix_det[:PIN_HEAL_MAX_DOMAINS]:
                log("固定 IP 自愈：补回 %s" % d)
            log("固定 IP 自愈：本轮补回 %d 个域名（已重载 mosdns）" % n_fix)
    except Exception as e:
        log("固定 IP 自愈异常：%s" % e)
    # 域名在、IP 是错的（主站边缘 301 踢走）也要纠：否则 ghcr 层文件 404，
    # docker pull 报 unknown blob，而粘滞守卫会一直「保住」这条看着能用的错钉。
    try:
        n_bad, bad_det = heal_bad_fastly_pins()
        if n_bad:
            for d in bad_det[:PIN_HEAL_MAX_DOMAINS]:
                log("资源域自愈：纠正错钉 %s" % d)
            log("资源域自愈：本轮纠正 %d 个域名（已重载 mosdns）" % n_bad)
    except Exception as e:
        log("资源域自愈异常：%s" % e)
    gt_guard()
    if os.path.isdir(LOCK_DIR):
        # 以前一遇到优选锁就整轮跳过；优化前优选一轮要 5 分钟，守护会连跳
        # 两轮、自愈被饿死。改成最多等 45 秒，锁一放立刻跑自己那一轮。
        for _ in range(3):
            time.sleep(15)
            if not os.path.isdir(LOCK_DIR):
                break
        if os.path.isdir(LOCK_DIR):
            log("优选任务仍在跑，这轮巡检先跳过（下一轮会补上）")
            return 0
    if os.path.exists(GT_GUARD_FLAG):
        try:
            os.remove(GT_GUARD_FLAG)
        except Exception:
            pass
        log("翻译真翻自检连续失败，立即触发 gt 路重选")
        # 真翻自检失败必须能真正重选；给这一条链路放行粘滞守卫，
        # 否则守卫用 HTTPS 判据判「还能开」却把整页翻译的退化挡在门外。
        env = dict(os.environ)
        env["PREF_RESELECT"] = "1"
        threading.Thread(
            target=lambda: subprocess.run(
                ["/app/scheduler/scheduler.sh", "once", "gt"],
                capture_output=True, timeout=240, env=env),
            daemon=True).start()
        return 0
    return heal_once()


def _doh_scan_async():
    """上游 DoH 定时扫描（自带限频：没到点会立刻返回）。

    放在线程里跑，是因为一轮扫描要真连二十几条 DoH，几秒到十几秒，
    不能把 IP 巡检的主循环堵住。
    """
    def _run():
        try:
            import doh_watch
            r = doh_watch.scan()
            if r.get("applied") or (r.get("new") and r.get("mode") == "manual"):
                log("上游扫描：%s" % r.get("summary", ""))
        except Exception as e:
            log("上游扫描异常：%s" % e)
    t = threading.Thread(target=_run, daemon=True)
    t.start()


# ---------------------------------------------------------------- 体验哨兵
def _api_ok(ip, tries=2):
    """api.github.com 根路径固定 200；用 101 自身 curl 连测 2 次。

    通用 health() 把 GitHub Pages 的 404 错误页当成正常 HTTPS 应答，这正是
    api 错钉一直没被主巡检发现、却让全屋 GitHub API 全挂的原因。
    跨境抖动时 IP 会「碰巧通一次」，单次 200 不足以补进冗余，必须连续通过。
    """
    for _ in range(tries):
        try:
            p = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "-m", "6", "--resolve", "api.github.com:443:" + ip,
                 "https://api.github.com/"],
                capture_output=True, timeout=8)
            if (p.stdout or b"").decode("utf-8", "replace").strip() != "200":
                return False
        except Exception:
            return False
    return True


def _experience_probe():
    """按 101 自身 DNS 真实访问，每个探针连测 3 次；返回 (是否可用, 明细)。

    与内部 health() 的区别：不带 --resolve，走的就是全屋设备同一条 DNS 链，
    用户打不开时这里也一定打不开 —— 这才是「用户视角」的验收。
    """
    detail = {}
    for name, url, want in EXPERIENCE_PROBES:
        codes = []
        for _ in range(3):
            try:
                p = subprocess.run(
                    ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                     "-m", "6", url], capture_output=True, timeout=8)
                codes.append((p.stdout or b"").decode("utf-8", "replace").strip()
                             or "000")
            except Exception:
                codes.append("000")
        detail[name] = {"codes": codes,
                        "ok": sum(1 for c in codes if c == want)}
    return all(v["ok"] >= 2 for v in detail.values()), detail


def _write_experience_status(status):
    try:
        jsave(EXPERIENCE_STATUS, status)
    except Exception as e:
        log("体验哨兵：状态写入失败：%s" % e)


def _experience_self_heal(status):
    """101 主动自愈：只按自己的实测结果写，绝不手工糊 IP。

    关键克制：验收失败 ≠ 链路能修。跨境整体丢包时所有候选也 timeout，
    这时绝不洗牌、绝不写瘦，只如实记录原因；有实测可用候选才换钉。
    """
    actions = []
    try:
        freed, _ = heal_blacklist_pollution(force=True)
        actions.append("黑名单复核解除 %d 条" % freed)
    except Exception as e:
        actions.append("黑名单复核异常 %s" % e)
    try:
        n, _det = heal_bad_fastly_pins(force=True)
        actions.append("资源域补齐 %d 个域" % n)
    except Exception as e:
        actions.append("资源域自愈异常 %s" % e)
    try:
        route = "github"
        rows = list(read_lines(os.path.join(PREF_DIR, route + ".hosts")))
        by_dom = {d: list(ips) for d, ips in rows}
        fixed = {}
        for dom in ("github.com", "api.github.com"):
            cur = by_dom.get(dom, [])
            if not cur:
                continue
            cands = candidates(route, dom, set(cur), ignore_bad=True)[:24]
            if dom == "api.github.com":
                from concurrent.futures import ThreadPoolExecutor
                with ThreadPoolExecutor(max_workers=8) as ex:
                    oks = list(ex.map(_api_ok, cands))
                good = [c for c, ok in zip(cands, oks) if ok]
                cur_ok = [ip for ip in cur if _api_ok(ip)]
            else:
                items = ([(route, dom, c) for c in cands]
                         + [(route, dom, ip) for ip in cur])
                cr = _batch_health(items)
                good = [c for c in cands
                        if cr.get((route, dom, c), (False,))[0]]
                cur_ok = [ip for ip in cur
                          if cr.get((route, dom, ip), (False,))[0]]
            # api 原本就是单点，有 1 个实测 200 的边缘就该换；主站仍要求
            # 至少 2 个，避免拿「碰巧通一次」的 IP 去换掉整行冗余。
            min_good = 1 if dom == "api.github.com" else 2
            if len(good) >= min_good:
                # 实测可用的优先：旧钉不能因为「原本占着 3 个位置」就把新
                # 测通的 IP 挤掉，否则自愈看起来跑了、行其实一个字没换。
                new = list(dict.fromkeys(cur_ok + good))[:max(3, len(cur))]
                if new != cur:
                    fixed[dom] = new
                    actions.append("%s 101 实测换成 %s" % (dom, " ".join(new)))
            else:
                actions.append("%s 本轮无可用候选（跨境丢包，DNS 层无法修复），"
                               "保留原 %d 个 IP 不动" % (dom, len(cur)))
        if fixed:
            by_dom.update(fixed)
            # 探测耗时几秒，期间资源哨兵可能已改同一份文件，重放磁盘最新行
            try:
                disk = dict(read_lines(os.path.join(PREF_DIR, route + ".hosts")))
                for d, ips in disk.items():
                    if d not in fixed and _is_resource_domain(d):
                        by_dom[d] = list(ips)
            except Exception:
                pass
            main = by_dom.get("github.com", [])
            extra = [(d, ips) for d, ips in by_dom.items()
                     if d != "github.com"]
            write_hosts(route, "github.com", main, extra)
            # 主动自愈的换钉必须立刻生效：以前只写 hosts 不重载，要等别的
            # 任务碰巧重载，实测 00:10:48 换完到 00:12:03 才生效。
            reload_mosdns(force=True)
    except Exception as e:
        actions.append("主站重选异常 %s" % e)

    status["last_heal"] = int(time.time())
    status["last_heal_actions"] = actions
    changed = any("101 实测换成" in a for a in actions)
    if changed:
        status["verdict"] = "self_healed"
        status["note"] = ("101 已主动发现、换钉并立即重载；"
                          ".252/.254 缓存约 120 秒后同步，期间旧应答属正常")
    else:
        status["verdict"] = "upstream_packet_loss"
        status["note"] = ("101 已主动验收并自愈：本轮候选实测全不通，"
                          "是跨境出口按 IP 段丢包，DNS 层无法修复；"
                          "配置保持多点冗余，链路恢复后自动恢复")
    _write_experience_status(status)
    for a in actions:
        log("体验哨兵自愈：%s" % a)
    try:
        subs.add_event("selfheal", "dns", "", "体验验收触发的主动自愈",
                       "; ".join(actions)[:180])
    except Exception:
        pass


def experience_guard_loop():
    """按真实访问主动验收，别再等用户打开网页才发现坏。

    每 EXPERIENCE_GUARD_SEC 走 101 自身 DNS 连测 github.com 与 raw 各 3 次；
    连续 2 轮不可用就主动触发一次强制自愈（EXPERIENCE_HEAL_SEC 限频），
    结果写 health_status.json 和面板事件。跨境丢包时如实标注「非 DNS 故障」，
    不假装修好，也不无限洗牌。
    """
    fails = 0
    last_heal = 0
    while True:
        time.sleep(max(20, EXPERIENCE_GUARD_SEC))
        try:
            usable, detail = _experience_probe()
            status = {
                "ts": int(time.time()),
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "usable": usable,
                "probes": detail,
                "consecutive_fail": fails,
                "last_heal": last_heal,
                "verdict": "",
                "note": "",
            }
            if usable:
                if fails:
                    log("体验哨兵：101 真实访问恢复正常（github/raw 均可用）")
                fails = 0
                status["note"] = "101 真实访问正常"
                _write_experience_status(status)
                continue
            fails += 1
            status["consecutive_fail"] = fails
            status["note"] = ("101 自身 DNS 真实访问失败，正在主动自愈"
                              if fails >= 2 else "101 检测到访问异常，继续观察")
            _write_experience_status(status)
            log("体验哨兵：第 %d 轮真实访问不可用 github=%s raw=%s"
                % (fails, detail.get("github", {}).get("codes"),
                   detail.get("raw", {}).get("codes")))
            try:
                subs.add_event("experience", "dns", "",
                               "真实访问失败 %d 轮" % fails,
                               "github=%s raw=%s" % (
                                   detail.get("github", {}).get("codes"),
                                   detail.get("raw", {}).get("codes")))
            except Exception:
                pass
            if fails >= 2 and time.time() - last_heal >= EXPERIENCE_HEAL_SEC:
                last_heal = int(time.time())
                log("体验哨兵：连续 %d 轮不可用，101 主动触发强制自愈" % fails)
                threading.Thread(
                    target=lambda: _experience_self_heal(dict(status)),
                    daemon=True).start()
        except Exception as e:
            log("体验哨兵异常：%s" % e)


def resource_guard_loop():
    """资源域哨兵：与主巡检解耦，独立高频复核全部资源域在用 IP。

    主巡检 180s 一轮、还要过 3 次失败窗口；单点坏钉靠它要挂十几分钟
    （2026-11-10 raw.githubusercontent.com 单点钉死就是这个下场）。
    这里每 30s 只探资源域（正常一轮全是好 IP，并发探测几秒就完），
    有坏钉立即换、冗余不足立即补，不改动任何其它路。
    """
    while True:
        time.sleep(max(15, RESOURCE_GUARD_SEC))
        try:
            n, det = heal_bad_fastly_pins(force=True)
            if n:
                log("资源域哨兵：立即修正 %d 个域名：%s"
                    % (n, "; ".join(det[:4])))
        except Exception as e:
            log("资源域哨兵异常：%s" % e)


def main():
    once = "--once" in sys.argv
    sec, on = runtime_cfg()
    log("启动：每 %d 秒把每路在用的 IP 各打开一次（单个超时 %.0fs），"
        "本轮能用就沿用；明确打不开（1034/证书）立刻换，"
        "本轮打不开且最近 %d 轮里 >=%d 次失败才换（慢不算失败）；"
        "翻译组仍要连续 %d 次失败才整组重选%s"
        % (sec, TIMEOUT, WINDOW_N, WINDOW_BAD, MAX_STRIKES,
           "（当前巡检已关闭）" if not on else ""))
    if once:
        run_once()
        return 0
    with _reload_lock:
        _reload_state["worker"] = True
    threading.Thread(target=_reload_worker, daemon=True).start()
    threading.Thread(target=resource_guard_loop, daemon=True).start()
    threading.Thread(target=experience_guard_loop, daemon=True).start()
    log("资源域哨兵已启动：每 %d 秒复核一次，坏钉立即换 / 每域至少 %d 个冗余 IP"
        % (max(15, RESOURCE_GUARD_SEC), RESOURCE_MIN_IPS))
    log("体验哨兵已启动：每 %d 秒按 101 自身 DNS 真实访问验收，"
        "连续 2 轮不可用主动自愈（%d 秒限频），结果写 health_status.json"
        % (max(20, EXPERIENCE_GUARD_SEC), EXPERIENCE_HEAL_SEC))
    log("重载合并已启用：%d 秒内多次变更只重启一次 mosdns" % RELOAD_MIN_SEC)
    while True:
        sec, on = runtime_cfg()
        if on:
            try:
                run_once()
            except Exception as e:
                log("异常：%s" % e)
        _doh_scan_async()
        image_guard_async()
        time.sleep(max(30, sec))


if __name__ == "__main__":
    sys.exit(main())
