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
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import https_probe          # noqa: E402
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
TIMEOUT = float(os.environ.get("PREF_WATCHDOG_TIMEOUT", "6"))
MAX_STRIKES = int(os.environ.get("PREF_WATCHDOG_STRIKES", "3"))
PORT = int(os.environ.get("PREF_WATCHDOG_PORT", "443"))
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")
GT_GUARD_STATE = os.path.join(DATA_DIR, "gt_guard_state.json")
GT_GUARD_FLAG = os.path.join(DATA_DIR, ".gt_need_refresh")
GT_CURL = "/usr/bin/curl" if os.path.exists("/usr/bin/curl") else "curl"
GT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
         "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")


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

HARD = ("cf", "cert", "wrong")   # 状态名以这些开头 = 明确不可用

# static.hosts 在 mosdns 的 hosts 插件里排在 all.hosts 前面、优先命中，
# 以前完全不在守护视野里：那里的 IP 坏了 101 发现不了。现在逐行纳入巡检。
STATIC_FILE = os.path.join(DATA_DIR, "static.hosts")
STATIC_STRIKES = int(os.environ.get("PREF_STATIC_STRIKES", "3"))
GT_MAIN_DOMAINS = ("translate.google.com", "translate.googleapis.com")
GT_STATIC_DEPS = ("translate.gstatic.com", "apis.google.com",
                  "csp.withgoogle.com", "fonts.googleapis.com")

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


def reload_mosdns():
    try:
        pid = int(open(PID_FILE).read().strip())
        os.kill(pid, signal.SIGTERM)
        log("已请求重载 mosdns（pid %d）" % pid)
        return True
    except Exception:
        return False


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


def _rebuild_all_hosts():
    """把各路 *.hosts 合并成 mosdns 实际读取的 all.hosts"""
    out = []
    try:
        for name in os.listdir(PREF_DIR):
            if not name.endswith(".hosts") or name == "all.hosts":
                continue
            for ln in open(os.path.join(PREF_DIR, name), encoding="utf-8", errors="replace"):
                p = ln.split()
                if len(p) >= 2 and RE_DOM.match(p[0]) and all(is_ip(x) for x in p[1:]):
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
    """该路的种子兜底 IP（镜像内置，无需联网）。"""
    out = []
    path = os.path.join(SEED_DIR, "%s.txt" % route)
    try:
        for ln in open(path, encoding="utf-8"):
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            tok = ln.split()[0]
            if tok.count(".") == 3 or ":" in tok:
                out.append(tok)
    except Exception:
        pass
    return out


def candidates(route, domain, skip):
    """补位候选：cfst 实测排序 > 订阅池 > 种子，去掉已在用的和已拉黑的。"""
    bad = subs._bad_set()
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
    for ip in subs.cmd_pool(route, 12, smart=True):
        if ip not in skip and ip not in bad and ip not in out:
            out.append(ip)
    for ip in seed_ips(route):
        if ip not in skip and ip not in bad and ip not in out:
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
    try:
        bad = subs._bad_set()
    except Exception:
        bad = set()
    new_ips, swapped = {}, 0
    for dom, ips in rows:
        keep, dropped = [], []
        for ip in ips:
            ok, st, _ms, _sp = results.get(("static", dom, ip),
                                           (False, "fail", None, None))
            key = "static|%s|%s" % (dom, ip)
            if ok and ip not in bad:
                state.pop(key, None)
                keep.append(ip)
                continue
            why = "blacklist" if ip in bad else st
            n = int((state.get(key) or {}).get("fails", 0)) + 1
            state[key] = {"fails": n, "ts": int(time.time()), "reason": why}
            if n >= STATIC_STRIKES:
                dropped.append((ip, why))
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
                if cr.get(("static", dom, c), (False,))[0] and c not in bad:
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
WD_CONC = int(os.environ.get("PREF_WD_CONC", "8"))
from concurrent.futures import ThreadPoolExecutor, as_completed  # noqa: E402


def health(ip, domain, route):
    """101 容器内按真实浏览器判据探一次。

    https_probe 对 <4KB 的响应不算速度、<32KB 的样本标 est=True（不可信），
    所以只拿可信样本判「慢到打不开」，不会误杀 API / 401 这类小页面。
    """
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


def heal_once():
    """全量巡检 + 精确补位（不含真翻自检与锁检查）。

    常驻守护 run_once() 与定时优选粘滞守卫共用同一套逻辑：
    健康的一律不动，只有连续失败的 IP 才撤下并从候选池实测补位。
    """
    state = jload(STATE_FILE, {})
    files = {}
    for name in sorted(os.listdir(PREF_DIR)):
        if not name.endswith(".hosts") or name == "all.hosts":
            continue
        route = name[:-6]
        rows = read_lines(os.path.join(PREF_DIR, name))
        if rows:
            # 所有路（含 gt）逐行全量巡检；gt 主域由 health() 内部改打真翻接口，
            # 附加域用各自 SNI，避免「只查第一行」漏掉整批在用 IP。
            files[route] = (rows, rows)

    items = [(route, dom, ip) for route, (_rows, scan) in files.items()
             for dom, ips in scan for ip in ips]
    # 静态钉子一起并发巡检：它在 hosts 插件里优先于 all.hosts，必须同样受守护。
    static_rows, static_items = static_targets()
    results = _batch_health(items + static_items)
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

    for route, (rows, scan) in files.items():
        new_rows = []
        for dom, ips in scan:
            keep, dropped = [], []
            for ip in ips:
                ok, st, ms, sp = results.get((route, dom, ip),
                                             (False, "fail", None, None))
                key = "%s|%s|%s" % (route, dom, ip)
                if ok:
                    state.pop(key, None)
                    state.pop("%s|%s" % (route, ip), None)
                    keep.append(ip)
                    continue
                if st.startswith(HARD) and route != "gt":
                    dropped.append((ip, st))
                    continue
                n = int((state.get(key) or {}).get("fails", 0)) + 1
                state[key] = {"fails": n, "ts": int(time.time()), "reason": st}
                if n >= MAX_STRIKES:
                    dropped.append((ip, st + "x%d" % n))
                else:
                    keep.append(ip)
            if not dropped:
                new_rows.append((dom, keep))
                continue
            for ip, why in dropped:
                subs.mark_bad(ip, why, route)
                state.pop("%s|%s|%s" % (route, dom, ip), None)
                log("%s 路：%s 的 %s 打不开（%s），已加入黑名单，%d 小时内不再用"
                    % (route, dom, ip, why_label(why), subs.BAD_TTL_H))
                subs.add_event("swap", route, ip, why, dom)
            dropped_all += [ip for ip, _ in dropped]
            need = max(0, len(ips) - len(keep))
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
                    elif st2.startswith(HARD):
                        subs.mark_bad(c, st2, route)
            final = keep + added
            new_rows.append((dom, final))
            swapped += len(dropped)
            changed = True
            if added:
                log("%s 路：%s 打不开，换成 %s（新 IP 已实测通过）"
                    % (route, dom, ",".join(added)))
            elif final:
                log("%s 路：%s 撤下打不开的，保留 %d 个仍可用"
                    % (route, dom, len(final)))
            else:
                log("%s 路：%s 全打不开、也没有可换的，已撤下这一行"
                    % (route, dom))
        if not new_rows:
            continue
        if new_rows != rows:
            write_hosts(route, new_rows[0][0], new_rows[0][1], new_rows[1:])
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


def run_once():
    """常驻守护入口：真翻自检 → 让出优选锁 → 全量巡检补位。"""
    gt_guard()
    if os.path.isdir(LOCK_DIR):
        log("优选任务正在跑，这轮巡检先跳过（避免两边同时改写 hosts 打架）")
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


def main():
    once = "--once" in sys.argv
    sec, on = runtime_cfg()
    log("启动：每 %d 秒把每路在用的 IP 各打开一次（单个超时 %.0fs），"
        "打不开（1034/证书/5xx/连不上）就换 IP；同一 IP 连续 %d 次不行才换%s"
        % (sec, TIMEOUT, MAX_STRIKES, "（当前巡检已关闭）" if not on else ""))
    if once:
        run_once()
        return 0
    while True:
        sec, on = runtime_cfg()
        if on:
            try:
                run_once()
            except Exception as e:
                log("异常：%s" % e)
        _doh_scan_async()
        time.sleep(max(30, sec))


if __name__ == "__main__":
    sys.exit(main())
