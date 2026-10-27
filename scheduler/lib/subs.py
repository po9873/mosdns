#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IP 源管理：源清单 + 定时拉取 + 候选池 + 坏 IP 黑名单 + 换 IP 事件。

模型（与 .101 一致）：
  * 每个源有独立的 v4 地址和 v6 地址，分别统计「段/个」和「展开后 IP 总数」
  * enabled 决定是否参与定时拉取与优选；勾选即可手动控制
  * 源订阅（subs）是一行一个「清单地址」，同步进来的是新源，默认不启用
  * 拉到的 IP 进候选池，按路（cf/google/...）存放，供优选直接取用

命令：
  init                     初始化（含内置源）
  status                   输出 JSON：源 / 池 / 黑名单 / 事件 / 定时配置
  save                     从 stdin 读 JSON 覆盖源配置（保存全部）
  add NAME V4URL [V6URL]   新增自定义源
  del KEY                  删除源
  enable KEY 0|1           启用 / 禁用
  test KEY                 只拉这个源，返回 v4/v6 数量并入池
  pull [--force]           拉取所有启用的源并入池
  pull-if-due              到点才拉（供调度器每轮调用）
  sync                     拉「源订阅」清单，把里面的新源同步进来（默认不启用）
  discover [--force]       扫描：把从没测过 / 上次失败的源挨个试一遍
  health [--force]         体检：所有源挨个拉一次，连续失败的第三方源直接删除
  gc                       立刻清理失效源（不等体检时间）
  restore [KEY...]         把删掉的内置源补回来
  pool ROUTE [N]           池内候选（已过滤黑名单）
  take ROUTE [N]           同 pool，已验证优先 + 新 IP 配额
  bump-many ROUTE          stdin: "IP ok|fail"
  mark-bad IP REASON [ROUTE]
  clear-bad IP
  bad / filter / prune / events
"""
import ipaddress
import json
import os
import re
import sys
import time
import urllib.request

DATA_DIR = os.environ.get("PREF_DATA_DIR", "/data")
SRC_FILE = os.path.join(DATA_DIR, "sources.json")
BLACK_FILE = os.path.join(DATA_DIR, "blacklist.json")
EVENT_FILE = os.path.join(DATA_DIR, "swap_events.json")
POOL_DIR = os.path.join(DATA_DIR, "pool")
ROUTES = ("cf", "google", "gt", "github", "ghcr")
UA = "mosdns-pref/1.0 (+sources)"
MAX_BYTES = 4 * 1024 * 1024


def _int(name, dft):
    try:
        return int(os.environ.get(name, dft))
    except Exception:
        return dft


BAD_TTL_H = _int("PREF_BAD_TTL_HOURS", 6)
POOL_MAX = _int("PREF_POOL_MAX", 4000)
SUB_TTL_DAYS = _int("PREF_SUB_TTL_DAYS", 14)
MAX_FAIL = _int("PREF_POOL_MAX_FAIL", 3)
CIDR_SAMPLE = _int("PREF_CIDR_SAMPLE", 6)

CYCLE_H = {"1h": 1, "2h": 2, "3h": 3, "4h": 4, "6h": 6, "8h": 8,
           "12h": 12, "daily": 24, "weekly": 168}

# ---------------------------------------------------------------- 内置源
# kind: official=厂商官方公布 / thirdparty=社区精选 / mirror=同一份数据的镜像
PRESETS = [
    {"key": "official-cf", "name": "Cloudflare 官方网段", "kind": "official",
     "note": "官方公布的 IPv4/IPv6 网段，最权威；只有网段，需采样展开",
     "url_v4": "https://www.cloudflare.com/ips-v4",
     "url_v6": "https://www.cloudflare.com/ips-v6", "enabled": True},
    {"key": "third-ipdb", "name": "IPDB 精选（社区）", "kind": "thirdparty",
     "note": "社区测速后维护的优选 IP，更新快、量小",
     "url_v4": "https://raw.githubusercontent.com/ymyuuu/IPDB/main/BestCF/bestcfv4.txt",
     "url_v6": "https://raw.githubusercontent.com/ymyuuu/IPDB/main/BestCF/bestcfv6.txt",
     "enabled": True},
    {"key": "third-ipdb-api", "name": "IPDB 接口（v4+v6）", "kind": "thirdparty",
     "note": "同一个数据源的接口形式，v4/v6 混在一起",
     "url_v4": "https://ipdb.api.030101.xyz/?type=bestcf&country=true",
     "url_v6": "", "enabled": True},
    {"key": "third-ipdb-proxy", "name": "IPDB 反代优选", "kind": "thirdparty",
     "note": "面向反向代理场景的优选地址",
     "url_v4": "https://raw.githubusercontent.com/ymyuuu/IPDB/main/BestProxy/bestproxy.txt",
     "url_v6": "", "enabled": True},
    {"key": "mirror-jsd", "name": "IPDB 镜像 · jsDelivr", "kind": "mirror",
     "note": "raw.githubusercontent 被墙时用这个",
     "url_v4": "https://cdn.jsdelivr.net/gh/ymyuuu/IPDB@main/BestCF/bestcfv4.txt",
     "url_v6": "https://cdn.jsdelivr.net/gh/ymyuuu/IPDB@main/BestCF/bestcfv6.txt",
     "enabled": False},
    {"key": "mirror-ghproxy", "name": "IPDB 镜像 · ghproxy", "kind": "mirror",
     "note": "国内可直连的 GitHub 加速前缀",
     "url_v4": "https://ghproxy.net/https://raw.githubusercontent.com/ymyuuu/IPDB/main/BestCF/bestcfv4.txt",
     "url_v6": "", "enabled": False},

    # ---- Google / GitHub 官方公布的 IP 段（供另外四路使用）----
    # 同一份数据被多路共用，所以按路各建一条，拉取互不影响
    {"key": "official-goog", "name": "Google 官方 IP 段（IPv4+IPv6）", "kind": "official",
     "note": "Google 公布的全部网段，搜索与翻译两路共用；只有网段，需采样展开",
     "route": "google", "url_v4": "https://www.gstatic.com/ipranges/goog.json",
     "url_v6": "https://www.gstatic.com/ipranges/goog.json", "enabled": True},
    {"key": "official-goog-gt", "name": "Google 官方 IP 段（翻译路）", "kind": "official",
     "note": "与搜索路同一份数据，翻译专用域名走这些段",
     "route": "gt", "url_v4": "https://www.gstatic.com/ipranges/goog.json",
     "url_v6": "https://www.gstatic.com/ipranges/goog.json", "enabled": True},
    {"key": "official-github", "name": "GitHub 官方 IP 段（IPv4+IPv6）", "kind": "official",
     "note": "GitHub 公布的全部网段，访问与 ghcr 两路共用",
     "route": "github", "url_v4": "https://api.github.com/meta",
     "url_v6": "https://api.github.com/meta", "enabled": True},
    {"key": "official-github-ghcr", "name": "GitHub 官方 IP 段（ghcr 路）", "kind": "official",
     "note": "与访问路同一份数据，镜像仓库专用域名走这些段",
     "route": "ghcr", "url_v4": "https://api.github.com/meta",
     "url_v6": "https://api.github.com/meta", "enabled": True},

    # ---- Google 网段的镜像 ----
    # 为什么需要：官方 goog.json 在 www.gstatic.com 上，本机常拉不到（实测 443 超时），
    # 那样 google/gt 两路就等于「没有源」，只能靠临时解析出的几个 IP。
    # 下面这份由 GitHub Actions 每天从官方 goog.json 转成纯文本，托管在 GitHub，
    # 国内可直连（raw.githubusercontent 可达），内容与官方一致（85 段 v4 / 15 段 v6）。
    {"key": "mirror-goog-list", "name": "Google 网段镜像 · GitHub（goog.json 转文本）", "kind": "mirror",
     "note": "官方 gstatic 拉不到时用这份：每日自动转换自官方 goog.json，含 142.250 等真实前端段",
     "route": "google",
     "url_v4": "https://raw.githubusercontent.com/RPDJF/google-ip-range/main/google-ip-range-ipv4.txt",
     "url_v6": "https://raw.githubusercontent.com/RPDJF/google-ip-range/main/google-ip-range-ipv6.txt",
     "enabled": True},
    {"key": "mirror-goog-list-gt", "name": "Google 网段镜像 · GitHub（翻译路）", "kind": "mirror",
     "note": "同一份镜像，翻译路单独一条，拉取互不影响",
     "route": "gt",
     "url_v4": "https://raw.githubusercontent.com/RPDJF/google-ip-range/main/google-ip-range-ipv4.txt",
     "url_v6": "https://raw.githubusercontent.com/RPDJF/google-ip-range/main/google-ip-range-ipv6.txt",
     "enabled": True},
    {"key": "mirror-goog-list-jsd", "name": "Google 网段镜像 · jsDelivr", "kind": "mirror",
     "note": "同上数据的 CDN 镜像，raw.githubusercontent 慢或被挡时打开这个",
     "route": "google",
     "url_v4": "https://cdn.jsdelivr.net/gh/RPDJF/google-ip-range@main/google-ip-range-ipv4.txt",
     "url_v6": "https://cdn.jsdelivr.net/gh/RPDJF/google-ip-range@main/google-ip-range-ipv6.txt",
     "enabled": False},

    # ---- Google 翻译：实测可用的翻译节点清单 ----
    # 为什么必须有这条：翻译服务在国内走的不是 142.250.x 那些官方网段，而是
    # 8.138.x / 113.31.x / 47.95.x 这类边缘节点（翻译入口就在这些地址上）。
    # goog.json 里根本没有这些地址，所以「拿官方网段采样再探」永远探不出翻译 IP——
    # 这才是之前翻译路一直选不出东西的真正原因，不是线路不通。
    # 清单来自社区工具 Ponderfly/GoogleTranslateIpCheck（大家常用的那个扫 IP 工具，
    # 每天实测后逐日提交，最近一次 2026-10-25）。它只提供候选，能不能用仍由本机
    # 实测决定：真发一次翻译请求，拿到译文才算数。
    {"key": "third-gtip", "name": "Google 翻译可用 IP 清单（Ponderfly 社区，每日更新）", "kind": "thirdparty",
     "note": "社区工具每天实测出的国内可用翻译节点（8.138 / 113.31 / 47.95 等），官方网段里没有这些地址",
     "route": "gt",
     "url_v4": "https://raw.githubusercontent.com/Ponderfly/GoogleTranslateIpCheck/master/src/GoogleTranslateIpCheck/GoogleTranslateIpCheck/ip.txt",
     "url_v6": "", "enabled": True},
    {"key": "third-gtip-jsd", "name": "Google 翻译可用 IP 清单 · jsDelivr 镜像", "kind": "mirror",
     "note": "同上数据的 CDN 镜像，raw.githubusercontent 打不开时打开这个",
     "route": "gt",
     "url_v4": "https://cdn.jsdelivr.net/gh/Ponderfly/GoogleTranslateIpCheck@master/src/GoogleTranslateIpCheck/GoogleTranslateIpCheck/ip.txt",
     "url_v6": "", "enabled": False},

    # ---- Google 搜索路：用的是同一批边缘节点 ----
    # 实测（本机直连、不走代理）：这批翻译节点对 www.google.com/search?q=... 同样
    # 返回 200 + 9 万字节的真实结果页（title 就是 Google Search），香港站也一样。
    # 也就是说「谷歌搜索在国内还有可用 IP」是真的，只是它们不在 Google 官方网段里，
    # 拿 goog.json 采样永远探不到。
    {"key": "third-gtip-google", "name": "Google 可用 IP 清单（搜索路，社区每日实测）", "kind": "thirdparty",
     "note": "与翻译路同一批边缘节点，实测搜 www.google.com 也能出结果页；只作候选，能不能用由本机实测决定",
     "route": "google",
     "url_v4": "https://raw.githubusercontent.com/Ponderfly/GoogleTranslateIpCheck/master/src/GoogleTranslateIpCheck/GoogleTranslateIpCheck/ip.txt",
     "url_v6": "", "enabled": True},

    # ---- GitHub 的社区 hosts 源（github / ghcr 两路）----
    # 为什么需要：这两路原来只有官方 api.github.com/meta 一条源。官方给的是 GitHub
    # 全量网段（含大量非前端段），采样展开后能连上的很少——实测一轮 60 个候选只选出
    # 1 个 IP，一个 IP 抖一下整路就没人可换。下面几份是社区每天维护的「当前可用前端
    # IP」，本身直接就是 IP+域名，比网段采样准；解析时只取其中的 IP，域名不参与。
    {"key": "third-gh520", "name": "GitHub520 社区 hosts（HelloGitHub）", "kind": "thirdparty",
     "note": "每天更新的 github.com / api / raw 可用前端 IP，含 140.82 / 20.205 等真实入口",
     "route": "github", "url_v4": "https://raw.hellogithub.com/hosts",
     "url_v6": "https://raw.hellogithub.com/hosts", "enabled": True},
    {"key": "third-ineo6", "name": "ineo6/hosts 社区 hosts（GitLab 直连）", "kind": "thirdparty",
     "note": "GitLab 托管的同类清单，与 GitHub520 互为备份，一份拉不到还有这份",
     "route": "github", "url_v4": "https://gitlab.com/ineo6/hosts/-/raw/master/next-hosts",
     "url_v6": "https://gitlab.com/ineo6/hosts/-/raw/master/next-hosts", "enabled": True},
    {"key": "third-gh520-ghcr", "name": "GitHub520 社区 hosts（ghcr 路）", "kind": "thirdparty",
     "note": "ghcr.io 与 github.com 同属 GitHub 前端段，这份清单能补到 20.27.x 这类入口",
     "route": "ghcr", "url_v4": "https://raw.hellogithub.com/hosts",
     "url_v6": "https://raw.hellogithub.com/hosts", "enabled": True},
    {"key": "mirror-gh520-jsd", "name": "GitHub520 镜像 · jsDelivr", "kind": "mirror",
     "note": "raw.hellogithub.com 拉不到时用这个 CDN 镜像（默认关，需要时在「源」页打开）",
     "route": "github",
     "url_v4": "https://cdn.jsdelivr.net/gh/521xueweihan/GitHub520@main/hosts",
     "url_v6": "https://cdn.jsdelivr.net/gh/521xueweihan/GitHub520@main/hosts", "enabled": False},
]

DEFAULT_PULL = {"enabled": True, "cycle": "6h", "hour": 4, "last": 0}
DEFAULT_DISC = {"enabled": False, "cycle": "daily", "hour": 4, "last": 0, "found": 0}
# 源体检：默认每天一次。官方源失败只标红，非官方源失败到阈值就删掉（默认第一次就删）
DEFAULT_HEALTH = {"enabled": True, "cycle": "daily", "hour": 5, "last": 0, "last_bad": 0}
# 失败几次就删：默认 1（一次拉不到就当它废了，界面不堆死源）；怕误删抖动的源可调到 2~3
AUTO_DISABLE_AFTER = _int("PREF_SRC_DISABLE_AFTER", 1)
# 失效源处理：1=直接删除（默认，界面上不留垃圾源），0=只停用、留在列表里等它恢复
AUTO_DELETE_BAD = _int("PREF_SRC_AUTO_DELETE", 1)

# ---------------------------------------------------------------- 读写
def jload(path, dft):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return dft


def jsave(path, obj):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)
    os.replace(tmp, path)


def load_src():
    d = jload(SRC_FILE, None)
    if not isinstance(d, dict):
        d = {}
    d.setdefault("items", [])
    d.setdefault("subs", [])
    d.setdefault("proxy", "")
    pull = d.get("pull") if isinstance(d.get("pull"), dict) else {}
    disc = d.get("discover") if isinstance(d.get("discover"), dict) else {}
    hl = d.get("health") if isinstance(d.get("health"), dict) else {}
    d["pull"] = {**DEFAULT_PULL, **pull}
    d["discover"] = {**DEFAULT_DISC, **disc}
    d["health"] = {**DEFAULT_HEALTH, **hl}
    return d


def save_src(d):
    jsave(SRC_FILE, d)


def auto_delete(d=None):
    """失效源是否直接删除：页面上的开关优先，没设置过就看环境变量。"""
    if isinstance(d, dict) and "auto_delete" in d:
        return bool(d["auto_delete"])
    return bool(AUTO_DELETE_BAD)


def pool_file(route):
    return os.path.join(POOL_DIR, "%s.json" % route)


def load_pool(route):
    d = jload(pool_file(route), None)
    if not isinstance(d, dict) or not isinstance(d.get("ips"), dict):
        d = {"ips": {}, "updated": 0}
    return d


def save_pool(route, d):
    d["updated"] = int(time.time())
    jsave(pool_file(route), d)


# ---------------------------------------------------------------- 黑名单
def load_bad():
    d = jload(BLACK_FILE, None)
    return d if isinstance(d, dict) else {}


def mark_bad(ip, reason, route="", replaced=""):
    d = load_bad()
    now = int(time.time())
    old = d.get(ip) or {}
    d[ip] = {"reason": reason, "ts": now, "until": now + BAD_TTL_H * 3600,
             "hits": int(old.get("hits", 0)) + 1, "route": route or old.get("route", "")}
    jsave(BLACK_FILE, d)
    add_event("drop", route, ip, reason, replaced)
    return d[ip]


def clear_bad(ip):
    d = load_bad()
    if ip in d:
        del d[ip]
        jsave(BLACK_FILE, d)


def purge_expired_bad():
    d = load_bad()
    now = time.time()
    gone = [k for k, v in d.items() if float(v.get("until", 0)) <= now]
    for k in gone:
        del d[k]
    if gone:
        jsave(BLACK_FILE, d)
    return gone


# ---------------------------------------------------------------- 事件
def add_event(kind, route, ip, reason, replaced=""):
    ev = jload(EVENT_FILE, {"events": []})
    if not isinstance(ev, dict):
        ev = {"events": []}
    ev.setdefault("events", [])
    ev["events"].insert(0, {"t": int(time.time()), "kind": kind, "route": route,
                            "ip": ip, "reason": reason, "to": replaced or ""})
    ev["events"] = ev["events"][:200]
    jsave(EVENT_FILE, ev)


# ---------------------------------------------------------------- 解析
def _public(ip):
    try:
        if ip.is_multicast or ip.is_loopback or ip.is_link_local:
            return False
        if ip.is_private or ip.is_reserved or ip.is_unspecified:
            return False
        return bool(ip.is_global)
    except Exception:
        return False


def expand_cidr(net, sample=None):
    """网段 -> 可探测 IP。小网段全展开，大网段固定步长采样（结果稳定）。"""
    sample = sample or CIDR_SAMPLE
    out = []
    try:
        n = net.num_addresses
    except Exception:
        return out
    if n <= 2:
        return out
    if n <= 256:
        allips = [str(a) for a in net]
        return allips[1:-1] if len(allips) > 2 else allips
    base = int(net.network_address)
    top = int(net.broadcast_address)
    step = max(1, n // max(1, sample))
    for i in range(sample):
        v = base + step * i + 1
        if v >= top:
            break
        try:
            ip = ipaddress.ip_address(v)
        except Exception:
            continue
        if _public(ip):
            out.append(str(ip))
    return out


SPLIT = re.compile(r"[\s,;|\"'<>()\[\]{}]+")


def parse_source(text):
    """解析一个源的内容。

    返回 dict：ips(实际入池候选) / v4(条目数) / v6(条目数) / v4_ips(地址总数) / v6_ips
    条目数用于「N 段/个」，地址总数用于「≈ X 万」。
    """
    ips, seen, nets = [], set(), set()
    n4 = n6 = t4 = t6 = 0
    s4 = s6 = 0                    # 网段条目数（「15 段」里的 15）
    if not text:
        return {"ips": [], "v4": 0, "v6": 0, "v4_ips": 0, "v6_ips": 0,
                "s4": 0, "s6": 0}

    raw = text
    # 整段 base64 的订阅（v2ray 风格）
    head = raw.strip()[:200]
    if head and not re.search(r"[\.:]\s*\d", head) and len(raw.strip()) > 60:
        try:
            import base64
            dec = base64.b64decode(raw.strip() + "=" * (-len(raw.strip()) % 4),
                                   validate=False).decode("utf-8", "ignore")
            if re.search(r"\d+\.\d+\.\d+\.\d+", dec):
                raw = dec
        except Exception:
            pass

    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        line = line.split("#", 1)[0]
        for tok in SPLIT.split(line):
            tok = tok.strip().strip(".")
            if not tok:
                continue
            if "/" in tok:
                try:
                    net = ipaddress.ip_network(tok, strict=False)
                except ValueError:
                    continue
                if str(net) in nets:
                    continue
                nets.add(str(net))
                n = net.num_addresses
                if net.version == 4:
                    n4 += 1
                    t4 += n
                    s4 += 1
                else:
                    n6 += 1
                    t6 += n
                    s6 += 1
                for c in expand_cidr(net):
                    if c not in seen:
                        seen.add(c)
                        ips.append(c)
                if len(ips) > POOL_MAX:
                    return {"ips": ips[:POOL_MAX], "v4": n4, "v6": n6,
                            "v4_ips": t4, "v6_ips": t6, "s4": s4, "s6": s6}
                continue
            cands = [tok]
            if tok.count(":") == 1:
                cands = [tok.split(":", 1)[0]]
            elif tok.startswith("[") and "]" in tok:
                cands = [tok.split("]", 1)[0].lstrip("[")]
            for c in cands:
                if c in seen:
                    continue
                try:
                    ip = ipaddress.ip_address(c)
                except ValueError:
                    continue
                if not _public(ip):
                    continue
                seen.add(c)
                ips.append(c)
                if ip.version == 4:
                    n4 += 1
                    t4 += 1
                else:
                    n6 += 1
                    t6 += 1
    return {"ips": ips, "v4": n4, "v6": n6, "v4_ips": t4, "v6_ips": t6,
            "s4": s4, "s6": s6}


# ---------------------------------------------------------------- 抓取
def _get(url, proxy="", timeout=20):
    u = url.strip()
    if proxy and "raw.githubusercontent.com" in u and "http" in u:
        u = proxy.rstrip("/") + "/" + u
    last = None
    for attempt in range(2):          # raw.githubusercontent 偶发断连，重试一次
        try:
            req = urllib.request.Request(u, headers={"User-Agent": UA,
                                                     "Accept": "text/plain,*/*"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = r.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise ValueError("内容超过 4MB，已拒绝")
            for enc in ("utf-8-sig", "utf-8", "gbk"):
                try:
                    return data.decode(enc)
                except Exception:
                    continue
            return data.decode("utf-8", "ignore")
        except Exception as e:
            last = e
            time.sleep(1)
    raise last


def fetch_item(it, proxy="", merge=True):
    """拉一个源的 v4/v6 两个地址，返回统计；merge=True 时并入对应路的池。"""
    now = int(time.time())
    v4 = v6 = 0
    t4 = t6 = 0
    s4 = s6 = 0
    all_ips = []
    errs = []
    # 两个地址都拉，按 IP 实际版本归类（v4 地址里混了 v6 也不会数错）
    # v4/v6 填了同一个地址（如 goog.json、GitHub meta 这种混合源）时只拉一次，
    # 否则同一份数据会被重复计数，段数翻倍
    urls = [(it.get("url_v4"), "v4")]
    if it.get("url_v6") and it.get("url_v6") != it.get("url_v4"):
        urls.append((it.get("url_v6"), "v6"))
    for url, label in urls:
        if not url:
            continue
        try:
            st = parse_source(_get(url, proxy))
            all_ips.extend(st["ips"])
            v4 += st["v4"]
            v6 += st["v6"]
            t4 += st["v4_ips"]
            t6 += st["v6_ips"]
            s4 += st["s4"]
            s6 += st["s6"]
        except Exception as e:
            errs.append("%s: %s" % (label, str(e)[:70]))

    if not all_ips and errs:
        it["status"] = "失败：" + errs[0]
        it["last_fetch"] = now
        return {"ok": False, "errors": errs}

    # 去重
    uniq, seen = [], set()
    for ip in all_ips:
        if ip not in seen:
            seen.add(ip)
            uniq.append(ip)

    if merge:
        route = it.get("route") or "cf"
        if route not in ROUTES:
            route = "cf"
        pool = load_pool(route)
        bucket = pool["ips"]
        added = 0
        for ip in uniq:
            if ip in bucket:
                bucket[ip]["a"] = now
                bucket[ip]["s"] = it.get("key", "")
            else:
                if len(bucket) >= POOL_MAX:
                    continue
                bucket[ip] = {"s": it.get("key", ""), "a": now, "ok": 0, "fl": 0, "lo": 0}
                added += 1
        save_pool(route, pool)
    else:
        added = 0

    it["last_test"] = {"v4": v4, "v6": v6, "v4_ips": t4, "v6_ips": t6,
                       "s4": s4, "s6": s6, "ts": now}
    it["last_fetch"] = now
    it["status"] = "成功" if not errs else "部分失败：" + errs[0]
    return {"ok": True, "v4": v4, "v6": v6, "v4_ips": t4, "v6_ips": t6,
            "s4": s4, "s6": s6, "ips": len(uniq), "added": added, "errors": errs}


# ---------------------------------------------------------------- 定时
def _due(cfg, last, now=None):
    if not cfg.get("enabled"):
        return False
    now = now or time.time()
    if not last:
        return True
    cyc = CYCLE_H.get(cfg.get("cycle", "6h"), 6)
    if cyc >= 24:
        if time.localtime(now).tm_hour < int(cfg.get("hour", 4)):
            return False
        return now - last >= cyc * 3600 - 3600
    return now - last >= cyc * 3600


def _next_ts(cfg, last, now=None):
    if not cfg.get("enabled"):
        return 0
    now = now or time.time()
    cyc = CYCLE_H.get(cfg.get("cycle", "6h"), 6)
    if not last:
        return int(now)
    if cyc >= 24:
        t = time.localtime(last + cyc * 3600 - 3600)
        return int(time.mktime((t.tm_year, t.tm_mon, t.tm_mday,
                                int(cfg.get("hour", 4)), 0, 0, 0, 0, -1)))
    return int(last + cyc * 3600)


# ---------------------------------------------------------------- 源操作
def cmd_add(name, u4, u6=""):
    if not (u4 or u6):
        return {"ok": False, "error": "至少填一个 v4 或 v6 地址"}
    for u in (u4, u6):
        if u and not re.match(r"^https?://", u, re.I):
            return {"ok": False, "error": "地址必须以 http:// 或 https:// 开头"}
    d = load_src()
    for it in d["items"]:
        if u4 and it.get("url_v4") == u4:
            return {"ok": False, "error": "这个 v4 地址已经存在", "key": it.get("key")}
    key = "custom-%d" % int(time.time() * 1000)
    d["items"].append({"key": key, "name": name or "自定义源", "note": "手动添加",
                       "kind": "custom", "url_v4": u4, "url_v6": u6,
                       "enabled": True, "route": "cf", "status": "",
                       "last_fetch": 0, "last_test": None})
    save_src(d)
    return {"ok": True, "key": key}


def _purge_pool_src(keys):
    """源没了，把它带进池子、但还没验证通过的 IP 一起清掉。

    已验证过（ok>0）的 IP 留着——它在实测里是通的，源挂了 IP 照样能用。
    """
    if not keys:
        return 0
    n = 0
    for rt in ROUTES:
        pool = load_pool(rt)
        b = pool["ips"]
        gone = [ip for ip, v in b.items()
                if str(v.get("s", "")) in keys and int(v.get("ok", 0)) == 0]
        for ip in gone:
            b.pop(ip, None)
        if gone:
            save_pool(rt, pool)
            n += len(gone)
    return n


def _drop_sources(d, keys, why):
    """从源清单里移除若干源，记进 deleted 历史（可查、可一键恢复内置源）。"""
    keys = {k for k in keys if k}
    if not keys:
        return 0
    gone = [it for it in d["items"] if it.get("key") in keys]
    if not gone:
        return 0
    d["items"] = [it for it in d["items"] if it.get("key") not in keys]
    now = int(time.time())
    hist = d.get("deleted")
    if not isinstance(hist, list):
        hist = []
    for it in gone:
        hist.insert(0, {"key": it.get("key"), "name": it.get("name"),
                        "kind": it.get("kind"), "route": it.get("route", "cf"),
                        "url_v4": it.get("url_v4", ""), "url_v6": it.get("url_v6", ""),
                        "ts": now, "why": why})
    d["deleted"] = hist[:40]
    return len(gone)


def cmd_gc():
    """清理失效源：把此刻体检失败的非官方源立刻处理（含已停用的）。

    「立即清理失效源」是用户主动点的，代表现在就要清干净，所以不看失败次数，
    只要最近一次体检没过就处理。体检自动处理那条走的是失败次数阈值。
    开关「失效自动删除」开着就删掉，关掉就只停用。
    """
    d = load_src()
    adv = auto_delete(d)
    keys, stopped = [], 0
    for it in d["items"]:
        if it.get("kind") == "official":
            continue
        h = it.get("health") or {}
        if not h.get("ts") or h.get("ok", True):
            continue
        if adv:
            keys.append(it.get("key"))
        elif it.get("enabled", True):
            it["enabled"] = False
            h["auto_disabled"] = int(time.time())
            stopped += 1
    n = _drop_sources(d, keys, "体检失败")
    save_src(d)
    return {"ok": True, "removed": n, "stopped": stopped, "keys": keys,
            "purged": _purge_pool_src(set(keys))}


def cmd_restore(keys=None):
    """把被删掉的内置源补回来（第三方/镜像也能找回，官方源一定补）。"""
    d = load_src()
    have = {it.get("key") for it in d["items"]}
    want = {k for k in (keys or []) if k}
    added = []
    for p in PRESETS:
        if p["key"] in have:
            continue
        if want and p["key"] not in want:
            continue
        d["items"].append({
            "key": p["key"], "name": p["name"], "note": p.get("note", ""),
            "kind": p["kind"], "url_v4": p["url_v4"], "url_v6": p["url_v6"],
            "enabled": p.get("enabled", True), "route": p.get("route", "cf"),
            "last_fetch": 0, "last_test": None, "status": "",
        })
        added.append(p["key"])
    if added:
        hist = [h for h in (d.get("deleted") or []) if h.get("key") not in set(added)]
        d["deleted"] = hist
        save_src(d)
    return {"ok": True, "added": added}


def cmd_del(key):
    d = load_src()
    n = len(d["items"])
    d["items"] = [it for it in d["items"] if it.get("key") != key]
    if len(d["items"]) == n:
        return {"ok": False, "error": "源不存在"}
    save_src(d)
    return {"ok": True, "purged": _purge_pool_src({key})}


def cmd_enable(key, on):
    d = load_src()
    for it in d["items"]:
        if it.get("key") == key:
            it["enabled"] = bool(on)
            save_src(d)
            return {"ok": True}
    return {"ok": False, "error": "源不存在"}


def cmd_save(payload):
    """保存全部：覆盖 items / subs / proxy / 定时配置（保留未提交的 last_test）。"""
    d = load_src()
    old = {it.get("key"): it for it in d["items"]}
    # 页面加载之后被系统自动删掉的源，别被浏览器里的旧列表又写回来
    since = int(payload.get("since") or 0)
    dead = {h.get("key") for h in (d.get("deleted") or [])
            if int(h.get("ts", 0)) > since}
    items = []
    # 只提交定时设置（不带 items）时不要动源清单，否则会被清空
    if "items" in payload:
        for it in (payload.get("items") or []):
            key = it.get("key") or ("custom-%d" % int(time.time() * 1000))
            if key in dead:
                continue
            prev = old.get(key, {})
            items.append({
                "key": key,
                "name": it.get("name") or prev.get("name") or "未命名",
                "note": it.get("note", prev.get("note", "")),
                "kind": it.get("kind") or prev.get("kind") or "custom",
                "url_v4": it.get("url_v4", ""),
                "url_v6": it.get("url_v6", ""),
                "enabled": bool(it.get("enabled", True)),
                "route": it.get("route") or prev.get("route") or "cf",
                "from_sub": it.get("from_sub") or prev.get("from_sub", ""),
                "last_test": it.get("last_test") or prev.get("last_test"),
                "last_fetch": prev.get("last_fetch", 0),
                "status": prev.get("status", ""),
                # 体检记录必须跟着源走，否则每保存一次就丢一次体检结果
                "health": it.get("health") or prev.get("health"),
            })
        d["items"] = items
    if "subs" in payload:
        d["subs"] = [s.strip() for s in (payload.get("subs") or []) if str(s).strip()]
    if "proxy" in payload:
        d["proxy"] = (payload.get("proxy") or "").strip()
    if isinstance(payload.get("pull"), dict):
        d["pull"] = {**d["pull"], **payload["pull"]}
    if isinstance(payload.get("discover"), dict):
        d["discover"] = {**d["discover"], **payload["discover"]}
    if isinstance(payload.get("health"), dict):
        d["health"] = {**d["health"], **payload["health"]}
    if "auto_delete" in payload:
        d["auto_delete"] = bool(payload["auto_delete"])
    save_src(d)
    return {"ok": True, "items": len(d["items"])}


def cmd_test(key):
    d = load_src()
    for it in d["items"]:
        if it.get("key") == key:
            r = fetch_item(it, d.get("proxy", ""), merge=True)
            save_src(d)
            return r
    return {"ok": False, "errors": ["源不存在"]}


def cmd_pull(force=False, only=None):
    d = load_src()
    now = int(time.time())
    if not force and not _due(d["pull"], d["pull"].get("last", 0), now):
        return {"ok": True, "skipped": True, "reason": "未到拉取时间",
                "next": _next_ts(d["pull"], d["pull"].get("last", 0), now)}
    results = []
    okn = 0
    for it in d["items"]:
        if only and it.get("key") != only:
            continue
        if not it.get("enabled", True):
            continue
        r = fetch_item(it, d.get("proxy", ""), merge=True)
        r["key"] = it.get("key")
        r["name"] = it.get("name")
        results.append(r)
        if r.get("ok"):
            okn += 1
    d["pull"]["last"] = now
    save_src(d)
    return {"ok": True, "sources": len(results), "succeeded": okn,
            "results": results, "next": _next_ts(d["pull"], now, now)}


def _parse_sublist(text):
    """源订阅清单：JSON 数组 / 文本行「名称 | v4 | v6」/ 裸地址。"""
    out = []
    t = (text or "").strip()
    if not t:
        return out
    if t.startswith("[") or t.startswith("{"):
        try:
            data = json.loads(t)
        except Exception:
            data = None
        if isinstance(data, dict):
            data = data.get("sources") or data.get("items") or []
        if isinstance(data, list):
            for e in data:
                if isinstance(e, str):
                    out.append({"name": "", "url_v4": e, "url_v6": ""})
                elif isinstance(e, dict):
                    out.append({
                        "name": e.get("name", ""),
                        "url_v4": e.get("url_v4") or e.get("url") or "",
                        "url_v6": e.get("url_v6") or "",
                    })
            return out
    for line in t.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) == 1:
            out.append({"name": "", "url_v4": parts[0], "url_v6": ""})
        elif len(parts) == 2:
            out.append({"name": "", "url_v4": parts[0], "url_v6": parts[1]})
        else:
            out.append({"name": parts[0], "url_v4": parts[1], "url_v6": parts[2]})
    return out


def cmd_sync():
    d = load_src()
    have = set()
    for it in d["items"]:
        for u in (it.get("url_v4"), it.get("url_v6")):
            if u:
                have.add(u)
    added = updated = 0
    errors = {}
    for sub in d.get("subs", []):
        try:
            entries = _parse_sublist(_get(sub, d.get("proxy", "")))
        except Exception as e:
            errors[sub] = str(e)[:80]
            continue
        for e in entries:
            u4, u6 = (e.get("url_v4") or "").strip(), (e.get("url_v6") or "").strip()
            if not u4 and not u6:
                continue
            if u4 in have or (u6 and u6 in have):
                updated += 1
                continue
            key = "sub-%d" % int(time.time() * 1000 + added)
            d["items"].append({
                "key": key, "name": e.get("name") or ("来自订阅 %d" % (added + 1)),
                "note": "源订阅同步", "kind": "thirdparty",
                "url_v4": u4, "url_v6": u6,
                "enabled": False,          # 与 .101 一致：同步进来默认不启用
                "route": "cf", "from_sub": sub,
                "last_fetch": 0, "last_test": None, "status": "",
            })
            if u4:
                have.add(u4)
            if u6:
                have.add(u6)
            added += 1
    d["discover"]["last"] = int(time.time())
    d["discover"]["found"] = added
    save_src(d)
    return {"ok": True, "added": added, "updated": updated, "errors": errors}


def cmd_health(force=False, only=None):
    """定时体检：把所有源（含已停用的第三方源）挨个拉一次，只看能不能用，不写池。

    和 discover 的区别：
      discover = 找「还没测过 / 上次失败」的源，目的是把新源纳进来
      health   = 定期复检「所有」源，包括一直正常的，目的是及时发现挂掉的源

    官方源（kind=official）失败只标记不改状态——它是权威定义，可能只是临时断网；
    第三方/镜像源连续失败 AUTO_DISABLE_AFTER 次：默认直接删掉（不留废源），
    把 PREF_SRC_AUTO_DELETE 设为 0 则只停用保留。
    """
    d = load_src()
    now = int(time.time())
    if not force and not _due(d["health"], d["health"].get("last", 0), now):
        return {"ok": True, "skipped": True, "reason": "未到体检时间",
                "next": _next_ts(d["health"], d["health"].get("last", 0), now)}

    checked = good = bad = disabled = 0
    results = []
    drop = {}
    adv = auto_delete(d)
    for it in d["items"]:
        if only and it.get("key") != only:
            continue
        lt = it.get("last_test") or {}
        # 已经能正常拉到 IP 的，说明当前就是通的，跳过省流量
        alive = lt.get("v4", 0) + lt.get("v6", 0) > 0 and not str(it.get("status", "")).startswith("失败")
        r = fetch_item(it, d.get("proxy", ""), merge=False)
        checked += 1
        h = it.setdefault("health", {"fails": 0, "ts": 0, "ok": True})
        h["ts"] = now
        if r.get("ok"):
            good += 1
            h["fails"] = 0
            h["ok"] = True
            h.pop("auto_disabled", None)
        else:
            bad += 1
            h["fails"] = int(h.get("fails", 0)) + 1
            h["ok"] = False
            h["error"] = (r.get("errors") or [""])[0][:100]
            # 非官方源连续失败到阈值：默认删除，避免列表里堆一堆死源
            if it.get("kind") != "official" and h["fails"] >= AUTO_DISABLE_AFTER:
                del_it = adv or not it.get("enabled", True)
                if del_it:
                    h["auto_disabled"] = now
                    drop[it.get("key")] = {
                        "key": it.get("key"), "name": it.get("name"),
                        "kind": it.get("kind"), "route": it.get("route", "cf"),
                        "url_v4": it.get("url_v4", ""), "url_v6": it.get("url_v6", ""),
                        "ts": now, "why": "拉取失败 ×%d" % h["fails"],
                    }
                    disabled += 1
                elif it.get("enabled", True):
                    it["enabled"] = False
                    h["auto_disabled"] = now
                    disabled += 1
        results.append({
            "key": it.get("key"), "name": it.get("name"),
            "kind": it.get("kind"), "ok": bool(r.get("ok")),
            "v4": r.get("v4", 0), "v6": r.get("v6", 0),
            "fails": h["fails"], "was_alive": alive,
            "disabled": not it.get("enabled", True),
            "deleted": it.get("key") in drop,
            "error": h.get("error", "") if not r.get("ok") else "",
        })

    removed = 0
    if drop:
        removed = _drop_sources(d, set(drop), "拉取失败")
    d["health"]["last"] = now
    d["health"]["last_bad"] = bad
    save_src(d)
    purged = _purge_pool_src(set(drop)) if drop else 0
    return {"ok": True, "checked": checked, "good": good, "bad": bad,
            "auto_disabled": disabled, "removed": removed, "purged": purged,
            "results": results,
            "next": _next_ts(d["health"], now, now)}


def cmd_discover(force=False):
    """扫描：把没测过或上次失败的源挨个试一遍，能拉到 IP 的记为可用。"""
    d = load_src()
    now = int(time.time())
    if not force and not _due(d["discover"], d["discover"].get("last", 0), now):
        return {"ok": True, "skipped": True, "reason": "未到扫描时间"}
    checked = 0
    good = 0
    results = []
    for it in d["items"]:
        lt = it.get("last_test")
        if lt and lt.get("v4", 0) + lt.get("v6", 0) > 0 and not str(it.get("status", "")).startswith("失败"):
            continue
        r = fetch_item(it, d.get("proxy", ""), merge=bool(it.get("enabled")))
        checked += 1
        if r.get("ok"):
            good += 1
        results.append({"key": it.get("key"), "name": it.get("name"),
                        "ok": bool(r.get("ok")), "v4": r.get("v4", 0),
                        "v6": r.get("v6", 0),
                        "error": (r.get("errors") or [""])[0]})
    d["discover"]["last"] = now
    d["discover"]["found"] = good
    save_src(d)
    return {"ok": True, "checked": checked, "good": good, "results": results}


# ---------------------------------------------------------------- 池
def _bad_set():
    now = time.time()
    return {k for k, v in load_bad().items() if float(v.get("until", 0)) > now}


def cmd_pool(route, n=120, smart=False):
    n = max(1, min(1000, int(n)))
    bad = _bad_set()
    pool = load_pool(route)["ips"]
    items = [(ip, v) for ip, v in pool.items() if ip not in bad]
    if not smart:
        items.sort(key=lambda kv: (-int(kv[1].get("lo", 0)), int(kv[1].get("fl", 0))))
        return [ip for ip, _ in items[:n]]

    fresh = [kv for kv in items if int(kv[1].get("ok", 0)) == 0 and int(kv[1].get("fl", 0)) == 0]
    ids = {ip for ip, _ in fresh}
    known = [kv for kv in items if kv[0] not in ids]
    fresh.sort(key=lambda kv: -int(kv[1].get("a", 0)))
    known.sort(key=lambda kv: (int(kv[1].get("fl", 0)), -int(kv[1].get("lo", 0))))

    q = max(1, n // 3)
    pick = [ip for ip, _ in fresh[:q]]
    for ip, _ in known:
        if len(pick) >= n:
            break
        pick.append(ip)
    for ip, _ in fresh[q:]:
        if len(pick) >= n:
            break
        pick.append(ip)
    return pick[:n]


def cmd_feed(route, entries, cap=None):
    """把非订阅来源的候选也灌进池子：DNS 实时解析、种子、通过校验的 IP。

    entries: [(ip, 来源)]，来源 = dns / seed / verify
    这样 Google / 翻译 / GitHub / ghcr 这些没有公开订阅源的路线，池子里也有真实数据。
    """
    cap = int(cap or POOL_MAX)
    bad = _bad_set()
    pool = load_pool(route)
    b = pool["ips"]
    now = int(time.time())
    added = seen = skipped = 0
    for ip, src in entries:
        ip = (ip or "").strip()
        if not ip or ip in bad:
            skipped += 1
            continue
        try:
            obj = ipaddress.ip_address(ip)
        except ValueError:
            skipped += 1
            continue
        if not _public(obj):
            skipped += 1
            continue
        cur = b.get(ip)
        if cur:
            cur["a"] = now
            if src == "verify":
                cur["ok"] = int(cur.get("ok", 0)) + 1
            cur.setdefault("src", src)
            seen += 1
        else:
            if len(b) >= cap:
                skipped += 1
                continue
            b[ip] = {"s": "feed:" + src, "a": now, "ok": 0, "fl": 0, "lo": 0,
                     "src": src}
            added += 1
    save_pool(route, pool)
    return {"route": route, "added": added, "seen": seen,
            "skipped": skipped, "pool": len(b)}


def cmd_bump(route, ip, result):
    pool = load_pool(route)
    b = pool["ips"].get(ip)
    if not b:
        return {"ok": False}
    if result == "ok":
        b["ok"] = int(b.get("ok", 0)) + 1
        b["lo"] = int(time.time())
        b["fl"] = 0
    else:
        b["fl"] = int(b.get("fl", 0)) + 1
    save_pool(route, pool)
    return {"ok": True, "fl": b["fl"], "okn": b["ok"]}


def cmd_prune(route=""):
    now = int(time.time())
    bad = _bad_set()
    routes = [route] if route in ROUTES else list(ROUTES)
    report = []
    for rt in routes:
        pool = load_pool(rt)
        bucket = pool["ips"]
        before = len(bucket)
        kills = []
        for ip, v in bucket.items():
            if ip in bad:
                kills.append((ip, "blacklist"))
            elif int(v.get("fl", 0)) >= MAX_FAIL and int(v.get("ok", 0)) == 0:
                kills.append((ip, "unreachable"))
            elif now - int(v.get("a", 0)) > SUB_TTL_DAYS * 86400:
                kills.append((ip, "stale"))
        for ip, _ in kills:
            bucket.pop(ip, None)
        if len(bucket) > POOL_MAX:
            rank = sorted(bucket.items(),
                          key=lambda kv: (-int(kv[1].get("ok", 0)),
                                          int(kv[1].get("fl", 0)),
                                          -int(kv[1].get("lo", 0))))
            keep = dict(rank[:POOL_MAX])
            bucket.clear()
            bucket.update(keep)
        save_pool(rt, pool)
        if before != len(bucket):
            tally = {}
            for _, r in kills:
                tally[r] = tally.get(r, 0) + 1
            report.append({"route": rt, "before": before, "after": len(bucket),
                           "removed": len(kills), "reasons": tally})
    return {"ok": True, "report": report, "expired_bad": len(purge_expired_bad())}


SRC_LABEL = {"sub": "订阅", "dns": "解析", "seed": "种子"}
FEED_LABEL = {"dns": "DNS 实时解析", "seed": "种子 / 兜底地址", "verify": "优选验证通过"}


def _src_split(ips):
    """按来源统计池内 IP 数量。"""
    out = {}
    for ip, v in ips.items():
        s0 = str(v.get("src") or "")
        if not s0:
            s0 = "sub" if not str(v.get("s", "")).startswith("feed:") else \
                str(v.get("s", ""))[5:]
        key = s0 if s0 in SRC_LABEL else "sub"
        out[key] = out.get(key, 0) + 1
    return out


def _src_detail(ips, items, deleted=None):
    """按具体源名统计池内 IP：这一池子的数到底是哪几个源给的。

    池里每条 IP 的 s = 源 key（订阅源），或 feed:dns / feed:seed（非订阅来源）。
    源被删掉后它的 IP 会短暂指向已不存在的 key，这里标成 gone（前端标红），
    名字从删除历史里找回来，显示成「原名（已删除）」。
    """
    by_key = {it.get("key"): it for it in items}
    hist = {h.get("key"): h for h in (deleted or [])}
    tally = {}
    for v in ips.values():
        s = str(v.get("s") or "")
        if s.startswith("feed:"):
            k = s[5:]
        elif s:
            k = s
        else:
            k = "unknown"
        tally[k] = tally.get(k, 0) + 1
    rows = []
    for k, n in tally.items():
        it = by_key.get(k)
        if it:
            rows.append({"key": k, "name": it.get("name") or k,
                         "kind": it.get("kind") or "custom", "n": n, "gone": False})
        elif k in FEED_LABEL:
            rows.append({"key": k, "name": FEED_LABEL[k], "kind": "feed",
                         "n": n, "gone": False})
        else:
            h = hist.get(k) or {}
            nm = h.get("name") or k
            rows.append({"key": k, "name": "%s（已删除）" % nm, "kind": "gone",
                         "n": n, "gone": True})
    rows.sort(key=lambda r: (-r["n"], r["name"]))
    return rows


def cmd_status():
    now = int(time.time())
    d = load_src()
    bad = load_bad()
    active = {k: v for k, v in bad.items() if float(v.get("until", 0)) > now}
    pools = {}
    for rt in ROUTES:
        p = load_pool(rt)
        ips = p["ips"]
        pools[rt] = {
            "total": len(ips),
            "verified": sum(1 for v in ips.values() if int(v.get("ok", 0)) > 0),
            "fresh": sum(1 for v in ips.values()
                         if int(v.get("ok", 0)) == 0 and int(v.get("fl", 0)) == 0),
            "blocked": sum(1 for k in ips if k in active),
            "v4": sum(1 for k in ips if ":" not in k),
            "v6": sum(1 for k in ips if ":" in k),
            "updated": p.get("updated", 0),
            # 来源拆分：订阅(sub) / DNS 实时解析(dns) / 种子(seed)
            # 让用户看得清「这个池子的数是从哪来的」
            "by_src": _src_split(ips),
            # 再细一层：具体哪个源给了多少（用户要看「到底是什么源」）
            "by_source": _src_detail(ips, d["items"], d.get("deleted")),
        }
    ev = jload(EVENT_FILE, {"events": []})
    return {
        "items": d["items"],
        "subs": d.get("subs", []),
        "proxy": d.get("proxy", ""),
        "pull": {**d["pull"], "next": _next_ts(d["pull"], d["pull"].get("last", 0), now)},
        "discover": {**d["discover"], "next": _next_ts(d["discover"], d["discover"].get("last", 0), now)},
        "health": {**d["health"], "next": _next_ts(d["health"], d["health"].get("last", 0), now)},
        "auto_disable_after": AUTO_DISABLE_AFTER,
        "auto_delete": auto_delete(d),
        "deleted": (d.get("deleted") or [])[:20],
        "pools": pools,
        "bad": [{"ip": k, **v} for k, v in sorted(active.items(),
                                                  key=lambda kv: -int(kv[1].get("ts", 0)))],
        "events": (ev.get("events") or [])[:60],
        "bad_ttl_hours": BAD_TTL_H,
        "pool_max": POOL_MAX,
    }


# ---------------------------------------------------------------- main
def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    cmd = sys.argv[1]
    a = sys.argv[2:]

    if cmd == "init":
        os.makedirs(POOL_DIR, exist_ok=True)
        if not os.path.exists(BLACK_FILE):
            jsave(BLACK_FILE, {})
        if not os.path.exists(EVENT_FILE):
            jsave(EVENT_FILE, {"events": []})
        d = load_src()
        have = {it.get("key") for it in d["items"]}
        for p in PRESETS:
            if p["key"] in have:
                continue
            d["items"].append({
                "key": p["key"], "name": p["name"], "note": p.get("note", ""),
                "kind": p["kind"], "url_v4": p["url_v4"], "url_v6": p["url_v6"],
                "enabled": p.get("enabled", True), "route": p.get("route", "cf"),
                "last_fetch": 0, "last_test": None, "status": "",
            })
        save_src(d)
        return 0

    if cmd == "status":
        print(json.dumps(cmd_status(), ensure_ascii=False))
        return 0

    if cmd == "save":
        try:
            payload = json.load(sys.stdin)
        except Exception as e:
            print(json.dumps({"ok": False, "error": "JSON 解析失败: %s" % e}))
            return 1
        print(json.dumps(cmd_save(payload), ensure_ascii=False))
        return 0

    if cmd == "add":
        if len(a) < 2:
            print(json.dumps({"ok": False, "error": "用法: add NAME V4URL [V6URL]"}))
            return 1
        print(json.dumps(cmd_add(a[0], a[1], a[2] if len(a) > 2 else ""), ensure_ascii=False))
        return 0

    if cmd == "del":
        print(json.dumps(cmd_del(a[0]) if a else {"ok": False}, ensure_ascii=False))
        return 0

    if cmd == "gc":
        print(json.dumps(cmd_gc(), ensure_ascii=False))
        return 0

    if cmd == "restore":
        print(json.dumps(cmd_restore(a), ensure_ascii=False))
        return 0

    if cmd == "enable":
        print(json.dumps(cmd_enable(a[0], a[1] not in ("0", "false", "off"))
                         if len(a) > 1 else {"ok": False}, ensure_ascii=False))
        return 0

    if cmd == "test":
        print(json.dumps(cmd_test(a[0]) if a else {"ok": False}, ensure_ascii=False))
        return 0

    if cmd in ("pull", "pull-if-due"):
        force = (cmd == "pull" and "--force" in a)
        print(json.dumps(cmd_pull(force=force), ensure_ascii=False))
        return 0

    if cmd == "sync":
        print(json.dumps(cmd_sync(), ensure_ascii=False))
        return 0

    if cmd == "discover":
        print(json.dumps(cmd_discover(force="--force" in a), ensure_ascii=False))
        return 0

    if cmd == "health":
        print(json.dumps(cmd_health(force="--force" in a,
                                    only=(a[1] if len(a) > 1 and not a[1].startswith("--") else None)),
                         ensure_ascii=False))
        return 0

    if cmd in ("pool", "take"):
        if not a:
            return 1
        n = int(a[1]) if len(a) > 1 else 120
        for ip in cmd_pool(a[0], n, smart=(cmd == "take")):
            print(ip)
        return 0

    if cmd == "feed":
        if not a:
            print(json.dumps({"ok": False, "error": "用法: feed ROUTE < ip 来源"}))
            return 1
        rows = []
        for ln in sys.stdin:
            q = ln.split()
            if q:
                rows.append((q[0], q[1] if len(q) > 1 else "dns"))
        print(json.dumps(cmd_feed(a[0], rows), ensure_ascii=False))
        return 0

    if cmd == "bump-many":
        if not a:
            return 1
        route = a[0]
        pool = load_pool(route)
        n = 0
        for ln in sys.stdin:
            p = ln.split()
            if len(p) < 2:
                continue
            b = pool["ips"].get(p[0])
            if not b:
                continue
            if p[1] == "ok":
                b["ok"] = int(b.get("ok", 0)) + 1
                b["lo"] = int(time.time())
                b["fl"] = 0
            else:
                b["fl"] = int(b.get("fl", 0)) + 1
            n += 1
        save_pool(route, pool)
        print(json.dumps({"ok": True, "n": n}))
        return 0

    if cmd == "mark-bad":
        if len(a) >= 2:
            print(json.dumps(mark_bad(a[0], a[1], a[2] if len(a) > 2 else "",
                                      a[3] if len(a) > 3 else ""), ensure_ascii=False))
        return 0

    if cmd == "clear-bad":
        if a:
            clear_bad(a[0])
        return 0

    if cmd == "bad":
        now = time.time()
        print(json.dumps({k: v for k, v in load_bad().items()
                          if float(v.get("until", 0)) > now}, ensure_ascii=False))
        return 0

    if cmd == "filter":
        bad = _bad_set()
        for ln in sys.stdin:
            p = ln.split()
            if p and p[0] not in bad:
                print(p[0])
        return 0

    if cmd == "prune":
        print(json.dumps(cmd_prune(a[0] if a else ""), ensure_ascii=False))
        return 0

    if cmd == "events":
        n = int(a[0]) if a else 60
        ev = jload(EVENT_FILE, {"events": []})
        print(json.dumps((ev.get("events") or [])[:n], ensure_ascii=False))
        return 0

    print("未知命令: %s" % cmd)
    return 1


if __name__ == "__main__":
    sys.exit(main())
