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
]

DEFAULT_PULL = {"enabled": True, "cycle": "6h", "hour": 4, "last": 0}
DEFAULT_DISC = {"enabled": False, "cycle": "daily", "hour": 4, "last": 0, "found": 0}


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
    d["pull"] = {**DEFAULT_PULL, **pull}
    d["discover"] = {**DEFAULT_DISC, **disc}
    return d


def save_src(d):
    jsave(SRC_FILE, d)


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
    for url, label in ((it.get("url_v4"), "v4"), (it.get("url_v6"), "v6")):
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


def cmd_del(key):
    d = load_src()
    n = len(d["items"])
    d["items"] = [it for it in d["items"] if it.get("key") != key]
    if len(d["items"]) == n:
        return {"ok": False, "error": "源不存在"}
    save_src(d)
    return {"ok": True}


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
    items = []
    for it in (payload.get("items") or []):
        key = it.get("key") or ("custom-%d" % int(time.time() * 1000))
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
        }
    ev = jload(EVENT_FILE, {"events": []})
    return {
        "items": d["items"],
        "subs": d.get("subs", []),
        "proxy": d.get("proxy", ""),
        "pull": {**d["pull"], "next": _next_ts(d["pull"], d["pull"].get("last", 0), now)},
        "discover": {**d["discover"], "next": _next_ts(d["discover"], d["discover"].get("last", 0), now)},
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
                "enabled": p.get("enabled", True), "route": "cf",
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

    if cmd in ("pool", "take"):
        if not a:
            return 1
        n = int(a[1]) if len(a) > 1 else 120
        for ip in cmd_pool(a[0], n, smart=(cmd == "take")):
            print(ip)
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
