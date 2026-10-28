#!/usr/bin/env python3
# ============================================================
# 控制台后端（纯 Python 标准库，无 pip 依赖）
# 单登录 + 状态/结果/日志/配置/触发/实时解析
# ============================================================
import ipaddress
import json
import mimetypes
import os
import re
import secrets
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# 上游探测 / 配置读写的实现在 scheduler/lib 下，UI 与定时扫描共用同一份，
# 免得两处各写一套正则，改了一边忘了另一边。
_LIB = "/app/scheduler/lib"
if not os.path.isdir(_LIB):
    _LIB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scheduler", "lib")
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)
try:
    import doh_config as doh_cfg
    import doh_probe as doh_pb
except Exception as _doh_imp_err:  # 老镜像里没有这两个文件时降级，不影响其它页面
    doh_cfg = doh_pb = None
    print("[ui] 上游探测模块缺失：%s" % _doh_imp_err, flush=True)

DATA_DIR = os.environ.get("PREF_DATA_DIR", "/data")
UI_PORT = int(os.environ.get("PREF_UI_PORT", "80"))
DNS_PORT = int(os.environ.get("PREF_DNS_PORT", "53"))
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
AUTH_FILE = os.path.join(DATA_DIR, "auth.json")
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")
PREF_DIR = os.path.join(DATA_DIR, "prefs")
PREF_LOG = os.path.join(DATA_DIR, "pref.log")
MOSDNS_OUT = os.path.join(DATA_DIR, "mosdns.out")
MOSDNS_PID = os.path.join(DATA_DIR, "mosdns.pid")
MOSDNS_LOG = os.path.join(DATA_DIR, "mosdns.log")
MOSDNS_API_PORT = int(os.environ.get("PREF_API_PORT", "9099"))
CACHE_DUMP = os.path.join(DATA_DIR, "cache.dump")
CACHE_SIZE = int(os.environ.get("PREF_CACHE_SIZE", "8192"))
SCHEDULER = "/app/scheduler/scheduler.sh"
DNSSQ = "/app/scheduler/lib/dnsq.py"
LISTS_PY = "/app/scheduler/lib/lists.py"
SUBS_PY = "/app/scheduler/lib/subs.py"
DIAG_PY = "/app/scheduler/lib/diag.py"
PUSH_PY = "/app/scheduler/lib/push.py"
LISTS_META = os.path.join(DATA_DIR, "lists_meta.json")

ROUTES = ["cf", "google", "gt", "github", "ghcr", "tmdb", "imdb"]
SESSIONS = {}
SESSION_TTL = 7 * 24 * 3600
LOCK = threading.Lock()


def load_auth():
    """返回 (user, pass, is_default)。is_default=True 表示仍是初始 admin/admin。"""
    try:
        with open(AUTH_FILE) as f:
            d = json.load(f)
        u, p = str(d.get("user", "admin")), str(d.get("pass", ""))
        return u, p, bool(d.get("default", u == "admin" and p == "admin"))
    except Exception:
        return "admin", "admin", True


def save_auth(user, pwd):
    data = {"user": user, "pass": pwd, "default": (user == "admin" and pwd == "admin")}
    write_json(AUTH_FILE, data)
    return data


def read_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, ensure_ascii=False)
    os.replace(tmp, path)


def tail(path, n=200):
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            block = min(size, max(n * 200, 8192))
            f.seek(size - block)
            data = f.read().decode("utf-8", "replace")
        lines = data.splitlines()
        return lines[-n:]
    except Exception:
        return []


def run_subs(args, stdin_data=None, timeout=180):
    """调用 subs.py 并解析 JSON；超时或异常都返回可读错误，不抛给前端。"""
    try:
        p = subprocess.run(
            [sys.executable, SUBS_PY] + list(args),
            input=stdin_data,
            capture_output=True,
            timeout=timeout,
        )
        out = p.stdout.decode("utf-8", "replace").strip()
        if not out:
            return {"ok": False, "error": (p.stderr.decode("utf-8", "replace")[:300] or "无输出")}
        return json.loads(out)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "操作超时（%ds），源可能响应太慢" % timeout}
    except Exception as e:
        return {"ok": False, "error": str(e)[:200]}


def sources_status():
    st = run_subs(["status"])
    if not isinstance(st, dict) or "items" not in st:
        return {"items": [], "subs": [], "pools": {}, "bad": [], "events": [],
                "error": st.get("error") if isinstance(st, dict) else "读取失败"}
    # 每路最近一次优选结果（含被拒原因），供「结果」页显示
    states = {}
    for r in ROUTES:
        p = os.path.join(PREF_DIR, "%s.state.json" % r)
        d = read_json(p, None)
        if d:
            states[r] = d
    st["states"] = states
    return st
def mosdns_alive():
    try:
        with open(MOSDNS_PID) as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)
        return True
    except Exception:
        return False


# 查询日志：mosdns 的 query_summary 插件写入，控制台「实时解析域名」读它
QTYPE = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
         16: "TXT", 28: "AAAA", 33: "SRV", 64: "SVCB", 65: "HTTPS", 255: "ANY"}
RCODE = {0: "正常", 2: "服务器失败", 3: "域名不存在", 4: "不支持", 5: "拒绝"}
CACHE_MS = 5.0   # 耗时 ≤ 该阈值视为命中缓存（cache 插件命中不回源，通常 1ms 内）


def rotate_qlog_if_big(max_bytes=32 * 1024 * 1024, keep_bytes=8 * 1024 * 1024):
    """日志过大时只保留尾部，避免 /data 被写满。"""
    try:
        if os.path.getsize(MOSDNS_LOG) <= max_bytes:
            return
        with open(MOSDNS_LOG, "rb") as f:
            f.seek(-keep_bytes, os.SEEK_END)
            data = f.read()
        with open(MOSDNS_LOG, "wb") as f:
            f.write(data)
    except Exception:
        pass


_PREF_DOM_CACHE = {"mtime": 0, "domains": set()}

# ---------------- 应答归属：这个域名解析出来的 IP 是谁家的 ----------------
# 面板里只看得到「回源/命中」，看不出这个站到底套没套 CDN。这里自己查一次 A 记录，
# 拿答案 IP 去比网段：CDN 段命中就标 Cloudflare/Google/...，落在国内段标「国内」。
_CDN_CACHE = {"mtime": (), "nets": []}
_ANS_CACHE = {}          # qname -> (ts, ip, owner)
_ANS_TTL = 180           # 3 分钟：够新，又不会每 5 秒刷一轮查询
_ANS_MAX = 1500


def _cdn_nets():
    """读 CDN/大厂网段库：/data 里可在线更新的那份 + 镜像内置那份，合并去重。

    两份都读是因为 /data 那份是线上更新器写的（常常只有 Cloudflare 一段），
    内置那份才带 Google/GitHub/Fastly；只读其一都会认漏。
    """
    paths = (os.path.join(DATA_DIR, "cdn_ranges.txt"), "/app/config/cdn_ranges.txt")
    mt = []
    for p in paths:
        try:
            mt.append(os.path.getmtime(p))
        except Exception:
            mt.append(0)
    if not any(mt):
        return []
    if tuple(mt) == tuple(_CDN_CACHE["mtime"]):
        return _CDN_CACHE["nets"]
    nets, seen = [], set()
    for p in paths:
        try:
            with open(p, encoding="utf-8") as f:
                for ln in f:
                    ln = ln.strip()
                    if not ln or ln.startswith("#"):
                        continue
                    parts = ln.split()
                    if len(parts) < 2:
                        continue
                    try:
                        net = ipaddress.ip_network(parts[1], strict=False)
                    except Exception:
                        continue
                    key = (str(net), parts[0])
                    if key in seen:
                        continue
                    seen.add(key)
                    nets.append((net, parts[0]))
        except Exception:
            continue
    _CDN_CACHE["mtime"] = tuple(mt)
    _CDN_CACHE["nets"] = nets
    return nets


def _cn_nets():
    for p in (os.path.join(DATA_DIR, "china_ip.txt"), "/app/config/china_ip.txt"):
        try:
            nets = []
            with open(p, encoding="utf-8") as f:
                for ln in f:
                    ln = ln.strip()
                    if not ln or ln.startswith("#"):
                        continue
                    try:
                        nets.append(ipaddress.ip_network(ln.split()[0], strict=False))
                    except Exception:
                        continue
            if nets:
                return nets
        except Exception:
            continue
    return []


_CN_CACHE = {"nets": None}


def owner_of(ip):
    """IP 归属：先比 CDN/大厂段，再比国内段。认不出就返回「海外」。"""
    try:
        a = ipaddress.ip_address(ip)
    except Exception:
        return ""
    for net, name in _cdn_nets():
        if a in net:
            return name
    if a.version == 4:
        if _CN_CACHE["nets"] is None:
            _CN_CACHE["nets"] = _cn_nets()
        for net in _CN_CACHE["nets"]:
            if a in net:
                return "国内"
    return "海外"


def dns_a(qname, timeout=0.8):
    """向本机 mosdns 查一次 A 记录，返回第一个 IP（失败返回 None）。

    只是为了让面板能显示「这个域名现在解析到哪个 IP、这 IP 是谁家的」，
    查的是自己家引擎，通常直接命中缓存，开销极小。
    """
    try:
        tid = secrets.randbelow(65536)
        hdr = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        qn = b"".join(bytes([len(p)]) + p.encode() for p in qname.split(".") if p) + b"\x00"
        pkt = hdr + qn + struct.pack("!HH", 1, 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(pkt, ("127.0.0.1", DNS_PORT))
            data, _ = s.recvfrom(2048)
        finally:
            s.close()
        if len(data) < 12 or (data[3] & 0x0F):
            return None
        an = struct.unpack("!H", data[6:8])[0]
        i = 12
        while i < len(data) and data[i]:
            if data[i] & 0xC0 == 0xC0:
                i += 1
                break
            i += 1 + data[i]
        i += 5
        for _ in range(an):
            while i < len(data) and data[i] and data[i] & 0xC0 != 0xC0:
                i += 1 + data[i]
            i += 2 if (i < len(data) and data[i] & 0xC0 == 0xC0) else 1
            if i + 10 > len(data):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[i:i + 10])
            i += 10
            if rtype == 1 and rdlen == 4:
                return socket.inet_ntoa(data[i:i + 4])
            i += rdlen
    except Exception:
        return None
    return None


def answer_of(qname):
    """带缓存的「域名 -> (IP, 归属)」。"""
    now = time.time()
    hit = _ANS_CACHE.get(qname)
    if hit and now - hit[0] < _ANS_TTL:
        return hit[1], hit[2]
    ip = dns_a(qname)
    own = owner_of(ip) if ip else ""
    if len(_ANS_CACHE) > _ANS_MAX:
        _ANS_CACHE.clear()
    _ANS_CACHE[qname] = (now, ip, own)
    return ip, own



def pref_domains():
    """优选 hosts 里写了哪些域名（按文件 mtime 缓存，没必要每行都重读）。"""
    p = os.path.join(PREF_DIR, "all.hosts")
    try:
        mt = os.path.getmtime(p)
    except Exception:
        return set()
    if mt != _PREF_DOM_CACHE["mtime"]:
        ds = set()
        try:
            with open(p, encoding="utf-8") as f:
                for ln in f:
                    parts = ln.split()
                    if parts and not parts[0].startswith("#"):
                        ds.add(parts[0].rstrip(".").lower())
        except Exception:
            pass
        _PREF_DOM_CACHE["mtime"] = mt
        _PREF_DOM_CACHE["domains"] = ds
    return _PREF_DOM_CACHE["domains"]


_ROUTE_NAMES = {
    "cf": "Cloudflare",
    "google": "Google 搜索",
    "gt": "Google 翻译",
    "github": "GitHub",
    "ghcr": "ghcr",
    "tmdb": "TMDB",
    "imdb": "IMDb",
}
_ROUTE_CACHE = {"sig": None, "map": {}}


def route_map():
    """域名 -> 所属优选路（cf / google / gt / github / ghcr / tmdb / imdb）。

    按路读各自的 hosts 文件，不读 all.hosts：合并后的文件看不出域名属于哪一路。
    Google 两路的优选 IP 多为国内中转节点，单看 IP 归属只会判成「国内」，
    因此线路一栏以域名归属为准，IP 归属作为附加信息。
    """
    try:
        names = sorted(os.listdir(PREF_DIR))
    except Exception:
        return {}
    files = []
    for n in names:
        if not n.endswith(".hosts") or n.startswith("all.hosts"):
            continue
        p = os.path.join(PREF_DIR, n)
        try:
            files.append((p, os.path.getmtime(p)))
        except Exception:
            continue
    sig = tuple((p, mt) for p, mt in files)
    if sig == _ROUTE_CACHE["sig"]:
        return _ROUTE_CACHE["map"]
    m = {}
    for p, _mt in files:
        key = os.path.basename(p)[: -len(".hosts")]
        try:
            with open(p, encoding="utf-8", errors="ignore") as f:
                for ln in f:
                    parts = ln.split()
                    if not parts or parts[0].startswith("#"):
                        continue
                    dom = parts[0].rstrip(".").lower()
                    if dom and dom not in m:
                        m[dom] = key
        except Exception:
            continue
    _ROUTE_CACHE["sig"] = sig
    _ROUTE_CACHE["map"] = m
    return m


def _elapsed_ms(v):
    """把 mosdns 的耗时字段统一换算成毫秒。

    新版 query_summary 输出的是带单位的字符串：`493.684495ms` / `105.026µs` / `1.2s` / `900ns`，
    老版是秒为单位的数字。两种都要能认，否则耗时列全空、缓存命中判断也失效。
    """
    try:
        s = str(v).strip()
        if s.endswith("µs") or s.endswith("us"):
            return round(float(s[:-2]) / 1000.0, 3)
        if s.endswith("ms"):
            return round(float(s[:-2]), 1)
        if s.endswith("ns"):
            return round(float(s[:-2]) / 1e6, 3)
        if s.endswith("s"):
            return round(float(s[:-1]) * 1000.0, 1)
        return round(float(s) * 1000.0, 1)   # 老版：纯秒数
    except Exception:
        return None


def read_qlog(limit=30, uniq=False, resolve=0):
    """从 mosdns 日志尾部解析 query_summary，返回最近若干条 + 命中统计。

    uniq=True 时按域名去重：同一个域名被查了 20 次也只留最近那一次，
    这样面板列的是「现在有哪些域名在解析」而不是同一批域名反复刷屏。
    resolve=N 时给前 N 条补上应答 IP 与归属（N=0 表示不查）。

    兼容两种日志格式：
      ① 老版 mosdns：INFO ... query summary {json}
      ② 新版 query_summary 插件：INFO <tag> qlog {"uqid": ..., "qname": ...}
    只认 "query summary" 会导致新版完全解析不出数据（面板一直显示"还没有查询记录"）。
    """
    lines = tail(MOSDNS_LOG, 2000)
    items = []
    for ln in lines:
        if "query summary" not in ln and '"uqid"' not in ln:
            continue
        pos = ln.find("{")
        if pos < 0:
            continue
        try:
            d = json.loads(ln[pos:])
        except Exception:
            continue
        qname = str(d.get("qname", "")).rstrip(".")
        if not qname:
            continue
        ms = _elapsed_ms(d.get("elapsed"))
        rcode = d.get("rcode")
        clock = ""
        head = ln.split("\t", 1)[0]
        if "T" in head:
            clock = head.split("T", 1)[1][:8]
        cli = re.sub(r"^::ffff:", "", str(d.get("client", "")))
        # 面板自己为了显示应答 IP 会问一次本机引擎，那些查询的 client 是环回地址，
        # 不能算进"谁在解析"，否则列表会被自己刷一遍。
        if cli in ("127.0.0.1", "::1", "localhost"):
            continue
        items.append({
            "time": clock,
            "qname": qname,
            "qtype": QTYPE.get(d.get("qtype"), str(d.get("qtype", ""))),
            "rcode": rcode,
            "status": RCODE.get(rcode, "无响应" if rcode is None else "异常"),
            "ms": ms,
            "cached": bool(ms is not None and ms <= CACHE_MS),
            # mosdns 给的 client 不带端口，但 IPv4 会写成 ::ffff:192.168.1.252；
            # 之前用 rsplit(":") 会把这种地址截成 "::ffff"，这里只剥前缀。
            "client": cli,
        })
    recent = items[-limit:][::-1]
    if uniq:
        # 从最新往回扫，同一个域名只留第一次遇到的那条（即最近一次查询）。
        # dict 保插入顺序，所以列表天然是"最近查过的域名在前"。
        seen = {}
        for x in reversed(items):
            if x["qname"] not in seen:
                seen[x["qname"]] = x
        recent = list(seen.values())
    total = len(items)
    vals = [x["ms"] for x in items if x["ms"] is not None]
    cached_n = sum(1 for x in items if x["cached"])
    failed_n = sum(1 for x in items if x["rcode"] not in (0, None))
    # 规则命中情况：域名写进了优选 hosts 就是被规则覆盖，否则走上游解析。
    # 只看「几路成功」看不出效果，这里把命中/没命中分别计数。
    pref = pref_domains()
    if resolve and recent:
        # 只给最上面那几条补应答（当前可见的那一屏），越往下越没必要。
        routes = route_map()
        for x in recent[:resolve]:
            rk = routes.get(x["qname"], "")
            x["route"] = rk
            x["route_name"] = _ROUTE_NAMES.get(rk, rk)
            x["pref"] = x["qname"] in pref
            ip, own = answer_of(x["qname"])
            x["ip"], x["owner"] = ip or "", own or ""
    hit = miss = 0
    hit_d, miss_d = set(), set()
    for x in items:
        if x["qname"] in pref:
            hit += 1
            hit_d.add(x["qname"])
        else:
            miss += 1
            miss_d.add(x["qname"])
    return {
        "items": recent,
        "total": total,
        "avg": round(sum(vals) / len(vals), 1) if vals else None,
        "cached": cached_n,
        "cached_pct": round(cached_n * 100.0 / total, 1) if total else 0,
        "failed": failed_n,
        "domains": len({x["qname"] for x in items}),
        "pref_hit": hit,
        "pref_hit_pct": round(hit * 100.0 / total, 1) if total else 0,
        "pref_hit_domains": len(hit_d),
        "pref_miss": miss,
        "pref_miss_domains": len(miss_d),
        "pref_total_domains": len(pref),
        "cache_ms": CACHE_MS,
        "log_ok": bool(items),
    }


def mosdns_api(path, timeout=3):
    """调 mosdns 原生 API（只监听环回，不经外网）。"""
    url = "http://127.0.0.1:%d%s" % (MOSDNS_API_PORT, path)
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read()


def _metric(txt, name):
    for ln in txt.splitlines():
        if ln.startswith(name):
            try:
                return int(float(ln.rsplit(" ", 1)[1]))
            except Exception:
                return None
    return None


def cache_info():
    """缓存用量：条数/上限/累计命中 + 落盘文件与日志体积。"""
    info = {"size": None, "hit": None, "capacity": CACHE_SIZE,
            "dump_bytes": 0, "log_bytes": 0, "api_ok": False}
    try:
        txt = mosdns_api("/metrics").decode("utf-8", "replace")
        info["size"] = _metric(txt, "mosdns_cache_size_current")
        info["hit"] = _metric(txt, "mosdns_cache_hit_total")
        info["api_ok"] = True
    except Exception:
        pass
    for key, p in (("dump_bytes", CACHE_DUMP), ("log_bytes", MOSDNS_LOG)):
        try:
            info[key] = os.path.getsize(p)
        except Exception:
            pass
    return info


def cache_flush():
    """清空 DNS 缓存：调 cache 插件 flush，并删掉落盘副本，避免重启后又被加载回来。"""
    mosdns_api("/plugins/dns_cache/flush")
    try:
        os.remove(CACHE_DUMP)
    except Exception:
        pass
    return True


def qlog_clear():
    try:
        with open(MOSDNS_LOG, "w"):
            pass
    except Exception:
        pass
    return True


def is_ip(s):
    try:
        ipaddress.ip_address((s or "").strip())
        return True
    except Exception:
        return False


# 「明确坏」的校验结果：Cloudflare 10xx 错误页 / 证书不符 / 5xx
# 这类 IP 绝不允许出现在「优选 IP」里——UI 再兜一道，防止 hosts 里的历史残留被展示出来
HARD_FAIL = re.compile(r"^(cf\d{3,4}|cert|wrong|http5\d\d)$")


def is_hard_fail(status):
    return bool(HARD_FAIL.match((status or "").strip().lower()))


def read_results():
    """读每路结果：域名 + 多个 IP（含延迟）。

    hosts 里理论上只会有通过校验的 IP，但重启/回滚可能留下历史残留，
    所以这里按 meta 里的校验状态再过滤一次，硬失败的直接剔除并计数。
    """
    out = {}
    for r in ROUTES:
        p = os.path.join(PREF_DIR, "%s.hosts" % r)
        entry = {"domain": "", "domains": [], "ip": "", "ips": [], "mtime": 0, "dropped": []}
        lat = {}
        try:
            with open(os.path.join(PREF_DIR, "%s.meta" % r)) as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            st = parts[2] if len(parts) > 2 else ""
                            sp = None
                            sp_est = False
                            if len(parts) > 3 and parts[3] not in ("-", ""):
                                # 「~158」表示样本太小、只是估算值（界面显示为 ≈158KB/s）
                                tok = parts[3]
                                sp_est = tok.startswith("~")
                                try:
                                    sp = float(tok.lstrip("~"))
                                except Exception:
                                    sp = None
                            lat[parts[0]] = (float(parts[1]), st, sp, sp_est)
                        except Exception:
                            pass
        except Exception:
            pass
        try:
            first = True
            with open(p) as f:
                for line in f:
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    # hosts 里一路可能有好几行：第一行是主域名（拿它的 IP 展示），
                    # 后面几行是同一路顺带映射的域名（api.tmdb.org、image.tmdb.org、
                    # raw/objects…）。只在第一行取 IP 就 break 的话，界面永远只显示
                    # 一个域名，用户根本看不出这一路到底覆盖了什么。
                    entry["domains"].append(parts[0])
                    if not first:
                        continue
                    first = False
                    entry["domain"] = parts[0]
                    ips = []
                    for ip in parts[1:]:
                        if not is_ip(ip):
                            continue
                        lt, st, sp, sp_est = lat.get(ip, (None, "", None, False))
                        st = st or "ok"
                        if is_hard_fail(st):
                            # 1034/证书/5xx 一律不展示，记下来供界面提示「已剔除」
                            entry["dropped"].append({"ip": ip, "reason": st})
                            continue
                        if lt is None and sp is None:
                            # hosts 里有这个 IP，但这一轮根本没测到它（meta 里没有记录）。
                            # 界面上延时、速度两栏都是空的，只剩一个「—」——
                            # 列出来既没用，还让人以为这一路总共就这么几个 IP。
                            # 记进 untested，不当作可用 IP 展示。
                            entry.setdefault("untested", []).append(ip)
                            continue
                        ips.append({
                            "ip": ip,
                            "family": "v6" if ":" in ip else "v4",
                            # latency 现在是真实 HTTPS 响应时间（TTFB），不再是 TCP 握手
                            "latency": lt,
                            "speed": sp,          # KB/s；拿不到（响应体太小）时为 null
                            "speed_est": sp_est,   # true = 样本太小，只是个大概值
                            "status": st,
                        })
                    entry["ips"] = ips
                    entry["ip"] = ips[0]["ip"] if ips else ""
            entry["mtime"] = int(os.path.getmtime(p))
        except Exception:
            pass
        out[r] = entry
        # 最近一轮的判定结果（ok / degraded / no_valid…），界面据此标「降级使用」
        st = read_json(os.path.join(PREF_DIR, "%s.state.json" % r), None)
        if isinstance(st, dict):
            entry["status"] = st.get("status", "")
            entry["checked_at"] = st.get("ts", 0)
            if st.get("domain"):
                entry["domain"] = st["domain"]
    return out


def diag_run(args, timeout=30):
    try:
        r = subprocess.run(["python3", DIAG_PY] + args, capture_output=True, timeout=timeout)
        return json.loads(r.stdout.decode("utf-8", "replace") or "{}")
    except Exception as e:
        return {"error": str(e)}


def push_brief():
    """每路当前生效的域名和 IP 整理成一段文本（推送正文 + 控制台预览共用）。"""
    try:
        r = subprocess.run(["python3", "/app/scheduler/lib/route_brief.py", PREF_DIR],
                           capture_output=True, timeout=10)
        return (r.stdout or b"").decode("utf-8", "replace").strip()
    except Exception:
        return ""


def push_event(ev, title, body):
    """按配置推送消息（企业微信 / 钉钉 / 飞书 机器人）。"""
    cfg = read_json(SETTINGS_FILE, {}).get("push") or {}
    if not cfg.get("enabled") or not cfg.get("url"):
        return
    evs = str(cfg.get("events", "") or "")
    if evs and ev not in [x.strip() for x in evs.split(",") if x.strip()]:
        return
    try:
        subprocess.run(["python3", PUSH_PY, cfg["url"], title, body],
                       capture_output=True, timeout=10)
    except Exception:
        pass


def tcp_latency(ip, port=443, timeout=3.0):
    v6 = ":" in (ip or "")
    best = None
    for _ in range(3):
        s = socket.socket(socket.AF_INET6 if v6 else socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = time.time()
        try:
            s.connect((ip, port, 0, 0) if v6 else (ip, port))
            dt = (time.time() - t0) * 1000.0
            best = dt if best is None else min(best, dt)
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass
        if best is not None:
            break
    return best


def dns_lookup(domain, port=None, timeout=3):
    """同时查 A 与 AAAA，返回 [(ip, family), ...]"""
    port = port or DNS_PORT
    try:
        res = subprocess.run(
            ["python3", DNSSQ, "127.0.0.1", str(port), domain, "ALL"],
            capture_output=True, timeout=timeout + 2,
        )
        out = []
        for line in res.stdout.decode("utf-8", "replace").splitlines():
            ip = line.strip()
            if is_ip(ip):
                out.append((ip, "v6" if ":" in ip else "v4"))
        return out
    except Exception:
        return []


# ---------- 分流清单 ----------
def lists_status():
    try:
        res = subprocess.run(["python3", LISTS_PY, "status"], capture_output=True, timeout=25)
        return json.loads(res.stdout.decode("utf-8", "replace") or "{}")
    except Exception:
        return {}


def count_lines(path):
    n = 0
    try:
        with open(path, "rb") as f:
            for line in f:
                if line.strip() and not line.lstrip().startswith(b"#"):
                    n += 1
    except Exception:
        return 0
    return n


# 四份分流清单：国内侧靠 IP 段 + 域名，国外侧靠域名（GFW 清单），
# CDN 网段给诊断用。概况页要把这四份都摊开，只报「国内 IP 段」会让人
# 以为国外没有清单。
LIST_SPECS = [
    ("china_ip", "国内 IP 段"),
    ("cn_domains", "国内域名"),
    ("gfw_domains", "国外域名"),
    ("cdn_ranges", "国外 CDN 网段"),
]
_LISTS_CACHE = {"at": 0, "data": None}


def lists_brief():
    """概况页用的轻量摘要：条数 + 更新时间，四份清单都给。

    110k 行的域名清单每次请求都数一遍太浪费（前端 5 秒轮询一次），
    所以缓存 30 秒；清单有更新时 updated_at 会变，最多迟半分钟才反映。
    """
    now = int(time.time())
    if _LISTS_CACHE["data"] and now - _LISTS_CACHE["at"] < 30:
        return _LISTS_CACHE["data"]
    meta = read_json(LISTS_META, {})
    out = {}
    for name, label in LIST_SPECS:
        path = os.path.join(DATA_DIR, name + ".txt")
        info = meta.get(name, {}) or {}
        lines = count_lines(path)
        updated = info.get("updated_at") or 0
        if not updated:
            try:
                updated = int(os.stat(path).st_mtime)
            except Exception:
                updated = 0
        src = info.get("source") or ""
        out[name] = {
            "label": label,
            "lines": lines,
            "updated_at": updated,
            "status": info.get("status") or ("ok" if lines else "empty"),
            "source_host": src.split("/")[2] if "//" in src else (src or "内置镜像"),
        }
    _LISTS_CACHE.update({"at": now, "data": out})
    return out


DOH_LOCAL_CUSTOM = os.path.join(DATA_DIR, "doh_local_custom.txt")
DOH_REMOTE_CUSTOM = os.path.join(DATA_DIR, "doh_remote_custom.txt")
DOH_SELECT = "/app/scheduler/lib/select_doh.py"


def _doh_line_ok(u):
    """一条上游只做最基本的合法性判断：必须 https/http，主机名或 IP 都能过。"""
    if not re.match(r"^https?://[A-Za-z0-9_.:\[\]-]{1,253}(/\S*)?$", u):
        return False
    return True


def _yaml_doh_block(entries):
    """生成与 entrypoint 探测输出同格式的 YAML 片段（8 空格缩进）。"""
    return doh_cfg.yaml_block(entries) if doh_cfg else ""


def _replace_doh_block(text, tag, block):
    """把某个 forward 插件的 upstreams 段整段换掉（实现见 scheduler/lib/doh_config.py）。"""
    return doh_cfg.replace_block(text, tag, block) if doh_cfg else text


def apply_upstreams(local, remote):
    """写自定义上游 -> 重写 /data/config.yaml -> 热重载引擎。

    手动填了就用手动（同时落 custom 文件，容器重启后 entrypoint 直接沿用）；
    传空列表表示恢复自动探测。
    """
    local = [x for x in (local or []) if _doh_line_ok(str(x).split()[0])]
    remote = [x for x in (remote or []) if _doh_line_ok(str(x).split()[0])]
    changed = doh_cfg.apply_entries(local, remote)
    # 落盘给下次容器启动用：存在 custom 文件 = 手动模式
    doh_cfg.write_custom(local, remote)
    if changed:
        doh_cfg.reload_engine(25)
    return changed


def test_upstreams(local, remote):
    """逐条真探测。写进配置之前必须过这一关：连不上 / 解析不了的不能固化。"""
    out = {"local": [], "remote": []}
    if not doh_pb:
        return out
    for key, entries, qname in (("local", local, "www.baidu.com"), ("remote", remote, "www.google.com")):
        entries = [str(x).strip() for x in (entries or []) if str(x).strip()]
        if entries:
            out[key] = doh_pb.probe_many(entries, qname=qname, timeout=5, workers=6)
    return out


def test_failures(results):
    bad = []
    for key in ("local", "remote"):
        for r in results.get(key) or []:
            if not r.get("ok"):
                bad.append(r)
    return bad


def scan_detail(d):
    """把上一次扫描摊成一张表：每一条候选到底是「在用 / 可用未启用 / 不通」。

    界面上那句「候选 12 条可用 1 条」太笼统，看着像没干活。
    这里给出逐条状态，让人一眼看到是「12 条都试过、11 条被墙」，
    而不是「只找到了 1 条」。
    """
    out = {}
    act = d.get("active") or {}
    alive = d.get("alive") or {}
    failed = d.get("failed") or {}
    for k in ("local", "remote"):
        active_lines = [str(x).strip() for x in (act.get(k) or []) if str(x).strip()]
        active_urls = {x.split()[0] for x in active_lines}
        rows, seen = [], set()
        for r in alive.get(k) or []:
            line = str(r.get("line") or "").strip()
            if not line or line in seen:
                continue
            seen.add(line)
            is_act = line in active_lines or (line.split()[0] in active_urls)
            rows.append({"line": line, "state": "active" if is_act else "alive",
                         "ms": int(r.get("ms") or 0), "ip": r.get("ip") or "", "err": ""})
        # 在用但没出现在探测结果里的（配置文件里手写的、扫描前刚改的）兜底
        for line in active_lines:
            if line not in seen:
                seen.add(line)
                rows.append({"line": line, "state": "active", "ms": 0, "ip": "", "err": ""})
        for r in failed.get(k) or []:
            line = str(r.get("line") or "").strip()
            if not line or line in seen:
                continue
            seen.add(line)
            rows.append({"line": line, "state": "dead", "ms": 0, "ip": "",
                         "err": r.get("err") or "探测不通"})
        rank = {"active": 0, "alive": 1, "dead": 2}
        rows.sort(key=lambda x: rank.get(x["state"], 9))
        out[k] = rows
    return out


def scan_counts(detail):
    c = {}
    for k, rows in (detail or {}).items():
        c[k] = {"active": 0, "alive": 0, "dead": 0, "total": len(rows)}
        for r in rows:
            if r["state"] in c[k]:
                c[k][r["state"]] += 1
    return c


def doh_scan_brief():
    """上次扫描的结果摘要（定时扫描写 /data/doh_scan.json）。"""
    try:
        with open(os.path.join(DATA_DIR, "doh_scan.json"), encoding="utf-8") as f:
            d = json.load(f)
    except Exception:
        return {"at": 0, "age": 0, "summary": "", "new": [], "dead": [], "mode": "auto",
                "detail": {"local": [], "remote": []}, "counts": {}}
    at = int(d.get("at") or 0)
    alive = 0
    for k in ("local", "remote"):
        alive += len((d.get("alive") or {}).get(k) or [])
    new = d.get("new") or []
    detail = scan_detail(d)
    return {
        "at": at,
        "age": max(0, int(time.time()) - at) if at else 0,
        "summary": d.get("summary") or "",
        "applied": bool(d.get("applied")),
        "mode": d.get("mode") or "auto",
        "pool": d.get("pool") or {},
        "pool_total": d.get("pool_total") or 0,
        "alive": alive,
        "new": new,
        "new_count": len(new),
        "dead": (d.get("dead") or [])[:8],
        "detail": detail,
        "counts": scan_counts(detail),
        "due_min": d.get("due_min") or 60,
        "took_ms": d.get("took_ms") or 0,
        "qname": d.get("qname") or {},
    }


def _dns_udp(port, qname, timeout=5):
    """问一次 mosdns 的测速入口（127.0.0.1:port），量一次真实转发耗时。"""
    try:
        body, _qid = doh_pb._wire_query(qname)
    except Exception as e:
        return {"ok": False, "ms": 0, "answers": 0, "rcode": None, "err": "构造查询失败：%s" % e}
    t0 = time.time()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(body, ("127.0.0.1", int(port)))
        raw, _ = sock.recvfrom(4096)
    except socket.timeout:
        return {"ok": False, "ms": int((time.time() - t0) * 1000), "answers": 0, "rcode": None,
                "err": "%d 秒内没响应（这条上游没回，或该地址根本没有 DoH 服务）" % timeout}
    except ConnectionRefusedError:
        return {"ok": False, "ms": 0, "answers": 0, "rcode": None,
                "err": "入口没在监听（mosdns 可能还没重载完）"}
    except Exception as e:
        return {"ok": False, "ms": 0, "answers": 0, "rcode": None,
                "err": str(getattr(e, "strerror", None) or e)}
    finally:
        if sock:
            sock.close()
    ms = int((time.time() - t0) * 1000)
    if len(raw) < 12:
        return {"ok": False, "ms": ms, "answers": 0, "rcode": None, "err": "响应太短（%d 字节）" % len(raw)}
    rcode = raw[3] & 0x0F
    an = int.from_bytes(raw[6:8], "big")
    if rcode != 0:
        # 2/SERVFAIL 有两种，含义完全不同：
        #   ① 很快返回（几十~几百毫秒）：真连上了，上游自己解析失败
        #      —— 路径不对、要 client id、或者这条地址根本不提供 DoH；
        #   ② 耗时贴着超时线：mosdns 等满了才兜底回一个 SERVFAIL，
        #      本质还是「没回应」（多半被墙/丢包），不能说成「连得上」。
        if rcode == 2 and ms >= int(timeout * 1000) - 300:
            return {"ok": False, "ms": ms, "answers": an, "rcode": rcode,
                    "err": "%d 秒内没响应（等满了只等来一个 SERVFAIL）" % timeout}
        why = {2: "上游回了 SERVFAIL（连得上，但它自己解析失败）",
               5: "上游拒绝这次查询（REFUSED）"}.get(rcode, "上游返回 rcode=%d" % rcode)
        return {"ok": False, "ms": ms, "answers": an, "rcode": rcode, "err": why}
    if an < 1:
        return {"ok": False, "ms": ms, "answers": 0, "rcode": rcode, "err": "能转发但查不到记录"}
    return {"ok": True, "ms": ms, "answers": an, "rcode": rcode, "err": ""}


def ensure_diag_ports():
    """确保 config 里有「每条上游一个测速入口」；候选池变了（加/删）也要重渲染。

    老逻辑只要发现有入口就直接返回，结果就是：手动加一条上游、或后台把死掉的删了，
    只要之前已经有入口，就不会重新生成——新加的那条永远没端口、永远测不到，
    被删的那条端口还空挂着。改成比对「想要的全集」和「已经渲染的」，不一致就重渲染 + 重载。
    """
    if not doh_cfg or not doh_pb:
        return []
    text = doh_cfg.read_cfg()
    items = doh_cfg.diag_ports(text)
    want = set(doh_cfg.full_set(text, "local")) | set(doh_cfg.full_set(text, "remote"))
    have = set(it["line"] for it in items)
    if items and want == have:
        return items
    with _DIAG_LOCK:
        # 拿锁后再核一次，避免并发重复重载
        text = doh_cfg.read_cfg()
        items = doh_cfg.diag_ports(text)
        want = set(doh_cfg.full_set(text, "local")) | set(doh_cfg.full_set(text, "remote"))
        have = set(it["line"] for it in items)
        if items and want == have:
            return items
        new = doh_cfg.render_diag(text)
        if not new or new == text:
            return items if items else []
        try:
            doh_cfg.write_cfg(new)
            doh_cfg.reload_engine(25)
            time.sleep(2)
        except Exception:
            return items if items else []
        return doh_cfg.diag_ports(doh_cfg.read_cfg())


# 上游是「哪家的」：按主机名和 IP 认。认不出来就如实显示主机名，
# 不编一个看起来像厂商的名字。
PROVIDERS = [
    ("alidns.com", "阿里 DNS"), ("223.5.5.5", "阿里 DNS"), ("223.6.6.6", "阿里 DNS"),
    ("dns.pub", "腾讯 DNSPod"), ("doh.pub", "腾讯 DNSPod"),
    ("119.29.29.29", "腾讯 DNSPod"), ("1.12.12.12", "腾讯 DNSPod"), ("120.53.53.53", "腾讯 DNSPod"),
    ("1.12.12.21", "腾讯 DNSPod"), ("120.53.53.54", "腾讯 DNSPod"),
    ("doh.360.cn", "360 安全 DNS"), ("101.226.4.6", "360 安全 DNS"),
    ("180.76.76.76", "百度 DNS"),
    ("117.50.10.10", "OneDNS"),
    ("cloudflare-dns.com", "Cloudflare"), ("1.1.1.1", "Cloudflare"), ("1.0.0.1", "Cloudflare"),
    ("dns.google", "Google"), ("8.8.8.8", "Google"), ("8.8.4.4", "Google"),
    ("dns.quad9.net", "Quad9"), ("9.9.9.9", "Quad9"), ("149.112.112.112", "Quad9"),
    ("doh.opendns.com", "OpenDNS"), ("208.67.222.222", "OpenDNS"),
    ("adguard-dns.com", "AdGuard DNS"), ("94.140.14.14", "AdGuard DNS"),
    ("dns.nextdns.io", "NextDNS"), ("45.90.28.1", "NextDNS"), ("45.90.30.1", "NextDNS"),
    ("controld.com", "ControlD"), ("76.76.2.", "ControlD"),
    ("quad101.net", "Quad101"), ("101.101.101.101", "Quad101"),
    ("dns-over-https.com", "DNS-over-HTTPS"), ("185.235.81.1", "DNS-over-HTTPS"),
    ("snopyta.org", "Snopyta"), ("95.216.24.100", "Snopyta"),
    ("doh.li", "doh.li"), ("178.216.201.70", "doh.li"),
    ("mullvad.net", "Mullvad"), ("194.242.2.", "Mullvad"),
    ("dns.sb", "DNS.SB"), ("185.222.222.222", "DNS.SB"),
    ("digitale-gesellschaft.ch", "Digitale Gesellschaft"), ("185.95.218.4", "Digitale Gesellschaft"),
]


def provider_of(line):
    """判断这条上游属于哪家。返回 (厂商名, 主机名)。"""
    parts = str(line or "").split()
    url = parts[0] if parts else ""
    host = url.split("//")[-1].split("/")[0]
    if host.startswith("["):
        host = host[1:host.find("]")] if "]" in host else host.strip("[]")
    elif host.count(":") == 1:
        host = host.split(":")[0]
    boot = parts[1].strip("[]") if len(parts) > 1 else ""
    for key, name in PROVIDERS:
        if key in host or (boot and key == boot):
            return name, host
    return host or url, host


# 一轮测速比一屏的耐心长：整池 35 条里常有近 20 条要等满超时才判死，跑完要一分半。
# 同步接口的后果是——点完按钮卡在「测速中…」、两张卡片全空、状态只有一根「—」，
# 看着就像页面坏了；偏偏「每 60 秒自动测」比一轮还短，于是永远等不到头。
# 改成后台线程跑，接口立刻回一张进度快照，前端每 1.5 秒来问一次。
_SPEED_LOCK = threading.Lock()
_DIAG_LOCK = threading.Lock()  # 串行化「重渲染测速入口」这种带 reload 的操作，避免并发重复重载
_SPEED = {
    "running": False, "at": 0, "started": 0, "phase": "",
    "items": [], "counts": {}, "note": "", "done": 0, "total": 0, "retry_left": 0,
}

# 后台定时扫面的运行状态：监测页直接读它把「怎么跑的」写在页面上。
# interval_min 是扫描周期；last_scan_at 是上一轮跑完的时刻；
# last_pruned / last_pruned_lines 是上一轮清掉的不通条目——用户要的是「确认没用的直接删」，
# 不是只标个「不通」，所以这里记下来好让页面/日志说清楚到底删了什么。
_SCAN_INFO = {
    "interval_min": 15,
    "last_scan_at": 0,
    "last_pruned": 0,
    "last_pruned_lines": [],
    "last_error": "",
    "next_at": 0,
}
_DEAD_FILE = os.path.join(DATA_DIR, ".speed_dead.json")


def _speed_snapshot():
    with _SPEED_LOCK:
        snap = dict(_SPEED)
        snap["items"] = list(_SPEED["items"])
        snap["counts"] = dict(_SPEED["counts"])
    snap["scan"] = dict(_SCAN_INFO)
    return snap


def _load_strikes():
    try:
        with open(_DEAD_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_strikes(d):
    try:
        with open(_DEAD_FILE, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False)
    except Exception:
        pass


def _remove_from_pool(side, line):
    """从某一侧的候选池文件里删掉同 URL 的所有行（IP 写法不同也算同一条）。"""
    path = os.path.join(DATA_DIR, "doh_%s_candidates.txt" % side)
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except Exception:
        return False
    url = str(line).split()[0] if line else ""
    if not url:
        return False
    kept, removed_any = [], False
    for ln in lines:
        raw = ln.split("#", 1)[0].strip()
        if not raw:
            kept.append(ln); continue
        if raw.split()[0] == url:
            removed_any = True
            continue
        kept.append(ln)
    if not removed_any:
        return False
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(kept).rstrip() + "\n")
    os.replace(tmp, path)
    return True


def prune_dead():
    """一轮扫完之后：把连续两次都测不通的「候选池」条目直接从清单里删掉。

    只动候选池（公开的那些），不动正在用的上游——在用的由配置页/自动探测管。
    连续两次才删，是给偶发性被墙/抖动留余量，避免把好 DNS 误杀；
    但两次都死就基本可以确定是死了，这种就该从清单消失，别只留下一行「不通」碍眼。
    """
    items = _SPEED.get("items") or []
    if not items:
        return
    strikes = _load_strikes()
    side_of = {}
    for it in items:
        line = it.get("line")
        if not line:
            continue
        side_of[line] = it.get("side")
        if it.get("active"):
            strikes.pop(line, None)
            continue
        if it.get("ok"):
            strikes.pop(line, None)
        else:
            strikes[line] = strikes.get(line, 0) + 1
    removed = []
    for line, n in list(strikes.items()):
        if n >= 2:
            side = side_of.get(line)
            if side and _remove_from_pool(side, line):
                removed.append(line)
                strikes.pop(line, None)
    _save_strikes(strikes)
    if removed:
        # 顺手把 orphan 的测速入口从引擎配置里也清掉（不然端口空挂着）
        try:
            if doh_cfg:
                t = doh_cfg.read_cfg()
                nw = doh_cfg.render_diag(t)
                if nw != t:
                    doh_cfg.write_cfg(nw)
                    doh_cfg.reload_engine(25)
                    time.sleep(2)
        except Exception:
            pass
        # 当前快照里也拿掉，前端下次轮询立刻少一行
        with _SPEED_LOCK:
            drop = set(removed)
            _SPEED["items"] = [x for x in _SPEED["items"] if x.get("line") not in drop]
            _SPEED["counts"] = _speed_counts(_SPEED["items"])
        _SCAN_INFO["last_pruned"] = len(removed)
        _SCAN_INFO["last_pruned_lines"] = removed
    else:
        _SCAN_INFO["last_pruned"] = 0
        _SCAN_INFO["last_pruned_lines"] = []
    _SCAN_INFO["last_scan_at"] = int(time.time())


def _speed_scheduler():
    """后台常驻：每隔 interval_min 分钟扫一遍候选池，死了的自动删。

    不依赖页面开着——关了页面它也在跑，所以「原来这里的 DNS 已经死了」这种事
    一定能被发现，而不是非得有人盯着看才测。"""
    time.sleep(60)  # 启动后先让一让，别和启动期的探测抢资源
    while True:
        try:
            if not _SPEED["running"]:
                diag_speed(refresh=True)
                deadline = time.time() + 300
                while _SPEED["running"] and time.time() < deadline:
                    time.sleep(5)
                # 清理逻辑已在 _speed_worker 收尾时跑过，这里不用再调
        except Exception as e:
            _SCAN_INFO["last_error"] = str(e)
        _SCAN_INFO["next_at"] = int(time.time()) + _SCAN_INFO["interval_min"] * 60
        time.sleep(_SCAN_INFO["interval_min"] * 60)


def _speed_counts(out):
    counts = {}
    for it in out:
        c = counts.setdefault(it["side"], {"total": 0, "active": 0, "alive": 0, "dead": 0})
        c["total"] += 1
        if not it["ok"]:
            c["dead"] += 1
        elif it["active"]:
            c["active"] += 1
        else:
            c["alive"] += 1
    return counts


def _speed_worker(items, qname, act):
    """整池逐条测。先把清单铺成占位行，测完一条填一条，前端能看见进度。"""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    out = []
    for it in items:
        name, host = provider_of(it["line"])
        out.append(dict(it, ok=False, ms=None, answers=0, rcode=None, err="",
                        active=False, provider=name, host=host, pending=True))
    with _SPEED_LOCK:
        _SPEED["items"] = list(out)

    def one(it, timeout):
        r = _dns_udp(it["port"], qname.get(it["side"], "www.baidu.com"), timeout=timeout)
        cur = {str(x).strip() for x in (act.get(it["side"]) or [])}
        name, host = provider_of(it["line"])
        return dict(it, **r, active=(it["line"] in cur), provider=name, host=host, pending=False)

    def flush():
        with _SPEED_LOCK:
            _SPEED["items"] = list(out)
            _SPEED["done"] = sum(1 for x in out if not x.get("pending"))

    try:
        # 并发压到 6：35 条一起抢的时候，每条都要新建 TLS，慢的那几条会被同批的快条目
        # 挤掉——明明能通也报「没响应」，看着就是一屏「不通」，还都是知名公共 DNS。
        with ThreadPoolExecutor(max_workers=6) as ex:
            jobs = {ex.submit(one, it, 5): i for i, it in enumerate(items)}
            for f in as_completed(jobs):
                i = jobs[f]
                try:
                    out[i] = f.result()
                except Exception as e:
                    out[i] = dict(out[i], ok=False, err="测的时候出错了：%s" % e, pending=False)
                flush()

        # 没通的单独再问一次。第一次的「不通」里有相当一部分只是并发抖动
        # （同厂商 4 个入口通 2 个、挂 2 个，或者上一轮 1690ms 这轮超时），
        # 不复测就把它写成「不通」是在骗人。串行复测 19 条要将近两分钟，
        # 改 3 并发；再往上调又开始互相挤，测出来的还是假「不通」。
        retry = [i for i, x in enumerate(out) if not x.get("ok")]
        if retry:
            with _SPEED_LOCK:
                _SPEED["phase"] = "retry"
                _SPEED["retry_left"] = len(retry)
            with ThreadPoolExecutor(max_workers=3) as ex:
                jobs = {ex.submit(one, items[i], 6): i for i in retry}
                for f in as_completed(jobs):
                    i = jobs[f]
                    try:
                        again = f.result()
                    except Exception:
                        again = None
                    if again and again.get("ok"):
                        again["retried"] = True
                        out[i] = again
                    else:
                        out[i] = dict(out[i], pending=False)
                    with _SPEED_LOCK:
                        _SPEED["retry_left"] = max(0, int(_SPEED.get("retry_left") or 0) - 1)
                    flush()
    finally:
        for x in out:
            x["pending"] = False
        with _SPEED_LOCK:
            _SPEED["items"] = list(out)
            _SPEED["counts"] = _speed_counts(out)
            _SPEED["at"] = int(time.time())
            _SPEED["running"] = False
            _SPEED["phase"] = ""
            _SPEED["retry_left"] = 0
            _SPEED["done"] = len(out)
        # 不管这轮是手动点的还是后台定时跑的，扫完都把确认死的候选池条目删掉——
        # 之前只挂在后台调度里，手动点「立即测速」不会清理，等于留个口子。
        prune_dead()


def diag_speed(refresh=False):
    """逐条问 mosdns 自己：这一条上游此刻转发一次要多久。

    测的是整池（候选清单里的每一条），不只是正在用的那几条——
    用户要看的是「都有哪些上游、各自多快」，只给 3 条等于把其余全藏了。
    不由外部直连 DoH：那样测的是「这条外部连接有多快」，与 mosdns 实际
    解析用的连接池、并发策略、缓存都不是一回事。

    接口本身不等结果：没在跑就起一轮后台测，立刻回快照（running=true + 占位清单）。
    """
    # 前端每 1.5 秒问一次进度，这两条快路径不能去碰 config 文件
    snap = _speed_snapshot()
    if snap["running"]:
        return snap
    # 没在跑：只有「手点了立即测速」或者「距上次测完已过 2 分钟」才重新起一轮，
    # 不然页面每次刷新都重测一遍，谁也别想看到稳定的数。
    if not refresh and snap["at"] and time.time() - snap["at"] < 120:
        return snap

    items = ensure_diag_ports()
    if not items:
        return {"running": False, "at": int(time.time()), "items": [], "counts": {},
                "done": 0, "total": 0, "phase": "", "retry_left": 0,
                "note": "测速入口还没有，可能是旧配置；保存一次上游或重启容器后自动生成"}
    with _SPEED_LOCK:
        if _SPEED["running"]:
            return dict(_SPEED)
        _SPEED.update({"running": True, "started": int(time.time()), "phase": "",
                       "items": [], "counts": {}, "note": "", "done": 0,
                       "total": len(items), "retry_left": 0})

    qname = {"local": "www.baidu.com", "remote": "www.google.com"}
    act = doh_cfg.active() if doh_cfg else {"local": [], "remote": []}
    threading.Thread(target=_speed_worker, args=(items, qname, act), daemon=True).start()
    return _speed_snapshot()


def probe_upstreams():
    """恢复自动探测：现场跑一遍候选清单探测（与容器启动同一套逻辑）。"""
    changed = False
    for cand, out, tag in (
        (os.path.join(DATA_DIR, "doh_local_candidates.txt"), "/tmp/lp.txt", "国内"),
        (os.path.join(DATA_DIR, "doh_remote_candidates.txt"), "/tmp/rp.txt", "国外"),
    ):
        if not os.path.exists(cand):
            continue
        try:
            with open(out, "w") as f:
                subprocess.run(["python3", DOH_SELECT, cand, "www.baidu.com" if tag == "国内" else "www.google.com", "3", "6"],
                               stdout=f, stderr=subprocess.DEVNULL, timeout=60)
            block = open(out, encoding="utf-8").read()
        except Exception:
            continue
        if "addr:" not in block:
            continue
        cfg_path = os.path.join(DATA_DIR, "config.yaml")
        with open(cfg_path, encoding="utf-8", errors="replace") as f:
            text = f.read().replace("\r\n", "\n")
        new = _replace_doh_block(text, "forward_local" if tag == "国内" else "forward_remote", block)
        if new != text:
            tmp = cfg_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(new)
            os.replace(tmp, cfg_path)
            changed = True
    if changed:
        try:
            subprocess.run([SCHEDULER, "reload"], capture_output=True, timeout=25)
        except Exception:
            pass
    return changed


def upstreams_payload():
    """概况/配置页共用：当前生效 + 是否手动指定 + 候选池数量。"""
    up = read_upstreams()
    up["mode"] = "manual" if (os.path.exists(DOH_LOCAL_CUSTOM) or os.path.exists(DOH_REMOTE_CUSTOM)) else "auto"
    try:
        for key, name in (("local", "doh_local_candidates.txt"), ("remote", "doh_remote_candidates.txt")):
            with open(os.path.join(DATA_DIR, name), encoding="utf-8") as f:
                up["cand_" + key] = sum(1 for ln in f if ln.strip() and not ln.lstrip().startswith("#"))
    except Exception:
        up["cand_local"] = up.get("cand_local", 0)
        up["cand_remote"] = up.get("cand_remote", 0)
    return up


def read_upstreams():
    """从引擎实际加载的 config.yaml 里读出 DoH 上游。

    读的是渲染后的配置，不是候选清单——候选里几十个地址都「理论上可用」，
    只有这里这几条才是此刻真正在转发的东西。
    """
    try:
        with open(os.path.join(DATA_DIR, "config.yaml"), encoding="utf-8", errors="replace") as f:
            text = f.read()
    except Exception:
        return {"local": [], "remote": [], "ok": False}
    res = {"local": [], "remote": [], "ok": True}
    cur_key, cur = None, None
    for ln in text.splitlines():
        m = re.match(r"\s*-\s+tag:\s*(\S+)", ln)
        if m:
            tag = m.group(1)
            cur_key = "local" if tag == "forward_local" else ("remote" if tag == "forward_remote" else None)
            cur = None
            continue
        if not cur_key:
            continue
        m = re.search(r"-\s+addr:\s*\"?([^\"\s]+)\"?", ln)
        if m:
            cur = {"addr": m.group(1), "dial": ""}
            res[cur_key].append(cur)
            continue
        m = re.search(r"dial_addr:\s*\"?([^\"\s]+)\"?", ln)
        if m and cur:
            cur["dial"] = m.group(1)
    # 补上「主机名 / 直连 IP」两种展示形式：IP 形式的 addr 主机就是 IP，
    # 域名形式要靠 dial_addr 才知道连的是哪个 IP。
    for key in ("local", "remote"):
        for u in res[key]:
            m = re.match(r"https?://([^/]+)", u["addr"])
            u["host"] = m.group(1) if m else u["addr"]
            u["ip"] = u["dial"].rsplit(":", 1)[0] if u.get("dial") else u["host"]
            u["ipv6"] = ":" in u["ip"] and not re.match(r"^\d+\.\d+\.\d+\.\d+$", u["ip"])
            # 概况页每行右侧要写清「这是哪家的」：按主机名 + 落地 IP 认，认不出就留主机名
            u["provider"] = provider_of(u["addr"] + " " + u["ip"])[0]
    return res


_VERSIONS_CACHE = {"at": 0, "data": None}


def read_versions():
    """工具与版本：按「镜像里实际装了什么」来报。

    /app/VERSIONS 是构建时写进去的（CI 每周探测上游最新 release 后传给
    build-arg），所以它就是镜像里装的那个版本；测速器文件不在就直说缺工具，
    不要照抄 versions.env 里「想要」的版本。
    """
    now = int(time.time())
    if _VERSIONS_CACHE["data"] and now - _VERSIONS_CACHE["at"] < 300:
        return _VERSIONS_CACHE["data"]
    build = {}
    try:
        with open("/app/VERSIONS", encoding="utf-8") as f:
            for ln in f:
                if "=" in ln:
                    k, v = ln.strip().split("=", 1)
                    build[k.strip()] = v.strip()
    except Exception:
        pass

    cft_path = "/app/bin/cft/cfst"
    # 版本以构建参数为准（镜像就是按这个 tag 下载的）；文件不在才报缺工具。
    # 不去解析 cfst -v 的输出：它第一行是「检查版本更新中…」，混着日期，
    # 正则抓数字很容易抓错。
    cft_v = build.get("cft", "") if os.path.isfile(cft_path) else ""

    items = [{"label": "mosdns 核心", "ver": build.get("mosdns") or "未知",
              "note": "官方源码编译，DNS 引擎与分流"}]
    # 优选实际都走 common.sh + probe.py 的内置探测，
    # 先把这条写清楚，免得以为跑了一堆外部工具。
    items.append({"label": "优选探测", "ver": "内置脚本", "note": "各路共用，TCP 延迟 + HTTPS 实测"})
    if cft_v:
        items.append({"label": "CloudflareSpeedTest", "ver": cft_v, "note": "已固化，备用测速器"})
    else:
        items.append({"label": "CloudflareSpeedTest", "ver": "缺工具", "note": "镜像内缺失，cf 路回退脚本探测"})
    # GT 只跟踪版本：上游 1.9 起不发 linux 包，gt 路用的是它的社区 IP 清单
    gt_v = build.get("gt") or ""
    if gt_v in ("", "latest"):
        gt_v = "跟随上游"
    items.append({"label": "GoogleTranslateIpCheck", "ver": gt_v,
                  "note": "仅用社区 IP 清单，跟随上游 master"})
    data = {
        "items": items,
        "build_rev": build.get("build_rev", ""),
        "build_date": build.get("build_date", ""),
    }
    _VERSIONS_CACHE.update({"at": now, "data": data})
    return data


def list_update_worker(name):
    try:
        subprocess.run(["python3", LISTS_PY, "update", name], capture_output=True, timeout=240)
        subprocess.run([SCHEDULER, "reload"], capture_output=True, timeout=25)
    except Exception:
        pass


class Handler(BaseHTTPRequestHandler):
    server_version = "pref-ui/1.0"

    # ---------- 工具 ----------
    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False)
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}

    def _cookie(self):
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "pref_session":
                return v
        return ""

    def _authed(self):
        tok = self._cookie()
        with LOCK:
            exp = SESSIONS.get(tok)
            if not exp:
                return False
            if exp < time.time():
                SESSIONS.pop(tok, None)
                return False
            return True

    def _must_change(self, path):
        """还是初始 admin/admin 时，除了登录/状态/改密/退出，其它接口一律拦下。
        这样即使绕过前端直接调接口，也进不去。"""
        if path in ("/api/status", "/api/account", "/api/logout", "/api/login"):
            return False
        try:
            return bool(load_auth()[2])
        except Exception:
            return False

    def log_message(self, fmt, *args):
        pass

    # ---------- 路由 ----------
    def do_GET(self):
        u = urlparse(self.path)
        path = u.path

        if path == "/" or path == "/index.html":
            return self._static("index.html")
        if path.startswith("/static/"):
            return self._static(path[len("/static/"):])
        if path == "/api/login":
            return self._send(405, {"error": "use POST"})

        if path.startswith("/api/"):
            if not self._authed():
                return self._send(401, {"error": "unauthorized"})
            if self._must_change(path):
                return self._send(403, {"error": "首次登录必须修改密码", "must_change": True})
            if path == "/api/status":
                au, _, is_default = load_auth()
                return self._send(200, {
                    "mosdns": mosdns_alive(),
                    "results": read_results(),
                    "settings": read_json(SETTINGS_FILE, {}),
                    "lists_brief": lists_brief(),
                    "upstreams": upstreams_payload(),
                    "doh_scan": doh_scan_brief(),
                    "versions": read_versions(),
                    "auth": {"user": au, "default_pass": is_default},
                    "now": int(time.time()),
                })
            if path == "/api/lists":
                d = lists_status()
                return self._send(200, {"items": d.get("items") or {},
                                        "auto": d.get("sched") or {}})
            if path == "/api/lists/preview":
                q = parse_qs(u.query)
                name = (q.get("name") or [""])[0]
                n = (q.get("n") or ["40"])[0]
                try:
                    res = subprocess.run(
                        ["python3", LISTS_PY, "preview", name, str(int(n))],
                        capture_output=True, timeout=20,
                    )
                    body = res.stdout.decode("utf-8", "replace") or "{}"
                    if res.returncode != 0:
                        return self._send(400, {"error": res.stderr.decode("utf-8", "replace")[:200]})
                    return self._send(200, body)
                except Exception as e:
                    return self._send(500, {"error": str(e)})
            if path == "/api/results":
                return self._send(200, read_results())
            if path == "/api/logs":
                q = parse_qs(u.query)
                n = int((q.get("n") or ["200"])[0])
                src = (q.get("src") or ["pref"])[0]
                f = MOSDNS_OUT if src == "mosdns" else PREF_LOG
                return self._send(200, {"lines": tail(f, n)})
            if path == "/api/lock":
                return self._send(200, {"locked": os.path.isdir(os.path.join(DATA_DIR, ".pref.lock"))})
            if path == "/api/qlog":
                q = parse_qs(u.query)
                try:
                    n = max(1, min(2000, int((q.get("n") or ["30"])[0])))
                except Exception:
                    n = 30
                uniq = (q.get("uniq") or [""])[0] in ("1", "true", "yes")
                try:
                    resolve = max(0, min(60, int((q.get("resolve") or ["0"])[0])))
                except Exception:
                    resolve = 0
                rotate_qlog_if_big()
                return self._send(200, read_qlog(n, uniq, resolve))
            if path == "/api/upstreams":
                return self._send(200, upstreams_payload())
            if path == "/api/diag/speed":
                ref = (parse_qs(u.query).get("refresh") or [""])[0] in ("1", "true", "yes")
                return self._send(200, diag_speed(refresh=ref))
            if path == "/api/cache/info":
                return self._send(200, cache_info())
            if path == "/api/sources":
                return self._send(200, sources_status())
            if path == "/api/push/preview":
                return self._send(200, {"text": push_brief()})
            return self._send(404, {"error": "not found"})

        return self._send(404, {"error": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        path = u.path

        if path == "/api/login":
            data = self._body()
            user, pwd, is_default = load_auth()
            if str(data.get("user", "")) == user and str(data.get("pass", "")) == pwd and pwd != "":
                tok = secrets.token_hex(24)
                with LOCK:
                    SESSIONS[tok] = time.time() + SESSION_TTL
                try:
                    ip = self.client_address[0]
                except Exception:
                    ip = "-"
                threading.Thread(target=push_event, daemon=True, args=(
                    "login", "控制台登录",
                    "账号 %s 于 %s 从 %s 登录" % (user, time.strftime("%Y-%m-%d %H:%M:%S"), ip),
                )).start()
                return self._send(200, {"ok": True, "user": user, "default_pass": is_default}, extra={
                    "Set-Cookie": "pref_session=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=%d" % (tok, SESSION_TTL)
                })
            return self._send(401, {"error": "账号或密码错误"})

        if not self._authed():
            return self._send(401, {"error": "unauthorized"})
        if self._must_change(path):
            return self._send(403, {"error": "首次登录必须修改密码", "must_change": True})

        if path == "/api/logout":
            tok = self._cookie()
            with LOCK:
                SESSIONS.pop(tok, None)
            return self._send(200, {"ok": True}, extra={
                "Set-Cookie": "pref_session=; Path=/; HttpOnly; Max-Age=0"
            })

        if path == "/api/account":
            data = self._body()
            cur_user, cur_pass, _ = load_auth()
            old_pass = str(data.get("old_pass", ""))
            new_user = str(data.get("user", cur_user)).strip()
            new_pass = str(data.get("pass", ""))
            if old_pass != cur_pass:
                return self._send(400, {"error": "当前密码不正确"})
            if not new_user or len(new_user) > 32:
                return self._send(400, {"error": "账号不能为空，且不超过 32 个字符"})
            if len(new_pass) < 4:
                return self._send(400, {"error": "新密码至少 4 位"})
            if len(new_pass) > 64:
                return self._send(400, {"error": "新密码不超过 64 位"})
            if new_pass == "admin":
                return self._send(400, {"error": "别再用 admin 当密码"})
            if new_user == cur_user and new_pass == cur_pass:
                return self._send(400, {"error": "账号和密码都没有变化"})
            saved = save_auth(new_user, new_pass)
            # 旧会话全部失效，仅保留当前这次登录，避免改完密码被踹出去
            tok = self._cookie()
            with LOCK:
                SESSIONS.clear()
                if tok:
                    SESSIONS[tok] = time.time() + SESSION_TTL
            return self._send(200, {"ok": True, "user": saved["user"],
                                    "default_pass": saved["default"], "relogin": False})

        if path == "/api/trigger":
            data = self._body()
            route = str(data.get("route", "all"))
            if route != "all" and route not in ROUTES:
                return self._send(400, {"error": "未知路"})
            if os.path.isdir(os.path.join(DATA_DIR, ".pref.lock")):
                return self._send(409, {"error": "已有优选任务在运行（串行执行）"})
            try:
                subprocess.Popen(
                    [SCHEDULER, "once", route],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
            except Exception as e:
                return self._send(500, {"error": str(e)})
            return self._send(200, {"ok": True, "route": route})

        if path == "/api/resolve":
            data = self._body()
            domain = str(data.get("domain", "")).strip()
            if not re.match(r"^[A-Za-z0-9_.-]{1,253}$", domain):
                return self._send(400, {"error": "非法域名"})
            pairs = dns_lookup(domain)
            items = []
            for ip, fam in pairs[:12]:
                lat = tcp_latency(ip)
                items.append({"ip": ip, "family": fam,
                              "latency": None if lat is None else round(lat, 1)})
            items.sort(key=lambda x: (x["latency"] is None, x["latency"] or 1e9))
            return self._send(200, {"domain": domain, "items": items})

        if path == "/api/lists/update":
            data = self._body()
            name = str(data.get("name", "all"))
            if name != "all" and name not in ("china_ip", "cn_domains", "gfw_domains"):
                return self._send(400, {"error": "未知清单"})
            threading.Thread(target=list_update_worker, args=(name,), daemon=True).start()
            return self._send(200, {"ok": True, "name": name, "started": True})

        if path == "/api/push/test":
            data = self._body()
            url = str(data.get("url", "")).strip()
            if not url.startswith(("http://", "https://")):
                return self._send(400, {"error": "Webhook 地址需以 http:// 或 https:// 开头"})
            brief = push_brief()
            try:
                r = subprocess.run(
                    ["python3", PUSH_PY, url, "测试消息",
                     "这是一条来自控制台的测试推送，收到即说明配置正确。"
                     + ("\n\n当前各路生效 IP：\n" + brief if brief else "")],
                    capture_output=True, timeout=15)
            except Exception as e:
                return self._send(500, {"error": str(e)})
            if r.returncode != 0:
                return self._send(500, {"error": (r.stderr or b"").decode("utf-8", "replace")[:200] or "推送失败"})
            return self._send(200, {"ok": True})

        # ---------- 诊断 ----------
        if path == "/api/diag/ip":
            data = self._body()
            ip = str(data.get("ip", "")).strip()
            if not is_ip(ip):
                return self._send(400, {"error": "请输入合法 IP（支持 IPv4 / IPv6）"})
            return self._send(200, diag_run(["ip", ip], 20))

        if path == "/api/diag/port":
            data = self._body()
            host = str(data.get("host", "")).strip()
            try:
                port = int(data.get("port") or 443)
            except Exception:
                port = 443
            if not (is_ip(host) or re.match(r"^[A-Za-z0-9_.-]{1,253}$", host)):
                return self._send(400, {"error": "请输入合法 IP 或域名"})
            if not (1 <= port <= 65535):
                return self._send(400, {"error": "端口需在 1-65535"})
            return self._send(200, diag_run(["port", host, str(port)], 60))

        if path == "/api/diag/domain":
            data = self._body()
            domain = str(data.get("domain", "")).strip()
            if not re.match(r"^[A-Za-z0-9_.-]{1,253}$", domain):
                return self._send(400, {"error": "非法域名"})
            # 解析只问 127.0.0.1（mosdns 自己），随后逐个 IP 发真实 HTTPS 请求，
            # 「能不能打开」是实测出来的，不是拿两边答案比对推出来的。
            return self._send(200, diag_run(["domain", domain], 90))

        if path == "/api/cache/flush":
            try:
                cache_flush()
            except Exception as e:
                return self._send(500, {"error": "清空失败：%s" % e})
            return self._send(200, {"ok": True, "info": cache_info()})

        if path == "/api/qlog/clear":
            try:
                qlog_clear()
            except Exception as e:
                return self._send(500, {"error": "清空失败：%s" % e})
            return self._send(200, {"ok": True})

        if path == "/api/sources":
            data = self._body()
            r = run_subs(["save"], stdin_data=json.dumps(data).encode("utf-8"))
            return self._send(200 if r.get("ok") else 400, r)

        if path == "/api/sources/add":
            data = self._body()
            name = str(data.get("name") or "").strip()[:60]
            route = str(data.get("route") or "cf").strip()
            if route not in ROUTES:
                route = "cf"
            u4 = str(data.get("url_v4") or "").strip()
            u6 = str(data.get("url_v6") or "").strip()
            inline = str(data.get("inline") or "")
            # 直贴 IP 清单模式：不走网络，只把清单交给 subs 存下来并立刻入池
            if inline.strip():
                args = ["add", name or "手动 IP 清单", "-", "", route]
                r = run_subs(args, stdin_data=inline.encode("utf-8"), timeout=60)
            else:
                r = run_subs(["add", name or "自定义源", u4, u6, route], timeout=60)
            if not r.get("ok"):
                return self._send(400, r)
            # 添加后立刻拉一次：手动添加的源要能马上生效，看到数量
            t = run_subs(["test", r["key"]], timeout=90)
            r["test"] = t
            return self._send(200, r)

        if path == "/api/sources/del":
            key = str(self._body().get("key", ""))
            r = run_subs(["del", key])
            return self._send(200 if r.get("ok") else 400, r)

        if path == "/api/sources/toggle":
            data = self._body()
            key = str(data.get("key", ""))
            on = "1" if data.get("enabled") else "0"
            r = run_subs(["enable", key, on])
            return self._send(200 if r.get("ok") else 400, r)

        if path == "/api/sources/test":
            key = str(self._body().get("key", ""))
            r = run_subs(["test", key], timeout=90)
            return self._send(200, r)

        if path == "/api/sources/pull":
            r = run_subs(["pull", "--force"], timeout=180)
            return self._send(200, r)

        if path == "/api/sources/sync":
            r = run_subs(["sync"], timeout=120)
            return self._send(200, r)

        if path == "/api/sources/discover":
            r = run_subs(["discover", "--force"], timeout=180)
            return self._send(200, r)

        if path == "/api/sources/health":
            # 立即体检：所有源（含停用的第三方）逐个拉一次，只看可用性
            r = run_subs(["health", "--force"], timeout=300)
            return self._send(200, r)

        if path == "/api/sources/prune":
            r = run_subs(["prune"], timeout=60)
            return self._send(200, r)

        if path == "/api/sources/gc":
            # 立即清理：连续失败到阈值的第三方源直接删掉，同时清掉它没验证过的 IP
            r = run_subs(["gc"], timeout=90)
            return self._send(200, r)

        if path == "/api/sources/restore":
            keys = self._body().get("keys") or []
            r = run_subs(["restore"] + [str(k) for k in keys], timeout=60)
            return self._send(200, r)

        if path == "/api/upstreams":
            data = self._body()
            mode = str(data.get("mode") or "manual")
            if mode == "auto":
                # 清掉自定义，现场重新探测（与容器启动同一套逻辑）
                apply_upstreams([], [])
                try:
                    probe_upstreams()
                except Exception as e:
                    return self._send(500, {"error": "重新探测失败：%s" % e})
                return self._send(200, {"ok": True, "upstreams": upstreams_payload(),
                                        "scan": doh_scan_brief()})
            local = [str(x).strip() for x in (data.get("local") or []) if str(x).strip()]
            remote = [str(x).strip() for x in (data.get("remote") or []) if str(x).strip()]
            bad = [x for x in local + remote if not _doh_line_ok(x.split()[0])]
            if bad:
                return self._send(400, {"error": "地址不合法：%s" % bad[0]})
            if not local or not remote:
                return self._send(400, {"error": "国内、国外各至少要有一条（想自动就点「恢复自动探测」）"})
            # 写进配置之前先真连一遍：一条死掉的 DNS 写进去，表现是「控制台一切正常、
            # 但全网解析随机失败」，比直接报错难查得多。
            results = test_upstreams(local, remote) if doh_pb else None
            if results and not data.get("force"):
                fails = test_failures(results)
                if fails:
                    return self._send(409, {"error": "%d 条上游探测不通，未写入" % len(fails),
                                            "results": results})
            changed = apply_upstreams(local, remote)
            return self._send(200, {"ok": True, "changed": changed,
                                    "upstreams": upstreams_payload(), "results": results})

        if path == "/api/upstreams/test":
            data = self._body()
            local = [str(x).strip() for x in (data.get("local") or []) if str(x).strip()]
            remote = [str(x).strip() for x in (data.get("remote") or []) if str(x).strip()]
            bad = [x for x in local + remote if not _doh_line_ok(x.split()[0])]
            if bad:
                return self._send(400, {"error": "地址不合法：%s" % bad[0]})
            results = test_upstreams(local, remote)
            return self._send(200, {"ok": not test_failures(results), "results": results})

        if path == "/api/upstreams/scan":
            # 立即扫一遍候选池（不等定时）：看有没有新可用的、在用的有没有死的
            try:
                r = subprocess.run(["python3", os.path.join(_LIB, "doh_watch.py"), "scan", "--force"],
                                   capture_output=True, timeout=180)
                out = json.loads((r.stdout or b"{}").decode("utf-8", "replace") or "{}")
            except Exception as e:
                return self._send(500, {"error": "扫描失败：%s" % e})
            if out.get("skipped"):
                return self._send(200, {"ok": True, "skipped": True, "reason": out.get("reason"),
                                        "scan": doh_scan_brief(), "upstreams": upstreams_payload()})
            return self._send(200, {"ok": True, "scan": doh_scan_brief(), "raw": out,
                                    "upstreams": upstreams_payload()})

        if path == "/api/upstreams/adopt":
            # 手动模式专用：把扫描发现的「新可用」补进现有清单。
            # 逐条再测一次，只补这次仍然通的——扫描是几分钟前的结果，
            # 拿旧结果直接写配置等于绕过「先测再存」。
            brief = doh_scan_brief()
            up = read_upstreams()
            cur = {"local": [" ".join([u["addr"]] + ([u["ip"]] if u.get("dial") else [])) for u in up["local"]],
                   "remote": [" ".join([u["addr"]] + ([u["ip"]] if u.get("dial") else [])) for u in up["remote"]]}
            have = {x.split()[0] for x in cur["local"] + cur["remote"]}
            cand = [n for n in (brief.get("new") or []) if n.get("line") and n["line"].split()[0] not in have]
            if not cand:
                return self._send(200, {"ok": True, "added": 0, "upstreams": upstreams_payload()})
            checked = test_upstreams([n["line"] for n in cand if (n.get("side") or "remote") == "local"],
                                     [n["line"] for n in cand if (n.get("side") or "remote") == "remote"])
            ok_lines = {r["line"] for k in ("local", "remote") for r in checked.get(k) or [] if r.get("ok")}
            # 同一个 IP 只是换了域名写法（dns.pub / doh.pub、223.5.5.5 / dns.alidns.com）
            # 算同一条，不重复补
            seen_ips = {u.get("ip") for u in up["local"] + up["remote"] if u.get("ip")}
            added, skipped = 0, []
            for n in cand:
                ip = n.get("ip") or ""
                if n["line"] in ok_lines and not (ip and ip in seen_ips):
                    cur[n.get("side") or "remote"].append(n["line"])
                    if ip:
                        seen_ips.add(ip)
                    added += 1
                else:
                    skipped.append(n["line"])
            if not added:
                return self._send(409, {"error": "这几条现在都探测不通，先不补", "results": checked})
            apply_upstreams(cur["local"], cur["remote"])
            # 补完把已补的从「新可用」里去掉，避免界面一直显示同一个数字
            rest = [n for n in (brief.get("new") or []) if n["line"] not in ok_lines]
            try:
                import doh_config as _dc
                with open(_dc.SCAN_FILE, encoding="utf-8") as f:
                    sc = json.load(f)
                sc["new"] = rest
                with open(_dc.SCAN_FILE, "w", encoding="utf-8") as f:
                    json.dump(sc, f, ensure_ascii=False, indent=2)
            except Exception:
                pass
            return self._send(200, {"ok": True, "added": added, "skipped": len(skipped),
                                    "skipped_lines": skipped[:6],
                                    "upstreams": upstreams_payload(), "results": checked})

        if path == "/api/upstreams/add":
            # 监测页「手动添加」：把一条 DoH 上游直接塞进候选池，下一轮扫描就会测它。
            # 只校验格式，不立刻联网测——测速本身是异步的，加了就让它进池子等扫。
            data = self._body()
            side = str(data.get("side") or "remote")
            if side not in ("local", "remote"):
                return self._send(400, {"error": "side 只能是 local / remote"})
            line = str(data.get("line") or "").strip()
            if not line:
                return self._send(400, {"error": "地址不能为空"})
            toks = line.split()
            if not _doh_line_ok(toks[0]):
                return self._send(400, {"error": "地址不合法：%s（要是 https://域名/dns-query 这种）" % toks[0]})
            path_c = os.path.join(DATA_DIR, "doh_%s_candidates.txt" % side)
            try:
                with open(path_c, encoding="utf-8") as f:
                    have = {l.split("#", 1)[0].strip().split()[0] for l in f if l.strip()}
            except Exception:
                have = set()
            if toks[0] in have:
                return self._send(409, {"error": "这条已经在候选池里了", "already": True})
            with open(path_c, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            # 立刻起一轮测速，把新加的也测了（页面上马上能看到它）
            threading.Thread(target=lambda: diag_speed(refresh=True), daemon=True).start()
            return self._send(200, {"ok": True, "side": side, "line": line,
                                    "msg": "已加入候选池，正在测速（看上方列表）"})

        if path == "/api/reload":
            try:
                subprocess.run([SCHEDULER, "reload"], capture_output=True, timeout=20)
            except Exception as e:
                return self._send(500, {"error": str(e)})
            return self._send(200, {"ok": True})

        if path == "/api/settings":
            data = self._body()
            cur = read_json(SETTINGS_FILE, {})
            if isinstance(data.get("interval_min"), (int, float)):
                cur["interval_min"] = max(1, int(data["interval_min"]))
            if "pref_enabled" in data:
                cur["pref_enabled"] = bool(data["pref_enabled"])
            if "watchdog_enabled" in data:
                cur["watchdog_enabled"] = bool(data["watchdog_enabled"])
            if isinstance(data.get("watchdog_sec"), (int, float)):
                cur["watchdog_sec"] = min(3600, max(30, int(data["watchdog_sec"])))
            if isinstance(data.get("threads"), (int, float)):
                cur["threads"] = max(0, int(data["threads"]))
            if "list_auto_update" in data:
                cur["list_auto_update"] = bool(data["list_auto_update"])
                # 老字段同步成新字段，两边永远一致
                cur["list_upd_enabled"] = bool(data["list_auto_update"])
            if "list_upd_enabled" in data:
                cur["list_upd_enabled"] = bool(data["list_upd_enabled"])
                cur["list_auto_update"] = bool(data["list_upd_enabled"])
            if data.get("list_upd_cycle") in ("1h", "2h", "3h", "4h", "6h", "8h",
                                              "12h", "24h", "daily", "weekly"):
                cur["list_upd_cycle"] = data["list_upd_cycle"]
            if isinstance(data.get("list_upd_hour"), (int, float)):
                cur["list_upd_hour"] = min(23, max(0, int(data["list_upd_hour"])))
            if "auto_reload" in data:
                cur["auto_reload"] = bool(data["auto_reload"])
            if isinstance(data.get("list_update_hours"), (int, float)):
                cur["list_update_hours"] = max(1, int(data["list_update_hours"]))
            if isinstance(data.get("top_n"), (int, float)):
                cur["top_n"] = min(8, max(1, int(data["top_n"])))
            # 保底个数：每路至少留几个可用 IP（不足会从池里补历史验证过的）
            if isinstance(data.get("keep_min"), (int, float)):
                cur["keep_min"] = min(8, max(1, int(data["keep_min"])))
            if "ipv6" in data:
                cur["ipv6"] = bool(data["ipv6"])
            if "verify_https" in data:
                cur["verify_https"] = bool(data["verify_https"])
            # 稳定模式的「别重扫」门槛：多久内不重扫 + 慢到什么程度才重扫
            if isinstance(data.get("stable_hours"), (int, float)):
                cur["stable_hours"] = min(72, max(0, int(data["stable_hours"])))
            if isinstance(data.get("stable_ttfb_ms"), (int, float)):
                cur["stable_ttfb_ms"] = min(10000, max(0, int(data["stable_ttfb_ms"])))
            if isinstance(data.get("stable_speed_kbps"), (int, float)):
                cur["stable_speed_kbps"] = min(102400, max(0, int(data["stable_speed_kbps"])))
            if "pref_stable" in data:
                cur["pref_stable"] = bool(data["pref_stable"])
            # 上游 DoH 定时扫描（默认 60 分钟一轮，扫描器自己读这三项，改完立即生效）
            if "doh_scan_enabled" in data:
                cur["doh_scan_enabled"] = bool(data["doh_scan_enabled"])
            if isinstance(data.get("doh_scan_min"), (int, float)):
                cur["doh_scan_min"] = min(1440, max(5, int(data["doh_scan_min"])))
            if isinstance(data.get("doh_keep"), (int, float)):
                cur["doh_keep"] = min(6, max(1, int(data["doh_keep"])))
            if isinstance(data.get("push"), dict):
                p = cur.get("push") or {}
                src = data["push"]
                if "enabled" in src:
                    p["enabled"] = bool(src["enabled"])
                if "url" in src:
                    u = str(src["url"]).strip()
                    if u and not u.startswith(("http://", "https://")):
                        return self._send(400, {"error": "Webhook 地址需以 http:// 或 https:// 开头"})
                    p["url"] = u
                if "events" in src:
                    p["events"] = str(src["events"])
                cur["push"] = p
            if isinstance(data.get("routes"), dict):
                r = cur.get("routes", {})
                for k in ROUTES:
                    if k in data["routes"]:
                        r[k] = bool(data["routes"][k])
                cur["routes"] = r
            write_json(SETTINGS_FILE, cur)
            return self._send(200, {"ok": True, "settings": cur})

        return self._send(404, {"error": "not found"})

    def _static(self, rel):
        rel = rel.lstrip("/")
        full = os.path.normpath(os.path.join(STATIC_DIR, rel))
        if not full.startswith(STATIC_DIR) or not os.path.isfile(full):
            return self._send(404, {"error": "not found"})
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        try:
            with open(full, "rb") as f:
                data = f.read()
        except Exception:
            return self._send(500, {"error": "read error"})
        return self._send(200, data, ctype=ctype)


def main():
    if doh_cfg:
        # 后台定时扫描候选池：死了的自动删，不依赖页面开着
        threading.Thread(target=_speed_scheduler, daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", UI_PORT), Handler)
    print("[ui] listening on 0.0.0.0:%d" % UI_PORT, flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
