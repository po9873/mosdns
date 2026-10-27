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
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

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


def read_qlog(limit=30):
    """从 mosdns 日志尾部解析 query_summary，返回最近若干条 + 命中统计。"""
    lines = tail(MOSDNS_LOG, 2000)
    items = []
    for ln in lines:
        if "query summary" not in ln:
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
        ms = None
        try:
            ms = round(float(d.get("elapsed", 0)) * 1000.0, 1)
        except Exception:
            pass
        rcode = d.get("rcode")
        clock = ""
        head = ln.split("\t", 1)[0]
        if "T" in head:
            clock = head.split("T", 1)[1][:8]
        items.append({
            "time": clock,
            "qname": qname,
            "qtype": QTYPE.get(d.get("qtype"), str(d.get("qtype", ""))),
            "rcode": rcode,
            "status": RCODE.get(rcode, "无响应" if rcode is None else "异常"),
            "ms": ms,
            "cached": bool(ms is not None and ms <= CACHE_MS),
            "client": str(d.get("client", "")).rsplit(":", 1)[0],
        })
    recent = items[-limit:][::-1]
    total = len(items)
    vals = [x["ms"] for x in items if x["ms"] is not None]
    cached_n = sum(1 for x in items if x["cached"])
    failed_n = sum(1 for x in items if x["rcode"] not in (0, None))
    # 规则命中情况：域名写进了优选 hosts 就是被规则覆盖，否则走上游解析。
    # 只看「几路成功」看不出效果，这里把命中/没命中分别计数。
    pref = pref_domains()
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


def lists_brief():
    """概况页用的轻量摘要：元数据优先，缺失则现数（8000 行约几毫秒）。"""
    m = read_json(LISTS_META, {}).get("china_ip", {})
    lines = m.get("lines") or count_lines(os.path.join(DATA_DIR, "china_ip.txt"))
    return {
        "china_ip": {
            "lines": lines,
            "updated_at": m.get("updated_at", 0),
            "status": m.get("status", ""),
            "source_host": m.get("source", ""),
        }
    }


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
                    n = max(1, min(200, int((q.get("n") or ["30"])[0])))
                except Exception:
                    n = 30
                rotate_qlog_if_big()
                return self._send(200, read_qlog(n))
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
            return self._send(200, diag_run(["domain", domain], 60))

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
    srv = ThreadingHTTPServer(("0.0.0.0", UI_PORT), Handler)
    print("[ui] listening on 0.0.0.0:%d" % UI_PORT, flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
