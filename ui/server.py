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
import threading
import time
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
SCHEDULER = "/app/scheduler/scheduler.sh"
DNSSQ = "/app/scheduler/lib/dnsq.py"
LISTS_PY = "/app/scheduler/lib/lists.py"
DIAG_PY = "/app/scheduler/lib/diag.py"
PUSH_PY = "/app/scheduler/lib/push.py"
LISTS_META = os.path.join(DATA_DIR, "lists_meta.json")

ROUTES = ["cf", "google", "gt", "github", "ghcr"]
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


def mosdns_alive():
    try:
        with open(MOSDNS_PID) as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def is_ip(s):
    try:
        ipaddress.ip_address((s or "").strip())
        return True
    except Exception:
        return False


def read_results():
    """读每路结果：域名 + 多个 IP（含延迟），兼容旧格式。"""
    out = {}
    for r in ROUTES:
        p = os.path.join(PREF_DIR, "%s.hosts" % r)
        entry = {"domain": "", "ip": "", "ips": [], "mtime": 0}
        lat = {}
        try:
            with open(os.path.join(PREF_DIR, "%s.meta" % r)) as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            st = parts[2] if len(parts) > 2 else ""
                            lat[parts[0]] = (float(parts[1]), st)
                        except Exception:
                            pass
        except Exception:
            pass
        try:
            with open(p) as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2:
                        entry["domain"] = parts[0]
                        ips = []
                        for ip in parts[1:]:
                            if not is_ip(ip):
                                continue
                            lt, st = lat.get(ip, (None, ""))
                            ips.append({
                                "ip": ip,
                                "family": "v6" if ":" in ip else "v4",
                                "latency": lt,
                                "status": st or "ok",
                            })
                        entry["ips"] = ips
                        entry["ip"] = ips[0]["ip"] if ips else ""
                        break
            entry["mtime"] = int(os.path.getmtime(p))
        except Exception:
            pass
        out[r] = entry
    return out


def diag_run(args, timeout=30):
    try:
        r = subprocess.run(["python3", DIAG_PY] + args, capture_output=True, timeout=timeout)
        return json.loads(r.stdout.decode("utf-8", "replace") or "{}")
    except Exception as e:
        return {"error": str(e)}


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
                return self._send(200, {"items": lists_status()})
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
            try:
                r = subprocess.run(
                    ["python3", PUSH_PY, url, "测试消息",
                     "这是一条来自控制台的测试推送，收到即说明配置正确。"],
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
            if isinstance(data.get("threads"), (int, float)):
                cur["threads"] = max(0, int(data["threads"]))
            if "list_auto_update" in data:
                cur["list_auto_update"] = bool(data["list_auto_update"])
            if "auto_reload" in data:
                cur["auto_reload"] = bool(data["auto_reload"])
            if isinstance(data.get("list_update_hours"), (int, float)):
                cur["list_update_hours"] = max(1, int(data["list_update_hours"]))
            if isinstance(data.get("top_n"), (int, float)):
                cur["top_n"] = min(8, max(1, int(data["top_n"])))
            if "ipv6" in data:
                cur["ipv6"] = bool(data["ipv6"])
            if "verify_https" in data:
                cur["verify_https"] = bool(data["verify_https"])
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
