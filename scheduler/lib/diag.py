#!/usr/bin/env python3
# 诊断库（纯标准库）：IP 归属与 CDN 识别 / 端口连通检测 / 域名解析体检
# 用法:
#   python3 diag.py ip <ip>
#   python3 diag.py port <host> <port>
#   python3 diag.py domain <domain>
# 输出: JSON
import ipaddress
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time

DATA_DIR = os.environ.get("PREF_DATA_DIR", "/data")
DNSQ = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dnsq.py")
DNS_PORT = int(os.environ.get("PREF_DNS_PORT", "53"))

# 真实 HTTPS 判定（能不能打开）复用优选那套实现：
# 同一套「SNI + Host + 状态码 + 1034/证书」规则，诊断和优选不会给出两种结论。
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import https_probe
except Exception:
    https_probe = None

# 常见 CDN / 大厂网段（只用于「这是谁的 IP」的粗判，不是权威归属）
CDN = [
    ("Cloudflare", ["104.16.0.0/12", "172.64.0.0/13", "162.158.0.0/15", "173.245.48.0/20",
                    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
                    "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
                    "197.234.240.0/22", "198.41.128.0/17", "131.0.72.0/22"]),
    ("Google", ["142.250.0.0/15", "172.217.0.0/16", "216.58.192.0/19", "74.125.0.0/16",
                "108.177.0.0/17", "209.85.128.0/17", "64.233.160.0/19", "172.253.0.0/16",
                "142.251.0.0/16", "216.239.32.0/19"]),
    ("Fastly", ["151.101.0.0/16", "199.232.0.0/16", "23.235.32.0/20"]),
    ("GitHub", ["140.82.112.0/20", "143.55.64.0/20", "192.30.252.0/22", "20.205.243.0/24",
                "20.200.245.0/24", "20.27.177.0/24"]),
    ("AWS/CloudFront", ["13.32.0.0/15", "52.84.0.0/14", "54.230.0.0/16", "99.86.0.0/16",
                        "13.224.0.0/14", "18.160.0.0/15"]),
    ("Akamai", ["23.32.0.0/11", "104.64.0.0/10", "184.24.0.0/13", "2.16.0.0/13"]),
    ("Microsoft", ["20.0.0.0/8", "13.64.0.0/11", "40.64.0.0/10"]),
]
CDN_NETS = [(name, ipaddress.ip_network(c)) for name, cs in CDN for c in cs]

_cdn_cache = {"mtime": 0, "nets": []}


def cdn_nets():
    """优先读 /data/cdn_ranges.txt（可在线更新），缺失时用内置兜底表。"""
    for p in (os.path.join(DATA_DIR, "cdn_ranges.txt"), "/app/config/cdn_ranges.txt"):
        try:
            mt = os.path.getmtime(p)
        except Exception:
            continue
        if _cdn_cache["mtime"] == mt and _cdn_cache["nets"]:
            return _cdn_cache["nets"]
        nets = []
        try:
            with open(p) as f:
                for line in f:
                    parts = line.split()
                    if len(parts) != 2 or line.lstrip().startswith("#"):
                        continue
                    try:
                        nets.append((parts[0], ipaddress.ip_network(parts[1], strict=False)))
                    except Exception:
                        pass
        except Exception:
            continue
        if nets:
            _cdn_cache["nets"] = nets
            _cdn_cache["mtime"] = mt
            return nets
    return CDN_NETS

_cn_cache = {"mtime": 0, "nets": []}


def cn_nets():
    """读取 /data/china_ip.txt 作为「境内」判定依据（本地，零外网）。"""
    for p in (os.path.join(DATA_DIR, "china_ip.txt"), "/app/config/china_ip.txt"):
        try:
            mt = os.path.getmtime(p)
        except Exception:
            continue
        if _cn_cache["mtime"] == mt and _cn_cache["nets"]:
            return _cn_cache["nets"]
        nets = []
        try:
            with open(p) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        nets.append(ipaddress.ip_network(line, strict=False))
                    except Exception:
                        pass
        except Exception:
            continue
        _cn_cache["nets"] = nets
        _cn_cache["mtime"] = mt
        return nets
    return []


def ip_basic(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return {"ip": ip, "error": "不是合法 IP"}

    out = {"ip": ip, "version": addr.version, "scope": "", "cdn": "", "ptr": "",
           "cn": False, "private": addr.is_private, "loopback": addr.is_loopback}

    if addr.is_private or addr.is_loopback:
        out["scope"] = "内网 / 保留地址"
        return out

    for name, net in cdn_nets():
        try:
            if addr.version == net.version and addr in net:
                out["cdn"] = name
                break
        except Exception:
            pass

    if addr.version == 4:
        cn = False
        for net in cn_nets():
            if net.version != 4:
                continue
            try:
                if addr in net:
                    cn = True
                    break
            except Exception:
                pass
        out["cn"] = cn
        out["scope"] = "中国境内" if cn else "境外"
    else:
        out["scope"] = "IPv6"

    # PTR 反查（限时，避免拖慢页面）
    res = {}

    def job():
        try:
            res["v"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass

    t = threading.Thread(target=job, daemon=True)
    t.start()
    t.join(2.0)
    out["ptr"] = res.get("v", "")

    if out["cdn"]:
        out["desc"] = "%s · %s CDN 节点" % (out["scope"], out["cdn"])
    else:
        out["desc"] = out["scope"]
    return out


def tcp_check(host, port, timeout=3.0, tries=3):
    best = None
    err = ""
    for _ in range(tries):
        fam = socket.AF_INET6 if ":" in host else socket.AF_INET
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = time.time()
        try:
            s.connect((host, port, 0, 0) if fam == socket.AF_INET6 else (host, port))
            dt = (time.time() - t0) * 1000.0
            best = dt if best is None else min(best, dt)
            break
        except Exception as e:
            err = str(e)
        finally:
            try:
                s.close()
            except Exception:
                pass
    return best, err


def icmp_ping(host, count=3, timeout=1.5):
    """原始套接字 ICMP；无权限时返回 None。"""
    try:
        addr = socket.gethostbyname(host)
    except Exception:
        return None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except Exception:
        return None
    s.settimeout(timeout)

    def cksum(data):
        if len(data) % 2:
            data += b"\x00"
        total = 0
        for i in range(0, len(data), 2):
            total += (data[i] << 8) + data[i + 1]
        total = (total >> 16) + (total & 0xFFFF)
        total += total >> 16
        return (~total) & 0xFFFF

    ok = 0
    rtts = []
    pid = os.getpid() & 0xFFFF
    try:
        for seq in range(count):
            payload = struct.pack("!d", time.time()) + b"mosdns-pref"
            header = struct.pack("!BBHHH", 8, 0, 0, pid, seq)
            pkt = struct.pack("!BBHHH", 8, 0, cksum(header + payload), pid, seq) + payload
            t0 = time.time()
            s.sendto(pkt, (addr, 0))
            deadline = t0 + timeout
            while time.time() < deadline:
                try:
                    data, _ = s.recvfrom(1024)
                except socket.timeout:
                    break
                if len(data) >= 28 and data[0] in (0, 0x45, 0x60):
                    off = (data[0] & 0x0F) * 4 if data[0] != 0 else 20
                    if len(data) > off and data[off] == 0:
                        ok += 1
                        rtts.append((time.time() - t0) * 1000.0)
                        break
            time.sleep(0.15)
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass
    if not rtts and ok == 0:
        return {"sent": count, "recv": 0, "loss": 100.0, "rtt_min": None, "rtt_avg": None}
    rtt_min = min(rtts) if rtts else None
    rtt_avg = sum(rtts) / len(rtts) if rtts else None
    return {"sent": count, "recv": ok, "loss": round((1 - ok / float(count)) * 100, 1),
            "rtt_min": None if rtt_min is None else round(rtt_min, 1),
            "rtt_avg": None if rtt_avg is None else round(rtt_avg, 1)}


def udp_check(host, port, tries=3, timeout=1.0):
    """UDP 无连接语义：只要内核不立刻回报不可达，就视为「可发送」。"""
    try:
        addr = socket.getaddrinfo(host, port, 0, socket.SOCK_DGRAM)[0]
    except Exception as e:
        return {"ok": False, "note": "解析失败：%s" % e}
    sent = 0
    refused = 0
    for _ in range(tries):
        fam, _, _, _, sa = addr
        s = socket.socket(fam, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(b"\x00" * 16, sa)
            sent += 1
        except OSError as e:
            if getattr(e, "errno", 0) == 111:
                refused += 1
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass
        time.sleep(0.1)
    return {"ok": sent > 0 and refused == 0, "sent": sent, "refused": refused,
            "note": "UDP 无握手，仅验证可发送" if refused == 0 else "对端端口不可达（ICMP）"}


def port_check(host, port):
    out = {"host": host, "port": port}
    out["icmp"] = icmp_ping(host, 3, 1.5)
    tcp_ms, err = tcp_check(host, port, 3.0, 3)
    out["tcp"] = {"ok": tcp_ms is not None,
                  "ms": None if tcp_ms is None else round(tcp_ms, 1),
                  "error": err}
    out["udp"] = udp_check(host, port, 3)
    if out["icmp"] is None:
        out["note"] = "ICMP 需要容器以 root/原始套接字运行，已跳过"
    return out


def dns_lookup(domain):
    try:
        res = subprocess.run(["python3", DNSQ, "127.0.0.1", str(DNS_PORT), domain, "ALL"],
                             capture_output=True, timeout=6)
        return [l.strip() for l in res.stdout.decode("utf-8", "replace").splitlines() if l.strip()]
    except Exception:
        return []


def domain_check(domain):
    """解析 + 逐个真打开。

    解析只问 127.0.0.1（就是 mosdns 自己），拿到的就是用户此刻真实会得到的 IP；
    然后对每个 IP 发一次真实 HTTPS 请求（SNI/Host 都是这个域名），
    看它到底能不能打开——TCP 握手成功不代表能打开（1034、证书错、5xx 全是握手成功）。
    """
    ips = dns_lookup(domain)
    items = []
    if not ips:
        return {"domain": domain, "count": 0, "items": [], "ok_count": 0,
                "verdict": "nxdomain", "verdict_note": "mosdns 没有解析出任何 A/AAAA 记录"}

    def one(ip):
        b = ip_basic(ip)
        st, ttfb = "fail", None
        if https_probe is not None:
            try:
                _ip, st, ttfb, _sp, _est = https_probe.check(ip, domain, 443, 5.0, 1, "/")
            except Exception:
                st = "fail"
        else:
            # 没有 https_probe 时退回 TCP 握手（只能说通，不保证能打开）
            lat, _ = tcp_check(ip, 443, 2.5, 1)
            st = "ok" if lat is not None else "timeout"
            ttfb = lat
        return {
            "ip": ip,
            "family": "v6" if ":" in ip else "v4",
            "scope": b.get("scope", ""),
            "cdn": b.get("cdn", ""),
            "ptr": b.get("ptr", ""),
            "state": st,
            "ok": st == "ok",
            "latency": None if ttfb is None else round(ttfb, 1),
        }

    try:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=6) as ex:
            items = list(ex.map(one, ips[:20]))
    except Exception:
        items = [one(ip) for ip in ips[:20]]

    ok = [x for x in items if x["ok"]]
    items.sort(key=lambda x: (not x["ok"], x["latency"] is None, x["latency"] or 1e9))
    if ok:
        verdict = "usable"
        note = "%d 个 IP 里 %d 个能真实打开，最快 %sms" % (len(items), len(ok), int(ok[0]["latency"] or 0))
    else:
        verdict = "unusable"
        note = ("解析出来的 %d 个 IP 没有一个能打开（%s）——要么被污染成假 IP，要么这张网络到它不通"
                % (len(items), items[0]["state"] if items else "无"))
    return {"domain": domain, "count": len(items), "items": items,
            "ok_count": len(ok), "verdict": verdict, "verdict_note": note}


def main():
    if len(sys.argv) < 3:
        print(json.dumps({"error": "用法: diag.py ip|port|domain ..."}))
        return
    cmd = sys.argv[1]
    if cmd == "ip":
        out = ip_basic(sys.argv[2])
    elif cmd == "port":
        out = port_check(sys.argv[2], int(sys.argv[3]))
    elif cmd == "domain":
        out = domain_check(sys.argv[2])
    else:
        out = {"error": "未知命令"}
    print(json.dumps(out, ensure_ascii=False))


if __name__ == "__main__":
    main()
