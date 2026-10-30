#!/usr/bin/env python3
"""github 资源域名（Fastly 承载）per-domain 优选。

背景：github 路的 best IP 是按 github.com 主域校验选出来的（网页边缘
140.82.x），而 avatars/raw/objects 等资源域由 Fastly（151.101.x / 185.199.x）
承载——用网页边缘 IP 映射资源域必然 301 跳走。以前这些域名的 pin 全是
「跳走检测漏放行」的 bug 产物，检测修严之后它们会全部撤下回退上游解析。

所以资源域名必须各自独立选 IP：本脚本对每个域名用「真实资源路径 + 专属
判定码」逐候选验证（根路径在真边缘上也有各自的正常状态码：403/404/400），
只有真正服务该域名的 Fastly 边缘才会被写进固定映射。

用法: fastly_pin_refresh.py OUT_FILE
输出: 每行「域名 ip1 ip2 ...」（每域名最多 4 个，按 TTFB 升序）。
      某域名一个都选不出来时保留旧文件里它的行（失效回退）。
"""
import json
import os
import re
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import subs  # noqa: E402
import pin_exempt  # noqa: E402

DATA_DIR = "/data"
PREF_DIR = os.path.join(DATA_DIR, "prefs")

# 判定表：域名 → (探测路径, 允许的状态码集合, 允许的 3xx 跳转目标 host 集合)
# 根路径 403/404/400 是该域名对「没有具体资源」的正常应答（服务在），
# 而不服务该域名的边缘一律 301 跳 github.com——一个 404 路径就能分开真假。
# 实测（2026-10）：codeload/collector 也是 Fastly 承载（140.82 网页边缘对
# 它们连不存在的 repo 都 301 踢走，Fastly 边缘回 404）。
DOMAIN_SPECS = {
    "avatars.githubusercontent.com": ("/u/1?v=4", {200}, set()),
    "raw.githubusercontent.com": ("/torvalds/linux/master/README", {200}, set()),
    "user-images.githubusercontent.com": ("/", {403}, set()),
    "objects.githubusercontent.com": ("/", {404}, set()),
    "pkg-containers.githubusercontent.com": ("/", {400}, set()),
    "camo.githubusercontent.com": ("/", {404}, set()),
    # gist 真边缘对 / 官方 301 → gist.github.com；假边缘 301 → github.com
    "gist.githubusercontent.com": ("/", {200}, {"gist.github.com"}),
    # 不存在的 repo/路径：真边缘（Fastly）回 404，网页边缘 301 踢 github.com
    "codeload.github.com": ("/xyz-notexist-abc/nope/tar.gz/master", {404}, set()),
    "collector.github.com": ("/xyz-notexist-abc", {404}, set()),
}

# Fastly 给 github 资源域的已知 anycast 变体（.133=Pages/raw 段，.217=资源段）
SAMPLE_IPS = [
    "151.101.%d.%d" % (octet, last)
    for octet in (0, 1, 2, 64, 65, 66, 128, 129, 130, 192, 193, 194)
    for last in (133, 217)
] + ["185.199.%d.133" % n for n in (108, 109, 110, 111)]

PUBLIC_DNS = ("223.5.5.5", "119.29.29.29", "180.76.76.76")
TIMEOUT = 6.0
TOP_N = 6          # Fastly anycast 变体波动大（同一 IP 时通时断），多点冗余
RETRIES = 2        # 单次超时可能是抖动，每个候选最多试两次
WORKERS = 16

# 「301 踢走」IP 缓存（本进程内共享）：不服务某个资源域的边缘，对其它资源域
# 也是同一套 301 → github.com 的踢法，测一次就知道，后面全部域名直接跳过。
_KICK = set()


def _is_kick_ip(ip):
    return ip in _KICK

LOC_RE = re.compile(r"(?im)^location:\s*(\S+)")


def log(msg):
    sys.stderr.write("[fastly-pin] %s\n" % msg)


def banned_ips():
    try:
        bl = json.load(open(os.path.join(DATA_DIR, "blacklist.json")))
        now = time.time()
        return {ip for ip, v in bl.items() if (v.get("until") or 0) > now}
    except Exception:
        return set()


def udp_dns_a(name, server):
    """向公共 DNS 发 UDP A 查询，返回 IP 列表（爱快应答头不可信的老教训：
    不信 qd/an 计数，逐条解析到包尾）。"""
    import struct
    import random
    tid = random.randint(0, 65535)
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        s.sendto(q, (server, 53))
        data, _ = s.recvfrom(2048)
    except Exception:
        return []
    finally:
        s.close()
    ips = []
    # 跳过头部(12) + 问题段
    off = 12
    while off < len(data) and data[off] != 0:
        off += data[off] + 1
    off += 5
    while off + 12 <= len(data):
        # 名字可能是压缩指针
        if data[off] & 0xC0 == 0xC0:
            off += 2
        else:
            while off < len(data) and data[off] != 0:
                off += data[off] + 1
            off += 1
        if off + 10 > len(data):
            break
        rtype, _, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rd = data[off:off + rdlen]
        off += rdlen
        if rtype == 1 and rdlen == 4:
            ips.append(socket.inet_ntoa(rd))
    return ips


def candidates():
    bad = banned_ips()
    out = []
    seen = set()
    for ip in SAMPLE_IPS:
        if ip not in bad and ip not in seen:
            seen.add(ip)
            out.append(ip)
    # 公共 DNS 解析资源域（污染了也没关系，后面逐个实测，假的通不过）
    for dom in ("raw.githubusercontent.com", "avatars.githubusercontent.com",
                "objects.githubusercontent.com"):
        for srv in PUBLIC_DNS:
            for ip in udp_dns_a(dom, srv):
                if ip not in bad and ip not in seen:
                    seen.add(ip)
                    out.append(ip)
    # github 池子全量兜底
    try:
        for ip in subs.cmd_pool("github", 2000):
            if ip not in bad and ip not in seen:
                seen.add(ip)
                out.append(ip)
    except Exception:
        pass
    return out


def check(ip, domain, path, ok_codes, ok_jump):
    """对 ip+域名 发 HTTPS GET，返回 (ip, ok?, ttfb_ms)。"""
    t0 = time.time()
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    try:
        s = socket.create_connection((ip, 443), timeout=TIMEOUT)
        s.settimeout(TIMEOUT)
        ss = ctx.wrap_socket(s, server_hostname=domain)
        req = ("GET %s HTTP/1.1\r\nHost: %s\r\n"
               "User-Agent: Mozilla/5.0\r\nAccept: */*\r\n"
               "Connection: close\r\n\r\n" % (path, domain))
        ss.sendall(req.encode())
        buf = b""
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = ss.recv(4096)
            if not chunk:
                break
            head += chunk
            if len(head) > 65536:
                break
        ss.close()
    except Exception:
        return ip, False, None
    ttfb = int((time.time() - t0) * 1000)
    m = re.match(r"^HTTP/1\.[01]\s+(\d{3})", head.decode("utf-8", "replace"))
    if not m:
        return ip, False, ttfb
    status = int(m.group(1))
    if status in ok_codes:
        return ip, True, ttfb
    if status in (301, 302, 303, 307, 308):
        lm = LOC_RE.search(head.decode("utf-8", "replace"))
        if lm:
            host = lm.group(1).strip().split("://", 1)[-1].split("/", 1)[0]
            host = host.split(":", 1)[0].strip(".").lower()
            if ok_jump and host in ok_jump:
                return ip, True, ttfb
            if host == "github.com":
                # 踢到主站 = 这个边缘不服务资源域名，缓存起来后面所有域名免测
                _KICK.add(ip)
    return ip, False, ttfb


def check_retry(ip, domain, path, ok_codes, ok_jump):
    """失败重试：Fastly 变体抖动大，同一 IP 一秒内时通时断很常见。"""
    if _is_kick_ip(ip):
        return ip, False, None
    ip, ok, ttfb = check(ip, domain, path, ok_codes, ok_jump)
    for _ in range(RETRIES - 1):
        if ok or _is_kick_ip(ip):
            return ip, ok, ttfb
        ip, ok, ttfb = check(ip, domain, path, ok_codes, ok_jump)
    return ip, ok, ttfb


def main():
    out_file = sys.argv[1] if len(sys.argv) > 1 else os.path.join(PREF_DIR, ".github.fastly")
    cands = candidates()
    log("候选 %d 个，开始逐域名校验" % len(cands))
    results = {}   # domain -> [(ttfb, ip)]
    for dom, (path, codes, jumps) in DOMAIN_SPECS.items():
        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            rs = list(ex.map(lambda c: check_retry(c, dom, path, codes, jumps), cands))
        oks = sorted(((t, ip) for ip, ok, t in rs if ok and t is not None))
        results[dom] = [ip for _, ip in oks[:TOP_N]]
        log("%s: %d/%d 通过 -> %s" % (dom, len(results[dom]), len(cands), results[dom]))
    # 失效回退：选不出来的域名沿用旧文件里它的行
    old = {}
    try:
        for ln in open(out_file, encoding="utf-8", errors="replace"):
            p = ln.split()
            if len(p) >= 2:
                old[p[0]] = p[1:]
    except Exception:
        pass
    lines = []
    for dom in DOMAIN_SPECS:
        ips = results.get(dom) or old.get(dom) or []
        if ips:
            lines.append(" ".join([dom] + ips))
            # 登记黑名单豁免（专属探针刚验证过才登记；沿用旧结果时保留旧豁免）
            if results.get(dom):
                try:
                    pin_exempt.update(dom, results[dom])
                except Exception:
                    pass
        else:
            log("警告: %s 一个可用 IP 都没有，本轮不写它的固定行" % dom)
    tmp = out_file + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))
    os.replace(tmp, out_file)
    print(json.dumps({"domains": len(lines)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
