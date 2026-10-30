#!/usr/bin/env python3
"""api.github.com 固定映射自愈。

为什么存在：github 优选池里的 IP 是「网页边缘」，对 API 路径回 301 踢到
github.com 网页端，App 的 API 请求全被带偏（表现为 429/410 报错页）。
全网段里只有少数 IP 真承载 API，所以这里不依赖池子，而是：

  1. 向多个公共 DNS 解析 api.github.com，拿候选 IP（官方动态出口）；
  2. 加上已知可用种子（上一次验证过的 IP）；
  3. 逐个真实验证 GET /rate_limit 必须 200 且 body 含 "limit"（API 专属应答，
     网页边缘给不出来——301 跳走没有这个 body）；
  4. 取最快的 2 个写入 <PREF_DIR>/.github.extra，供 github_pref 每轮追加。

每轮 github 优选前跑一次，IP 失效/被限流自动换新，无需人工干预。
用法: python3 api_pin_refresh.py /data/prefs/.github.extra
"""
import json
import socket
import ssl
import struct
import sys
import time

SEEDS = ["140.82.116.6", "20.205.243.168"]   # 2026-10-30 验证过的真 API 边缘
RESOLVERS = ["223.5.5.5", "119.29.29.29", "180.76.76.76"]
DOMAIN = "api.github.com"
PROBE_PATH = "/rate_limit"
NEEDLE = b"limit"
TIMEOUT = 6.0
KEEP = 2


def dns_a(name, server):
    """极简 A 记录查询（不信包头计数，逐条解析到包尾——爱快那坑的教训）。"""
    try:
        q = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
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


def probe_api(ip):
    """返回 TTFB ms；只有「200 且 body 含 needle」才算 API 边缘，否则 None。"""
    t0 = time.time()
    try:
        s = socket.create_connection((ip, 443), timeout=TIMEOUT)
        ctx = ssl.create_default_context()
        ss = ctx.wrap_socket(s, server_hostname=DOMAIN)
        ss.sendall((
            "GET %s HTTP/1.1\r\nHost: %s\r\n"
            "User-Agent: Mozilla/5.0 (compatible; mosdns-pref/1.0)\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n" % (PROBE_PATH, DOMAIN)
        ).encode())
        buf = b""
        while len(buf) < 65536:
            d = ss.recv(8192)
            if not d:
                break
            buf += d
            if b"\r\n\r\n" in buf and NEEDLE in buf:
                break
        ss.close()
    except Exception:
        return None
    if not buf.startswith(b"HTTP/"):
        return None
    status = int(buf.split(b" ", 2)[1]) if b" " in buf else 0
    if status != 200 or NEEDLE not in buf:
        return None
    return (time.time() - t0) * 1000.0


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else ".github.extra"
    cands = []
    for r in RESOLVERS:
        for ip in dns_a(DOMAIN, r):
            if ip not in cands:
                cands.append(ip)
    for ip in SEEDS:
        if ip not in cands:
            cands.append(ip)
    if not cands:
        print("no candidates, keep existing file")
        return
    results = []
    for ip in cands:
        ttfb = probe_api(ip)
        if ttfb is not None:
            results.append((ttfb, ip))
    results.sort()
    good = [ip for _t, ip in results[:KEEP]]
    if not good:
        # 全挂了：保留旧文件不动（里面还有种子 IP 可用），并报警告
        print("WARN: no IP passed API validation, keeping existing pins")
        return
    with open(out, "w") as f:
        f.write("%s %s\n" % (DOMAIN, " ".join(good)))
    # 登记黑名单豁免：这些 IP 可能因「对 github.com 网页 blocked」被主优选
    # 拉黑，但它们对 api.github.com 是真 API 边缘（刚验证过 /rate_limit=200）。
    try:
        import pin_exempt
        pin_exempt.update(DOMAIN, good)
    except Exception:
        pass
    print("api pins refreshed: %s (ttfb %s ms)" % (
        " ".join(good), "/".join("%.0f" % t for t, _i in results[:KEEP])))


if __name__ == "__main__":
    main()
