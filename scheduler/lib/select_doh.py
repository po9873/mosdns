#!/usr/bin/env python3
# ============================================================
# 本地探测候选 DoH 清单，自动选用「当地真正能通」的上游。
#
# 设计原则（与用户要求一致）：
#   1) 不写死：到底用哪个 DoH，完全由本机探测结果决定，不依赖任何内置默认值。
#   2) 检测源可更新：候选清单是 /data 下的文本文件，用户随时可改、可增删，
#      镜像只负责在文件缺失时补齐一份默认清单，绝不覆盖用户已修改的版本。
#   3) 以当地为准：探测在容器内（mosdns 的真实出网路径）执行，连得上/连不上
#      都是当地网络的真实情况，探测不到就如实报「无可用上游」。
#
# 用法: select_doh.py <候选文件> <探测域名> <最多保留数> [超时秒]
#   候选文件每行: <url> [连接IP]   # 注释以 # 开头
#     - url 形如 https://host/path 或 https://ip/path
#     - 连接IP 可选：实际连接的 IP（TLS 的 SNI 仍用域名，等价 mosdns 的 dial_addr）
# 输出: 每个可用候选输出一段 YAML（缩进 8 空格，可直接替换 config 模板里的占位行）
#   - addr: "https://host/dns-query"
#     dial_addr: "1.2.3.4:443"
#     insecure_skip_verify: true
#   一个都没探测到时：输出第一行候选作为「尽力兜底」并在 stderr 告警，保证配置仍合法。
# ============================================================
import sys, socket, ssl, re, time, struct, concurrent.futures

def parse(line):
    line = line.split("#", 1)[0].strip()
    if not line:
        return None
    parts = line.split()
    url = parts[0]
    boot = parts[1] if len(parts) > 1 else None
    return url, boot

def host_of(url):
    m = re.match(r"https?://([^/]+)(/.*)?$", url)
    if not m:
        return None, None
    return m.group(1), (m.group(2) or "/dns-query")

def dns_query(name, qtype=1):
    """构造标准 DNS 查询报文（wire 格式），与 mosdns 实际发送的一致。"""
    hdr = struct.pack(">HHHHHH", 0x2F2F, 0x0100, 1, 0, 0, 0)
    qd = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".") if p) + b"\x00"
    return hdr + qd + struct.pack(">HH", qtype, 1)

def probe(url, boot, test_domain, timeout):
    """返回 (ok, 延迟ms) 或 (False, None)。"""
    host, path = host_of(url)
    if not host:
        return False, None
    ip = boot or host
    body = dns_query(test_domain)
    t0 = time.time()
    s = None
    try:
        ctx = ssl._create_unverified_context()  # 跳过证书：用 IP/自签时证书必然对不上
        s = socket.socket()
        s.settimeout(timeout)
        ss = ctx.wrap_socket(s, server_hostname=host)  # SNI 用 host（与 mosdns 行为一致）
        ss.connect((ip, 443))
        req = (
            "POST %s HTTP/1.1\r\nHost: %s\r\n"
            "Content-Type: application/dns-message\r\n"
            "Accept: application/dns-message\r\n"
            "Content-Length: %d\r\nConnection: close\r\n\r\n"
        ) % (path, host, len(body))
        ss.sendall(req.encode() + body)
        data = b""
        while True:
            d = ss.recv(4096)
            if not d:
                break
            data += d
            if len(data) > 8192:
                break
        dt = (time.time() - t0) * 1000.0
        # 严格判定：必须是「真的能解析」的上游，而不是只要回了个 HTTP 200。
        head, _, payload = data.partition(b"\r\n\r\n")
        if b" 200" not in head.split(b"\r\n")[0]:
            return False, None
        if len(payload) >= 12:
            flags = (payload[2] << 8) | payload[3]
            rcode = flags & 0xF
            ancount = (payload[6] << 8) | payload[7]
            if rcode == 0 and ancount >= 1:
                return True, dt
        return False, None
    except Exception:
        return False, None
    finally:
        try:
            if s:
                s.close()
        except Exception:
            pass

def main():
    if len(sys.argv) < 4:
        sys.stderr.write("用法: select_doh.py <候选文件> <探测域名> <最多保留数> [超时秒]\n")
        sys.exit(2)
    path, test_domain, max_n = sys.argv[1], sys.argv[2], int(sys.argv[3])
    timeout = float(sys.argv[4]) if len(sys.argv) > 4 else 8
    max_n = min(max(max_n, 1), 5)

    cands = []
    try:
        with open(path, encoding="utf-8") as f:
            for ln in f:
                p = parse(ln)
                if p:
                    cands.append(p)
    except FileNotFoundError:
        sys.stderr.write("候选文件不存在: %s\n" % path)
        sys.exit(3)

    if not cands:
        sys.stderr.write("候选清单为空: %s\n" % path)
        sys.exit(4)

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(20, len(cands))) as ex:
        futs = {ex.submit(probe, u, b, test_domain, timeout): (u, b) for u, b in cands}
        for fu in concurrent.futures.as_completed(futs):
            u, b = futs[fu]
            ok, ms = fu.result()
            if ok:
                results.append({"url": u, "boot": b, "ms": ms})

    results.sort(key=lambda x: x["ms"])
    chosen = results[:max_n]

    if not chosen:
        # 尽力兜底：保留第一个候选，保证 mosdns 配置合法（但会在日志告警）
        u, b = cands[0]
        sys.stderr.write("⚠ 当地未探测到任何可用 DoH（%s），用首个候选兜底，但解析可能失败\n" % path)
        chosen = [{"url": u, "boot": b, "ms": 0}]

    for r in chosen:
        print('        - addr: "%s"' % r["url"])
        if r["boot"]:
            # mosdns 的 bootstrap 是「用来解析域名的 DNS 服务器」，不是「连接用的 IP」。
            # 要让「SNI 用域名、实际连指定 IP」必须用 dial_addr（实测 bootstrap 会导致
            # 上游拿不到响应，最终被 mosdns 回成 REFUSED）。
            print('          dial_addr: "%s:443"' % r["boot"])
        print("          insecure_skip_verify: true")

if __name__ == "__main__":
    main()
