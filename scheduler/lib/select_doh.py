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
#   候选文件每行: <url> [bootstrap_ip]   # 注释以 # 开头
#     - url 形如 https://host/path 或 https://ip/path
#     - bootstrap_ip 可选：指定实际连接的 IP（避免再用 DNS 解析 host 造成自循环）
# 输出: 每个可用候选输出一段 YAML（缩进 8 空格，可直接替换 config 模板里的占位行）
#   - addr: "https://host/dns-query"
#     bootstrap: "1.2.3.4"
#     insecure_skip_verify: true
#   一个都没探测到时：输出第一行候选作为「尽力兜底」并在 stderr 告警，保证配置仍合法。
# ============================================================
import sys, socket, ssl, re, time, concurrent.futures

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

def probe(url, boot, test_domain, timeout):
    """返回 (ok, 延迟ms) 或 (False, None)。"""
    host, path = host_of(url)
    if not host:
        return False, None
    ip = boot or host
    q = path + ("?" if "?" not in path else "&") + "name=%s&type=A" % test_domain
    t0 = time.time()
    s = None
    try:
        ctx = ssl._create_unverified_context()  # 跳过证书：用 IP/自签时证书必然对不上
        s = socket.socket()
        s.settimeout(timeout)
        ss = ctx.wrap_socket(s, server_hostname=host)  # SNI 用 host（与 mosdns 行为一致）
        ss.connect((ip, 443))
        req = (
            "GET %s HTTP/1.1\r\nHost: %s\r\n"
            "Accept: application/dns-json\r\nConnection: close\r\n\r\n"
        ) % (q, host)
        ss.sendall(req.encode())
        data = b""
        while True:
            d = ss.recv(4096)
            if not d:
                break
            data += d
            if len(data) > 4096:
                break
        dt = (time.time() - t0) * 1000.0
        text = data.decode("utf-8", "replace")
        # 只要服务端回了 HTTP（哪怕查询格式不被认可也说明「当地能连上」），就算可达；
        # 能解析出 A 记录则更优，但不强制——mosdns 自身会用标准 wire 格式通信。
        if "HTTP/" in text[:200] or '"Answer"' in text:
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
            print('          bootstrap: "%s"' % r["boot"])
        print("          insecure_skip_verify: true")

if __name__ == "__main__":
    main()
