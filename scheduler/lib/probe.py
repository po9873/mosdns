#!/usr/bin/env python3
# 并发 TCP 连接延迟探测（纯标准库）
# 用法: python3 probe.py <port> <timeout_sec> <concurrency>
# 输入: stdin 每行一个 IP
# 输出: "ip latency_ms" 按延迟升序（仅输出成功项）
import concurrent.futures
import socket
import sys
import time


def probe(ip, port, timeout):
    best = None
    for _ in range(3):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = time.time()
        try:
            s.connect((ip, port))
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
    return ip, best


def main():
    if len(sys.argv) < 4:
        return
    port = int(sys.argv[1])
    timeout = float(sys.argv[2])
    conc = max(1, int(sys.argv[3]))

    ips = []
    for line in sys.stdin:
        line = line.strip()
        if line:
            ips.append(line)
    if not ips:
        return

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=conc) as ex:
        for ip, lat in ex.map(lambda i: probe(i, port, timeout), ips):
            if lat is not None:
                results.append((ip, lat))
    results.sort(key=lambda x: x[1])
    for ip, lat in results:
        print("%s %.1f" % (ip, lat))


if __name__ == "__main__":
    main()
