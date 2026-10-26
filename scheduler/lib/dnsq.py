#!/usr/bin/env python3
# 向指定 DNS 服务器查询 A 记录（纯标准库，不依赖系统 resolv.conf / dig）
# 用法: python3 dnsq.py <server> <port> <domain>
# 输出: 每行一个 IPv4
import random
import socket
import struct
import sys


def build_query(domain, qid):
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    body = b""
    for part in domain.rstrip(".").split("."):
        if not part:
            continue
        body += bytes([len(part)]) + part.encode("ascii", "ignore")
    body += b"\x00" + struct.pack(">HH", 1, 1)
    return header + body


def skip_name(data, idx):
    while idx < len(data):
        l = data[idx]
        if l == 0:
            return idx + 1
        if l & 0xC0 == 0xC0:
            return idx + 2
        idx += 1 + l
    return idx


def parse_response(data):
    if len(data) < 12:
        return []
    ancount = struct.unpack(">H", data[6:8])[0]
    idx = skip_name(data, 12)
    idx += 4  # qtype + qclass
    ips = []
    for _ in range(ancount):
        if idx >= len(data):
            break
        idx = skip_name(data, idx)
        if idx + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[idx:idx + 10])
        idx += 10
        rdata = data[idx:idx + rdlen]
        idx += rdlen
        if rtype == 1 and rdlen == 4:
            ips.append(".".join(str(b) for b in rdata))
        elif rtype == 5:  # CNAME：继续解析后续 A 记录（由 ancount 循环自然处理）
            continue
    return ips


def main():
    if len(sys.argv) < 4:
        return
    server, port, domain = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    qid = random.randint(0, 65535)
    pkt = build_query(domain, qid)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        s.sendto(pkt, (server, port))
        data, _ = s.recvfrom(4096)
        for ip in parse_response(data):
            print(ip)
    except Exception:
        pass
    finally:
        s.close()


if __name__ == "__main__":
    main()
