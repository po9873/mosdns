#!/usr/bin/env python3
# 向指定 DNS 服务器查询 A / AAAA 记录（纯标准库，不依赖系统 resolv.conf / dig）
# 用法: python3 dnsq.py <server> <port> <domain> [A|AAAA|ALL]
# 输出: 每行一个 IP（ALL 时先 IPv4 后 IPv6，已去重）
import random
import socket
import struct
import sys

QTYPE = {"A": 1, "AAAA": 28}


def build_query(domain, qid, qtype):
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    body = b""
    for part in domain.rstrip(".").split("."):
        if not part:
            continue
        body += bytes([len(part)]) + part.encode("ascii", "ignore")
    body += b"\x00" + struct.pack(">HH", qtype, 1)
    return header + body


def skip_name(data, idx):
    guard = 0
    while idx < len(data) and guard < 128:
        guard += 1
        l = data[idx]
        if l == 0:
            return idx + 1
        if l & 0xC0 == 0xC0:
            return idx + 2
        idx += 1 + l
    return idx


def format_v6(raw):
    if len(raw) != 16:
        return None
    groups = ["%02x%02x" % (raw[i], raw[i + 1]) for i in range(0, 16, 2)]
    # 压缩最长的一段连续 0 组
    best_i = best_len = cur_i = cur_len = -1
    for i, g in enumerate(groups):
        if g == "0000":
            if cur_len <= 0:
                cur_i, cur_len = i, 1
            else:
                cur_len += 1
        else:
            if cur_len > best_len:
                best_i, best_len = cur_i, cur_len
            cur_len = 0
    if cur_len > best_len:
        best_i, best_len = cur_i, cur_len
    if best_len < 2:
        return ":".join(groups)
    head = ":".join(groups[:best_i])
    tail = ":".join(groups[best_i + best_len:])
    if not head and not tail:
        return "::"
    return head + "::" + tail


def parse_response(data, want):
    """want: 1=A, 28=AAAA；返回该类型的地址列表。"""
    if len(data) < 12:
        return []
    ancount = struct.unpack(">H", data[6:8])[0]
    idx = skip_name(data, 12)
    idx += 4  # qtype + qclass
    out = []
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
        if rtype == want:
            if rtype == 1 and rdlen == 4:
                out.append(".".join(str(b) for b in rdata))
            elif rtype == 28 and rdlen == 16:
                a = format_v6(rdata)
                if a:
                    out.append(a)
        # CNAME 由 ancount 循环自然穿过
    return out


def query(server, port, domain, qtype):
    qid = random.randint(0, 65535)
    pkt = build_query(domain, qid, qtype)
    fam = socket.AF_INET6 if ":" in server else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        s.sendto(pkt, (server, port))
        data, _ = s.recvfrom(4096)
        return parse_response(data, qtype)
    except Exception:
        return []
    finally:
        s.close()


def main():
    if len(sys.argv) < 4:
        return
    server, port, domain = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    mode = (sys.argv[4] if len(sys.argv) > 4 else "A").upper()
    if mode == "ALL":
        seq = [QTYPE["A"], QTYPE["AAAA"]]
    else:
        seq = [QTYPE.get(mode, 1)]
    seen = set()
    for qt in seq:
        for ip in query(server, port, domain, qt):
            if ip not in seen:
                seen.add(ip)
                print(ip)


if __name__ == "__main__":
    main()
