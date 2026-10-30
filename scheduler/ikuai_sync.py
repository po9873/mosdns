#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ikuai_sync.py — 每轮优选后校验「爱快 → AdGuard → mosdns」链路的应答一致性（只读）。

设计约束（用户要求）：DNS 必须经过 AdGuard 过滤，因此【不】往爱快写域名规则；
mosdns 的 pin 通过 DNS 链路自然生效。爱快 DNS缓存 cache_ttl 已降到 120s，
pin 变化后最多 2 分钟全网跟上。本脚本只做抽查：爱快答的 IP 是否还在 pin 里，
发现陈旧就打警告（会在 TTL 内自愈，无需人工处理）。

环境变量:
  IKUAI_TOKEN   未设置则静默退出（保留以便将来需要管理动作）
  IKUAI_DNSIP   爱快 DNS 查询地址, 默认 192.168.6.254
  IKUAI_SAMPLE  抽查域名数上限, 默认 20
映射来源: /data/prefs/all.hosts (每行 "域名 IP1 IP2 ...")
"""
import os
import random
import socket
import struct
import sys

KEY_PRIORITY = ("github.com", "www.github.com", "api.github.com", "alive.github.com",
                "translate-pa.googleapis.com", "translate.googleapis.com",
                "www.themoviedb.org", "api.themoviedb.org", "image.tmdb.org",
                "www.imdb.com", "ghcr.io")


def log(msg):
    print("[ikuai-check] %s" % msg, flush=True)


def is_v4(s):
    bits = s.split(".")
    return len(bits) == 4 and all(b.isdigit() and 0 <= int(b) <= 255 for b in bits)


def load_pins():
    path = "/data/prefs/all.hosts"
    if not os.path.isfile(path):
        return {}
    out = {}
    for line in open(path):
        p = line.split()
        if len(p) >= 2 and all(is_v4(x) for x in p[1:]):
            out[p[0]] = set(x for x in p[1:] if is_v4(x))
    return out


def _skip_name(data, off):
    """跳过(可能压缩的)域名，返回新偏移。"""
    while off < len(data):
        n = data[off]
        if n == 0:
            return off + 1
        if n & 0xC0:  # 压缩指针
            return off + 2
        off += n + 1
    return off


def dns_query(name, server, timeout=3):
    """极简 A 记录查询，返回 IP 列表。

    注意: 爱快应答头计数不可信(qd/an 胡填)，故不信 qdcount/ancount，
    手工跳过问题区后逐条解析到包尾。
    """
    try:
        q = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        for lab in name.split("."):
            q += struct.pack("B", len(lab)) + lab.encode()
        q += b"\x00" + struct.pack(">HH", 1, 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(q, (server, 53))
        data, _ = s.recvfrom(2048)
        s.close()
    except Exception:
        return None
    # 跳过第一条(真实)问题区: 域名 + type(2) + class(2)
    off = _skip_name(data, 12)
    off += 4
    ips = []
    while off + 10 <= len(data):
        off = _skip_name(data, off)          # 记录名(常是压缩指针)
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        if rtype == 1 and rdlen == 4 and off + 4 <= len(data):
            ips.append(".".join(str(b) for b in data[off:off + 4]))
        off += rdlen
    return ips


def main():
    if not os.environ.get("IKUAI_TOKEN"):
        sys.exit(0)
    dns_ip = os.environ.get("IKUAI_DNSIP", "192.168.6.254")
    sample_n = int(os.environ.get("IKUAI_SAMPLE", "20"))

    pins = load_pins()
    if not pins:
        log("没有 pin 映射, 跳过")
        return

    # 关键域名优先，其余随机补齐
    doms = [d for d in KEY_PRIORITY if d in pins]
    rest = [d for d in pins if d not in doms]
    random.shuffle(rest)
    doms += rest[:max(0, sample_n - len(doms))]

    stale = dead = ok = 0
    for d in doms:
        ans = dns_query(d, dns_ip)
        if ans is None:
            dead += 1
            log("  ? %s: 查询失败" % d)
        elif not (set(ans) & pins[d]):
            stale += 1
            log("  ! %s: 爱快答 %s 不在 pin %s 里(缓存未跟上, TTL 内自愈)" % (
                d, ",".join(ans[:3]), ",".join(sorted(pins[d])[:3])))
        else:
            ok += 1
    log("链路抽查: 一致=%d 陈旧=%d 失败=%d / 共%d" % (ok, stale, dead, len(doms)))


if __name__ == "__main__":
    main()
