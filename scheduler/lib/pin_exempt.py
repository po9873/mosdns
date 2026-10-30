#!/usr/bin/env python3
"""固定映射 IP 的黑名单豁免登记。

同一 IP 对不同域名提供不同服务：140.82.116.6 对 github.com 网页回 blocked
（主优选拉黑它完全正确），但对 api.github.com 的 /rate_limit 是 200。
全局 IP 黑名单会把这类「专属 pin」误杀——固定映射行被 merge 滤掉后
api.github.com 就没有 pin 了，App 又回到 429/410。

固定映射脚本（api_pin_refresh / fastly_pin_refresh）选定 IP 后在这里登记
「IP → 域名列表」；merge_hosts / watchdog 撤下坏 IP 时，凡被某域名豁免的
IP 在该域名的 pin 行里保留。豁免的前提是专属探针刚验证过（/rate_limit=200、
真实资源路径 404 等），假边缘拿不到豁免，安全边界不变。"""
import json
import os

EXEMPT_FILE = "/data/prefs/pin_exempt.json"


def load():
    try:
        d = json.load(open(EXEMPT_FILE))
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def save(d):
    tmp = EXEMPT_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(d, f, ensure_ascii=False, sort_keys=True)
    os.replace(tmp, EXEMPT_FILE)


def update(domain, ips):
    """登记 domain 当前的固定映射 IP（覆盖该域名的旧登记）。"""
    if not domain or not ips:
        return
    d = load()
    for ip in list(d.keys()):
        if domain in d[ip]:
            d[ip] = [x for x in d[ip] if x != domain]
            if not d[ip]:
                del d[ip]
    for ip in ips:
        d.setdefault(ip, [])
        if domain not in d[ip]:
            d[ip].append(domain)
    save(d)
