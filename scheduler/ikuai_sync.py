#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ikuai_sync.py — 每轮优选后把 mosdns pin 的 IP 自动同步进爱快(4.x)「DNS加速」规则。

思路参考 cloudflarexikuai 镜像(john327)：与其指望各层缓存过期，
不如直接让爱快把优选 IP 答给全网设备。爱快 4.0 REST API：
  GET  /api/v4.0/network/dns/proxy/rules          列规则
  POST /api/v4.0/network/dns/proxy/rules          建规则
  PUT  /api/v4.0/network/dns/proxy/rules/{id}     改规则
  POST /api/v4.0/network/dns/services:restart     重启DNS服务(清缓存, 尝试性)
认证: Authorization: Bearer <IKUAI_TOKEN>

环境变量:
  IKUAI_TOKEN   爱快「个人API令牌」(设备设置→登录管理→个人API令牌)，未设置则直接退出
  IKUAI_HOST    默认 https://192.168.6.254
  IKUAI_COMMENT 规则备注标记, 默认 mosdns-auto
  IKUAI_MAXIP   每个域名最多写入几个IP, 默认 2
  IKUAI_DNSADDR 直接指定"域名:IP"映射(逗号分隔, 如 github.com:20.27.177.113),
                设置后忽略 all.hosts, 用于手工测试
映射来源: /data/prefs/all.hosts (每行 "IP 域名", run_route 选路后落盘)
"""
import base64
import json
import os
import ssl
import sys
import urllib.request

API = "/api/v4.0"
TAG_DEFAULT = "mosdns-auto"
MAX_IP_DEFAULT = 2


def log(msg):
    print("[ikuai-sync] %s" % msg, flush=True)


def api(host, token, method, path, body=None):
    url = host.rstrip("/") + API + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "mosdns-ikuai-sync",
    })
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # 爱快自签证书
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            raw = resp.read().decode()
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        log("HTTP %s %s -> %s %s" % (method, path, e.code, raw[:120]))
        return None
    except Exception as e:
        log("请求失败 %s %s: %s" % (method, path, e))
        return None
    # 爱快固件可能吐裸 nil
    raw = raw.replace(":nil", ":null")
    try:
        d = json.loads(raw)
    except Exception:
        log("非JSON响应 %s %s: %s" % (method, path, raw[:120]))
        return None
    if isinstance(d, dict) and d.get("code") not in (None, 0, 10000):
        log("API错误 %s %s: code=%s %s" % (method, path, d.get("code"), str(d.get("message"))[:100]))
        return None
    return d


def load_mappings():
    """返回 {domain: [ip, ...]}，按 all.hosts 顺序。"""
    env = os.environ.get("IKUAI_DNSADDR", "").strip()
    if env:
        out = {}
        for pair in env.split(","):
            if ":" in pair:
                d, ip = pair.rsplit(":", 1)
                out.setdefault(d.strip(), []).append(ip.strip())
        return out
    path = "/data/prefs/all.hosts"
    if not os.path.isfile(path):
        log("未找到 %s" % path)
        return {}
    out = {}
    for line in open(path):
        parts = line.split()
        # all.hosts 格式: 域名 IP1 IP2 ...
        if len(parts) >= 2 and all(_is_ip(p) for p in parts[1:]):
            out.setdefault(parts[0], []).extend(parts[1:])
    return out


def _is_ip(s):
    if ":" in s:  # IPv6
        return True
    bits = s.split(".")
    return len(bits) == 4 and all(b.isdigit() and 0 <= int(b) <= 255 for b in bits)


def main():
    token = os.environ.get("IKUAI_TOKEN", "").strip()
    if not token:
        sys.exit(0)  # 未配置则静默退出，不影响调度
    host = os.environ.get("IKUAI_HOST", "https://192.168.6.254")
    tag = os.environ.get("IKUAI_COMMENT", TAG_DEFAULT)
    max_ip = int(os.environ.get("IKUAI_MAXIP", MAX_IP_DEFAULT))

    # 令牌完整性自检: 爱快令牌是 base64 的 UUID，解出来应是 8-4-4-4-12
    try:
        dec = base64.b64decode(token + "=" * (-len(token) % 4)).decode()
        parts = dec.split("-")
        if len(parts) != 5 or len(dec) != 36:
            log("警告: 令牌解码=%s 长度异常, 可能复制不完整!" % dec)
    except Exception:
        log("警告: 令牌不是合法 base64, 可能复制不完整!")

    maps = load_mappings()
    if not maps:
        log("没有可同步的映射, 退出")
        return
    doms = sorted(maps.keys())
    log("待同步域名 %d 个: %s" % (len(doms), ", ".join(doms[:8])))

    rules = api(host, token, "GET", "/network/dns/proxy/rules?limit=500")
    items = []
    if isinstance(rules, dict):
        items = rules.get("data") or rules.get("items") or []
    if not isinstance(items, list):
        items = []
    by_domain = {}
    for it in items:
        if isinstance(it, dict):
            by_domain[str(it.get("domain", ""))] = it

    created = updated = failed = 0
    for dom in doms:
        ips = maps[dom][:max_ip]
        body = {
            "domain": dom,
            "dns_addr": ",".join(ips),
            "parse_type": "ipv4",
            "enabled": "yes",
            "comment": tag,
        }
        old = by_domain.get(dom)
        if old is None:
            r = api(host, token, "POST", "/network/dns/proxy/rules", body)
            if r is not None:
                created += 1
                log("  + %s -> %s (新建)" % (dom, body["dns_addr"]))
            else:
                failed += 1
        else:
            same = str(old.get("dns_addr", "")) == body["dns_addr"]
            if same and str(old.get("enabled", "yes")) in ("yes", "1", "true"):
                continue  # 无变化不动
            r = api(host, token, "PUT", "/network/dns/proxy/rules/%s" % old.get("id"), body)
            if r is not None:
                updated += 1
                log("  ~ %s: %s -> %s" % (dom, old.get("dns_addr"), body["dns_addr"]))
            else:
                failed += 1
        import time
        time.sleep(0.5)  # 温和限速

    log("同步完成: 新建=%d 更新=%d 失败=%d" % (created, updated, failed))

    # 尝试重启 DNS 服务清缓存(端点不存在则跳过)
    r = api(host, token, "POST", "/network/dns/services:restart", {})
    if r is not None:
        log("已触发爱快 DNS 服务重启(清缓存)")
    else:
        log("DNS 服务重启端点不可用, 依赖规则更新自动生效")


if __name__ == "__main__":
    main()
