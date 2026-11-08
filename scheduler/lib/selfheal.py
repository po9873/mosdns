#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""自愈纯逻辑（无副作用，便于单测）。

1) plan_unban —— 黑名单是 IP 级，101 的探测判据却是 (路, 域, IP) 级。
   一个域偶发抖动就把整个 IP 拉黑，会把同一 IP 上其它正常域名（甚至是
   正在使用的翻译依赖域）一起挡在候选池外，以前只能人工清理。
   这里让 101 每轮拿自己刚跑完的分域实测结果复核：在用 IP 本轮在
   每一个在用域上都通过就自动解除；任一域不过就保留（例如某节点对
   csp 域证书不匹配），绝不把坏 IP 放出来。
2) soft_retry_ips —— 跨境网关抖动会把候选池整批打进 6 小时黑名单，
   导致主域冗余一直补不回来。冷却满后给这些 IP 一次「重新实测」的机会，
   不是无条件解禁：补位仍要过同一套 101 HTTPS 校验。
3) image_status / fetch_registry_state —— 内网 mirror 的 latest 会缓存住旧
   manifest，直接重拉会把容器退回旧版。101 每天自己核对一次并告警。
"""
import json
import re
import ssl
import time
import urllib.request

# 外部抖动类（网关 5xx / 超时 / 连不上 / 慢 / 抖动窗口），不是节点本身坏
SOFT_PREFIXES = ("http5", "timeout", "fail", "blocked", "slow", "ok ")
SOFT_RETRY_SEC = 1800
SOFT_RETRY_MAX = 4
# 同一 IP 解除后 30 分钟内不再重复解除，避免「解除→补位再判死→再解除」抖动
UNBAN_COOLDOWN_SEC = 1800

_ACC = ("application/vnd.docker.distribution.manifest.v2+json, "
        "application/vnd.oci.image.manifest.v1+json")
_TAG_RE = re.compile(r"^v[\d.]+-(\d{8})-([0-9a-f]{7})$")


def build_used(files, static_rows, static_route="static"):
    """files: {route: (rows, scan)}；返回 {ip: {(route, dom, ip), ...}}。

    key 与 _batch_health 的 results 完全一致，直接拿来取本轮实测证据。
    """
    used = {}
    for route, pair in (files or {}).items():
        _rows, scan = pair
        for dom, ips in scan:
            for ip in ips:
                used.setdefault(ip, set()).add((route, dom, ip))
    for dom, ips in (static_rows or []):
        for ip in ips:
            used.setdefault(ip, set()).add((static_route, dom, ip))
    return used


def plan_unban(bad, used, results, now=None, recent_unbans=None):
    """返回本轮应由 101 自动解除拉黑的 IP 列表。

    证据只来自 results（本轮 101 容器自己发出的探测），且必须是该 IP 在
    hosts 里真正在用的**每一个**域都有实测；未测过 / 已过期 / 不在用 /
    任一域判 BAD 的一律不动。

    2026-11-08 复发修复：只复核「外部抖动类」拉黑。cert / 1034 / wrong
    是节点与域名不匹配的确定性结论（例如 GitHub Pages 段对 github.com
    主域证书不对），解除后同一轮补位会立刻再次判死，形成每 7 分钟
    「解除→拉黑→解除」的循环；解除后 30 分钟内也不重复放同一 IP。
    """
    t = time.time() if now is None else now
    recent = recent_unbans or {}
    freed = []
    for ip, rec in (bad or {}).items():
        try:
            if float(rec.get("until", 0)) <= t:
                continue
        except (TypeError, ValueError):
            continue
        if not str(rec.get("reason") or "").startswith(SOFT_PREFIXES):
            continue
        try:
            if t - float(recent.get(ip) or 0) < UNBAN_COOLDOWN_SEC:
                continue
        except (TypeError, ValueError):
            pass
        keys = used.get(ip)
        if not keys:
            continue
        if not all(k in results for k in keys):
            continue
        judged = [results[k] for k in keys]
        if judged and all(bool(v and v[0]) for v in judged):
            freed.append(ip)
    return freed


def soft_retry_ips(bad, now=None, cooldown=SOFT_RETRY_SEC, limit=SOFT_RETRY_MAX):
    """挑出「拉黑满冷却、属外部抖动类」的 IP，让 101 重新实测一次。"""
    t = time.time() if now is None else now
    out = []
    for ip, rec in (bad or {}).items():
        try:
            if float(rec.get("until", 0)) <= t:
                continue
            if t - float(rec.get("ts", 0)) < cooldown:
                continue
        except (TypeError, ValueError):
            continue
        if str(rec.get("reason") or "").startswith(SOFT_PREFIXES):
            out.append(ip)
        if len(out) >= limit:
            break
    return out


def image_status(ghcr_digest, mirror_digest, local_rev, latest_rev):
    """返回 (level, msg)：ok / warn。纯逻辑，不联网。"""
    msgs = []
    if ghcr_digest and mirror_digest and mirror_digest != ghcr_digest:
        msgs.append("镜像加速 latest 缓存滞后，别从 mirror 重拉（会退回旧版）")
    if latest_rev and local_rev and latest_rev != local_rev:
        msgs.append("有更新版本 %s，当前运行 %s" % (latest_rev, local_rev))
    if msgs:
        return "warn", "；".join(msgs)
    return "ok", ""


def _get(url, headers=None, timeout=10, insecure=False):
    req = urllib.request.Request(url, headers=headers or {})
    kw = {"timeout": timeout}
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        kw["context"] = ctx
    with urllib.request.urlopen(req, **kw) as r:
        return r.read(), dict(r.headers)


def fetch_registry_state(repo="po9873/mosdns",
                         mirror="registry.linkease.net:5443", timeout=10):
    """在 101 容器内取 ghcr（无缓存基准）+ 内网 mirror 的 latest digest。"""
    out = {"ghcr": "", "mirror": "", "rev": ""}
    try:
        raw, _ = _get("https://ghcr.io/token?scope=repository:%s:pull&service=ghcr.io"
                      % repo, timeout=timeout)
        tok = json.loads(raw)["token"]
        h = {"Authorization": "Bearer " + tok, "Accept": _ACC}
        raw, hd = _get("https://ghcr.io/v2/%s/manifests/latest" % repo, h, timeout)
        for k, v in hd.items():
            if k.lower() == "docker-content-digest":
                out["ghcr"] = v.strip()
        if not out["ghcr"]:
            out["ghcr"] = (json.loads(raw).get("config") or {}).get("digest", "")
        raw, _ = _get("https://ghcr.io/v2/%s/tags/list?n=1000" % repo, h, timeout)
        cands = [t for t in (json.loads(raw).get("tags") or []) if _TAG_RE.match(t)]
        if cands:
            # 不能按字典序取最大：同一天有多个提交，'f...' 会压过 '5...'，
            # 把老构建误报成「有更新版本」，每天推一条假告警。
            newest = max(m.group(1) for m in (_TAG_RE.match(t) for t in cands))
            same_day = [t for t in cands if _TAG_RE.match(t).group(1) == newest]
            # ghcr tags/list 按推送先后返回，同一天里最后一条就是最新构建。
            out["rev"] = _TAG_RE.match(same_day[-1]).group(2)
    except Exception:
        pass
    try:
        _raw, hd = _get("https://%s/v2/%s/manifests/latest" % (mirror, repo),
                        {"Accept": _ACC}, timeout, insecure=True)
        for k, v in hd.items():
            if k.lower() == "docker-content-digest":
                out["mirror"] = v.strip()
    except Exception:
        pass
    return out
