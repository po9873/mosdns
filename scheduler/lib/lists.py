#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""分流清单管理：国内 IP 段 / 国内域名 / 国外域名

命令：
  init                首次启动：/data 缺清单时从镜像补齐，并记录来源
  status              输出 JSON（条目数 / 大小 / 更新时间 / 来源 / 状态）
  preview NAME [N]    输出清单前 N 行（供 UI 查看）
  update NAME|all     多源下载 → 校验 → 原子替换 → 写元数据
  auto [HOURS]        到点自动更新（周期+时刻来自设置）；有变化返回 0，无变化返回 1
  sched               输出当前的自动更新计划（开关 / 周期 / 时刻）

设计要点：
  1) 多个源依次尝试，任一成功即止；全部失败保留旧文件（绝不让清单变空）。
  2) 下载内容先写临时文件，校验通过才原子替换，避免半截文件被 mosdns 读到。
  3) 条目数有下限校验，防止把 404 页面当成清单写进去。
"""
import hashlib
import ipaddress
import json
import os
import re
import sys
import time
import urllib.request

DATA_DIR = os.environ.get("PREF_DATA_DIR", "/data")
IMAGE_CONFIG = "/app/config"
TMP_DIR = os.path.join(DATA_DIR, ".lists_tmp")
META_FILE = os.path.join(DATA_DIR, "lists_meta.json")
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")
UA = "mosdns-pref/1.0"

# 自动更新周期：跟「源拉取 / 源体检」用同一套写法（小时 / 每天 / 每周）
CYCLE_H = {"1h": 1, "2h": 2, "3h": 3, "4h": 4, "6h": 6, "8h": 8, "12h": 12,
           "24h": 24, "daily": 24, "weekly": 168}
DEFAULT_HOUR = 4


def list_sched():
    """读设置：清单自动更新的开关 / 周期 / 时刻。

    老版本设置里只有 list_auto_update + list_update_hours，这里做一次兼容映射，
    升级后不用手动重填。
    """
    st = {}
    try:
        with open(SETTINGS_FILE, encoding="utf-8") as f:
            st = json.load(f) or {}
    except Exception:
        st = {}

    on = st.get("list_upd_enabled")
    if on is None:
        on = st.get("list_auto_update", True)

    cyc = str(st.get("list_upd_cycle") or "").strip()
    if cyc not in CYCLE_H:
        try:
            h = int(st.get("list_update_hours"))
        except Exception:
            h = 24
        if h in (1, 2, 3, 4, 6, 8, 12):
            cyc = "%dh" % h
        elif h <= 48:
            cyc = "daily"
        else:
            cyc = "weekly"

    try:
        hour = int(st.get("list_upd_hour", DEFAULT_HOUR))
    except Exception:
        hour = DEFAULT_HOUR
    return {"enabled": bool(on), "cycle": cyc, "hour": max(0, min(23, hour))}


def sched_due(sched, last, now=None):
    """到点没有：周期 < 24h 按间隔算；按天/按周还要求已过设定的时刻。"""
    if not sched["enabled"]:
        return False
    now = now or time.time()
    if not last:
        return True
    cyc = CYCLE_H.get(sched["cycle"], 24)
    if cyc >= 24:
        if time.localtime(now).tm_hour < int(sched["hour"]):
            return False
        return now - last >= cyc * 3600 - 3600
    return now - last >= cyc * 3600


def sched_next(sched, last, now=None):
    if not sched["enabled"]:
        return 0
    now = now or time.time()
    cyc = CYCLE_H.get(sched["cycle"], 24)
    if not last:
        return int(now)
    if cyc >= 24:
        t = time.localtime(last + cyc * 3600 - 3600)
        return int(time.mktime((t.tm_year, t.tm_mon, t.tm_mday,
                                int(sched["hour"]), 0, 0, 0, 0, -1)))
    return int(last + cyc * 3600)

# ---------------------------------------------------------------- 清单定义
LISTS = {
    "china_ip": {
        "file": "china_ip.txt",
        "label": "国内 IP 段",
        "kind": "ip",
        "min_lines": 500,          # 真实清单数千条；低于此值视为下载失败
        "auto": True,              # 参与自动更新
        "sources": [
            {"url": "https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt"},
            {"url": "https://ispip.clang.cn/all_cn.txt"},
            {"url": "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china.txt"},
            # 官方来源，需解析 APNIC 委派记录
            {"url": "https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest", "parser": "apnic_cn"},
        ],
    },
    "cn_domains": {
        "file": "cn_domains.txt",
        "label": "国内域名",
        "kind": "domain",
        "min_lines": 100,
        "auto": True,              # 域名也会变（新站/换域名），跟着一起自动更新
        "sources": [
            {"url": "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt"},
            {"url": "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/cn"},
            # raw.githubusercontent.com 实测经常读超时（线上就掉过），
            # 加两个国内可达的镜像：连不上官方仓库时还有得拉。
            {"url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/direct-list.txt"},
            {"url": "https://ghproxy.net/https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt"},
        ],
    },
    "gfw_domains": {
        "file": "gfw_domains.txt",
        "label": "国外/GFW 域名",
        "kind": "domain",
        "min_lines": 100,
        "auto": True,
        "sources": [
            {"url": "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt"},
            {"url": "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/proxy-list.txt"},
            {"url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/gfw.txt"},
            {"url": "https://ghproxy.net/https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/proxy-list.txt"},
        ],
    },
    # CDN 网段库：用于诊断页判断「这个 IP 是谁的」。多源合并，任一可用即保留其余
    "cdn_ranges": {
        "file": "cdn_ranges.txt",
        "label": "CDN 网段库",
        "kind": "cdn",
        "min_lines": 20,
        "auto": True,
        "merge": True,
        "sources": [
            {"url": "https://www.cloudflare.com/ips-v4", "parser": "cdn", "provider": "Cloudflare"},
            {"url": "https://www.cloudflare.com/ips-v6", "parser": "cdn", "provider": "Cloudflare"},
            {"url": "https://www.gstatic.com/ipranges/goog.txt", "parser": "cdn_goog", "provider": "Google"},
            {"url": "https://api.fastly.com/public-ip-list", "parser": "cdn_fastly", "provider": "Fastly"},
            # CloudFront 段：TMDB / IMDb 两路用的就是它。以前没有这份，
            # 诊断页看这两路的 IP 全是「未知」，等于看不出是谁家的节点。
            {"url": "https://ip-ranges.amazonaws.com/ip-ranges.json", "parser": "cdn_aws", "provider": "CloudFront"},
        ],
    },
}

RE_IP = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$")
RE_CIDR_ANY = re.compile(r"^[0-9a-fA-F:.]+/\d{1,3}$")
RE_DOM_PREFIXED = re.compile(r"^(domain|full|keyword|regexp):\S+$")
RE_DOM_BARE = re.compile(r"^[A-Za-z0-9_.*\u4e00-\u9fa5-]+\.[A-Za-z]{2,}$")


# ---------------------------------------------------------------- 小工具
def meta_all():
    try:
        with open(META_FILE, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def meta_set(name, obj):
    d = meta_all()
    d[name] = obj
    os.makedirs(os.path.dirname(META_FILE), exist_ok=True)
    tmp = META_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=1)
    os.replace(tmp, META_FILE)


def host_of(url):
    m = re.match(r"^https?://([^/]+)", url or "")
    return m.group(1) if m else (url or "")


def fetch(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def parse_apnic_cn(text):
    """把 APNIC delegated-apnic-latest 里的 CN IPv4 委派记录转成 CIDR。"""
    out = []
    for line in text.splitlines():
        p = line.split("|")
        if len(p) < 7 or p[0] != "apnic" or p[1] != "CN" or p[2] != "ipv4":
            continue
        if p[6] not in ("allocated", "assigned"):
            continue
        try:
            count = int(p[4])
            if count <= 0 or (count & (count - 1)) != 0:   # 必须是 2 的幂
                continue
            prefix = 32 - (count.bit_length() - 1)
            out.append(str(ipaddress.ip_network("%s/%d" % (p[3], prefix), strict=False)))
        except Exception:
            continue
    return out


def normalize(items, kind):
    """清洗成 mosdns 可直接读取的行；去重、去注释、剔非法项。"""
    out, seen = [], set()
    for raw in items:
        s = (raw or "").strip()
        if not s or s.startswith("#") or s.startswith("//"):
            continue
        if kind == "cdn":
            parts = s.split()
            if len(parts) != 2:
                continue
            name, cidr = parts[0], parts[1]
            if ":" in cidr:
                if not RE_CIDR_ANY.match(cidr):
                    continue
            elif not RE_IP.match(cidr):
                continue
            try:
                cidr = str(ipaddress.ip_network(cidr, strict=False))
            except Exception:
                continue
            s = "%s %s" % (name, cidr)
        elif kind == "ip":
            if not RE_IP.match(s):
                continue
            try:
                s = str(ipaddress.ip_network(s, strict=False))
            except Exception:
                continue
        else:
            if not (RE_DOM_PREFIXED.match(s) or RE_DOM_BARE.match(s)):
                continue
            if not RE_DOM_PREFIXED.match(s):
                s = "domain:" + s.lstrip(".")
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def count_lines(path):
    n = 0
    try:
        with open(path, "rb") as f:
            for line in f:
                if line.strip() and not line.lstrip().startswith(b"#"):
                    n += 1
    except Exception:
        return 0
    return n


# ---------------------------------------------------------------- 命令实现
def cmd_init():
    """补齐 /data 缺失清单（来源记为镜像内置），已有文件绝不覆盖。"""
    os.makedirs(DATA_DIR, exist_ok=True)
    m = meta_all()
    changed = []
    for name, spec in LISTS.items():
        dst = os.path.join(DATA_DIR, spec["file"])
        if os.path.isfile(dst) and os.path.getsize(dst) > 0:
            continue
        src = os.path.join(IMAGE_CONFIG, spec["file"])
        try:
            with open(src, "rb") as f:
                body = f.read()
            with open(dst, "wb") as f:
                f.write(body)
            m[name] = {
                "status": "ok",
                "source": "image:" + src,
                "updated_at": int(time.time()),
                "checked_at": int(time.time()),
                "lines": count_lines(dst),
                "bytes": len(body),
                "sha256": hashlib.sha256(body).hexdigest()[:16],
                "error": "",
            }
            changed.append(name)
        except Exception as e:
            m.setdefault(name, {})
            m[name].update({"status": "empty", "error": "镜像内也无此清单: %s" % e})
    if changed:
        tmp = META_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(m, f, ensure_ascii=False, indent=1)
        os.replace(tmp, META_FILE)
    print(json.dumps({"initialized": changed}, ensure_ascii=False))


def cmd_status():
    sched = list_sched()
    now = int(time.time())
    out = {}
    m = meta_all()
    for name, spec in LISTS.items():
        path = os.path.join(DATA_DIR, spec["file"])
        info = m.get(name, {})
        item = {
            "label": spec["label"],
            "file": path,
            "auto": spec["auto"],
            "min_lines": spec["min_lines"],
        }
        try:
            st = os.stat(path)
            item["bytes"] = st.st_size
            item["mtime"] = int(st.st_mtime)
        except Exception:
            item["bytes"] = 0
            item["mtime"] = 0
        item["lines"] = count_lines(path)
        item["updated_at"] = info.get("updated_at") or item["mtime"]
        item["checked_at"] = info.get("checked_at") or 0
        item["source"] = info.get("source", "")
        item["source_host"] = host_of(info.get("source", "")) if info.get("source") else "内置镜像"
        item["status"] = info.get("status") or ("ok" if item["lines"] else "empty")
        item["error"] = info.get("error", "")
        # 这一份清单自己的自动更新计划（开关关掉时为 0）
        item["auto_enabled"] = bool(sched["enabled"] and spec["auto"])
        item["next"] = (sched_next(sched, item["updated_at"], now)
                        if item["auto_enabled"] else 0)
        out[name] = item
    print(json.dumps({"sched": sched, "items": out}, ensure_ascii=False))


def cmd_preview(name, n=50):
    spec = LISTS.get(name)
    if not spec:
        print(json.dumps({"error": "未知清单"}), file=sys.stderr)
        return 2
    path = os.path.join(DATA_DIR, spec["file"])
    lines = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                s = line.rstrip("\n")
                lines.append(s)
                if len(lines) >= n:
                    break
    except Exception as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        return 2
    print(json.dumps({"name": name, "label": spec["label"], "lines": lines}, ensure_ascii=False))
    return 0


def _parse_source(src, spec):
    """按源类型解析成清单行（不同公开源的格式差异都在这里抹平）。"""
    url = src["url"] if isinstance(src, dict) else src
    parser = src.get("parser", "text") if isinstance(src, dict) else "text"
    provider = src.get("provider", "") if isinstance(src, dict) else ""
    raw = fetch(url)

    if parser == "apnic_cn":
        items = parse_apnic_cn(raw)
    elif parser == "cdn":
        items = ["%s %s" % (provider, l.strip()) for l in raw.splitlines()
                 if l.strip() and not l.strip().startswith("#")]
    elif parser == "cdn_goog":
        items = []
        for line in raw.splitlines():
            p = line.split(",")
            if len(p) >= 2 and p[0].strip() in ("ipv4", "ipv6"):
                items.append("%s %s" % (provider, p[1].strip()))
    elif parser == "cdn_fastly":
        items = []
        try:
            d = json.loads(raw)
            for k in ("addresses", "ipv6_addresses"):
                for c in d.get(k) or []:
                    items.append("%s %s" % (provider, c))
        except Exception:
            pass
    elif parser == "cdn_aws":
        # AWS ip-ranges.json 里 90% 是 EC2/S3/AMAZON 段，只取 service=CLOUDFRONT
        # （214 段 v4 / 34 段 v6）。不筛的话会把几万个 EC2 段全写进来，
        # 诊断页面对任何 AWS 上的 IP 都显示「CloudFront」，等于没判断。
        items = []
        try:
            d = json.loads(raw)
            for p in d.get("prefixes") or []:
                if p.get("service") == "CLOUDFRONT" and p.get("ip_prefix"):
                    items.append("%s %s" % (provider, p["ip_prefix"]))
            for p in d.get("ipv6_prefixes") or []:
                if p.get("service") == "CLOUDFRONT" and p.get("ipv6_prefix"):
                    items.append("%s %s" % (provider, p["ipv6_prefix"]))
        except Exception:
            pass
    else:
        items = raw.splitlines()
    return url, normalize(items, spec["kind"])


def _commit(name, spec, items, source_desc):
    dst = os.path.join(DATA_DIR, spec["file"])
    os.makedirs(TMP_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)
    body = ("\n".join(items) + "\n").encode("utf-8")
    sha = hashlib.sha256(body).hexdigest()[:16]
    old = meta_all().get(name, {})

    # 内容一模一样就不动文件、不触发引擎重载（DNS 零中断），只把「已检查」时间刷新
    if old.get("sha256") == sha and os.path.isfile(dst):
        meta = dict(old)
        meta.update({
            "status": "ok", "source": source_desc, "checked_at": int(time.time()),
            "updated_at": int(time.time()), "error": "",
        })
        meta_set(name, meta)
        return dict(meta, ok=True, unchanged=True, name=name, label=spec["label"])

    tmp = os.path.join(TMP_DIR, spec["file"] + ".new")
    with open(tmp, "wb") as f:
        f.write(body)
        f.flush()
        os.fsync(f.fileno())
    # 旧文件留一份 .bak，便于回滚
    if os.path.isfile(dst):
        try:
            os.replace(dst, dst + ".bak")
        except Exception:
            pass
    os.replace(tmp, dst)
    meta = {
        "status": "ok",
        "source": source_desc,
        "updated_at": int(time.time()),
        "checked_at": int(time.time()),
        "lines": len(items),
        "bytes": len(body),
        "sha256": sha,
        "error": "",
    }
    meta_set(name, meta)
    return dict(meta, ok=True, unchanged=False, name=name, label=spec["label"])


def update_one(name):
    """单清单更新：多源尝试，成功即原子替换；全失败保留旧文件。

    merge=True 的清单（CDN 网段库）会合并所有可用源，而不是取第一个成功的。
    """
    spec = LISTS[name]
    errors = []

    if spec.get("merge"):
        merged, used = [], []
        for src in spec["sources"]:
            url = src["url"] if isinstance(src, dict) else src
            try:
                _, items = _parse_source(src, spec)
                if items:
                    merged.extend(items)
                    used.append(host_of(url))
            except Exception as e:
                errors.append("%s: %s" % (host_of(url), str(e)[:80]))
        items = normalize(merged, spec["kind"])
        if len(items) >= spec["min_lines"]:
            return _commit(name, spec, items, " + ".join(used))
        errors.insert(0, "合并后条目过少(%d)，需要 %d" % (len(items), spec["min_lines"]))
    else:
        for src in spec["sources"]:
            url = src["url"] if isinstance(src, dict) else src
            try:
                _, items = _parse_source(src, spec)
                if len(items) < spec["min_lines"]:
                    errors.append("%s 有效条目过少(%d)" % (host_of(url), len(items)))
                    continue
                return _commit(name, spec, items, url)
            except Exception as e:
                errors.append("%s: %s" % (host_of(url), str(e)[:100]))

    old = meta_all().get(name, {})
    meta = dict(old)
    meta.update({
        "checked_at": int(time.time()),
        "error": "; ".join(errors)[:300] or "全部源不可用",
    })
    if old.get("status") != "ok":
        meta["status"] = "fail"
    meta_set(name, meta)
    return {"ok": False, "name": name, "label": spec["label"],
            "error": meta["error"], "kept_old": True}


def cmd_update(target):
    names = list(LISTS) if target == "all" else [target]
    if target != "all" and target not in LISTS:
        print(json.dumps({"error": "未知清单"}), file=sys.stderr)
        return 2
    results = [update_one(n) for n in names]
    print(json.dumps({"results": results}, ensure_ascii=False))
    return 0 if any(r.get("ok") for r in results) else 1


def cmd_auto(hours=None):
    """四份清单到点就自动拉；内容有变化返回 0（调度器据此重载引擎）。

    计划来自设置里的「周期 + 时刻」（list_upd_cycle / list_upd_hour），
    只有内容真的变了才算 changed，避免每天白白重启一次引擎。
    """
    sched = list_sched()
    if not sched["enabled"]:
        print(json.dumps({"checked": [], "changed": 0, "reason": "自动更新已关闭"},
                         ensure_ascii=False))
        return 1
    # 兼容老调用：auto <hours> 时按小时数临时覆盖周期
    if hours not in (None, ""):
        try:
            h = float(hours)
        except Exception:
            h = 0
        if h > 0:
            sched = {"enabled": True, "hour": sched["hour"],
                     "cycle": ("%dh" % int(h)) if int(h) in (1, 2, 3, 4, 6, 8, 12)
                              else ("daily" if h <= 48 else "weekly")}

    now = time.time()
    checked, changed = [], []
    for name, spec in LISTS.items():
        if not spec["auto"]:
            continue
        info = meta_all().get(name, {})
        last = info.get("updated_at") or 0
        if not sched_due(sched, last, now):
            continue
        # 刚试过（失败也算）就先跳过，别每轮都白等一次超时
        if info.get("checked_at") and (now - int(info["checked_at"])) < 1800 \
                and info.get("status") != "ok":
            continue
        r = update_one(name)
        checked.append({
            "name": name, "label": spec["label"], "ok": bool(r.get("ok")),
            "unchanged": bool(r.get("unchanged")), "lines": r.get("lines") or 0,
            "error": r.get("error", ""),
        })
        if r.get("ok") and not r.get("unchanged"):
            changed.append((name, r.get("lines"), host_of(r.get("source", ""))))
    print(json.dumps({"checked": checked, "changed": len(changed),
                      "updated": changed, "sched": sched}, ensure_ascii=False))
    return 0 if changed else 1


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    cmd = sys.argv[1]
    if cmd == "init":
        cmd_init()
        return 0
    if cmd == "status":
        cmd_status()
        return 0
    if cmd == "preview":
        return cmd_preview(sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 50)
    if cmd == "update":
        return cmd_update(sys.argv[2] if len(sys.argv) > 2 else "all")
    if cmd == "auto":
        # auto            按设置里的周期+时刻判断
        # auto 24         兼容旧调用：按小时数
        return cmd_auto(sys.argv[2] if len(sys.argv) > 2 else None)
    if cmd == "sched":
        print(json.dumps(list_sched(), ensure_ascii=False))
        return 0
    print("未知命令: %s" % cmd, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
