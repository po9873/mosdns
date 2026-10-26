#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""分流清单管理：国内 IP 段 / 国内域名 / 国外域名

命令：
  init                首次启动：/data 缺清单时从镜像补齐，并记录来源
  status              输出 JSON（条目数 / 大小 / 更新时间 / 来源 / 状态）
  preview NAME [N]    输出清单前 N 行（供 UI 查看）
  update NAME|all     多源下载 → 校验 → 原子替换 → 写元数据
  auto HOURS          过期的自动清单才更新；有变更返回 0，无变更返回 1

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
UA = "mosdns-pref/1.0"

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
        "auto": False,
        "sources": [
            {"url": "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt"},
            {"url": "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/cn"},
        ],
    },
    "gfw_domains": {
        "file": "gfw_domains.txt",
        "label": "国外/GFW 域名",
        "kind": "domain",
        "min_lines": 100,
        "auto": False,
        "sources": [
            {"url": "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt"},
            {"url": "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/proxy-list.txt"},
        ],
    },
}

RE_IP = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$")
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
        if kind == "ip":
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
        out[name] = item
    print(json.dumps(out, ensure_ascii=False))


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


def update_one(name):
    """单清单更新：多源尝试，成功即原子替换；全失败保留旧文件。"""
    spec = LISTS[name]
    dst = os.path.join(DATA_DIR, spec["file"])
    os.makedirs(TMP_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)
    errors = []

    for src in spec["sources"]:
        url = src["url"] if isinstance(src, dict) else src
        parser = src.get("parser", "text") if isinstance(src, dict) else "text"
        try:
            raw = fetch(url)
            items = parse_apnic_cn(raw) if parser == "apnic_cn" else raw.splitlines()
            items = normalize(items, spec["kind"])
            if len(items) < spec["min_lines"]:
                errors.append("%s 有效条目过少(%d)" % (host_of(url), len(items)))
                continue

            body = ("\n".join(items) + "\n").encode("utf-8")
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
                "source": url,
                "updated_at": int(time.time()),
                "checked_at": int(time.time()),
                "lines": len(items),
                "bytes": len(body),
                "sha256": hashlib.sha256(body).hexdigest()[:16],
                "error": "",
            }
            meta_set(name, meta)
            return dict(meta, ok=True, name=name, label=spec["label"])
        except Exception as e:
            errors.append("%s: %s" % (host_of(url), str(e)[:100]))

    old = meta_all().get(name, {})
    meta = dict(old)
    meta.update({
        "status": "ok" if old.get("status") == "ok" else "fail",
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


def cmd_auto(hours):
    """只有标记 auto 且已过期的清单才更新；有变更返回 0。"""
    try:
        hours = float(hours)
    except Exception:
        hours = 24.0
    if hours <= 0:
        return 1
    now = time.time()
    changed = []
    for name, spec in LISTS.items():
        if not spec["auto"]:
            continue
        info = meta_all().get(name, {})
        last = info.get("updated_at") or 0
        if last and (now - last) < hours * 3600:
            continue
        r = update_one(name)
        if r.get("ok"):
            changed.append((name, r.get("lines"), host_of(r.get("source", ""))))
    if changed:
        print(json.dumps({"auto_updated": changed}, ensure_ascii=False))
        return 0
    return 1


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
        return cmd_auto(sys.argv[2] if len(sys.argv) > 2 else "24")
    print("未知命令: %s" % cmd, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
