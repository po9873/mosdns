#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""域名自动发现：从 mosdns 查询日志里捞「属于某条优选路、但还没映射」的域名。

背景：各路的附加域名清单（PREF_EXTRA_DOMAINS）是硬编码的，IP 变了能自动跟，
但服务方新增域名（如 Gmail 的 content-gmail.googleapis.com）不会自己出现——
那次 Gmail 打不开就是漏映射。这里补上闭环：日志里真实被查过、后缀属于
某路域名族、且不在任何 hosts 里的域名，自动登记给该路下一轮优选探测；
逐 IP 真实 HTTPS 校验通过才写进 hosts（校验不过的永远不会映射）。

用法:
    python3 dom_watch.py scan          # 扫一轮日志，更新各路待映射清单
    python3 dom_watch.py list          # 查看当前登记情况（JSON）

文件:
    /data/prefs/.autodom/<route>.txt   各路待映射域名（write_route 消费）
    /data/prefs/.autodom.json          状态（最近发现时间，14 天没再查的清掉）
    /data/prefs/.autodom.deny          用户排除清单（每行一个后缀，# 注释）
"""

import json
import os
import re
import time

DATA_DIR = os.environ.get("PREF_DATA_DIR", "/data")
PREF_DIR = os.path.join(DATA_DIR, "prefs")
QLOG = os.path.join(DATA_DIR, "mosdns.log")
STATE_FILE = os.path.join(PREF_DIR, ".autodom.json")
DENY_FILE = os.path.join(PREF_DIR, ".autodom.deny")
AUTO_DIR = os.path.join(PREF_DIR, ".autodom")

# 日志可能很大，只读末尾这段（覆盖上一轮周期足够）
TAIL_BYTES = 4 * 1024 * 1024
QNAME_RE = re.compile(r'"qname":\s*"([^"]+)"')

KEEP_DAYS = 14          # 超过这么久没再被查的域名从登记里清掉
MAX_PER_ROUTE = 40      # 每路最多登记多少个（防日志异常把清单撑爆）

# 域名族 → 优选路。匹配取「最长后缀命中」，所以
# objects.githubusercontent.com 命中 githubusercontent.com（github），
# ghcr.io 命中 ghcr —— 已经映射过的域名反正会被排除，这里只管「漏网的」。
# 故意不收的：youtube.com / googlevideo.com / ytimg.com（视频流量不走中转）、
# 广告域名（googleadservices 等，AdGuard 在前面就拦了，到不了这层日志）。
FAMILIES = [
    ("google", ("google.com", "googleapis.com", "gstatic.com",
                "googleusercontent.com", "ggpht.com", "withgoogle.com", "gvt1.com")),
    ("gt", ("translate.googleapis.com", "translate.googleusercontent.com",
            "clients5.google.com")),
    ("github", ("github.com", "githubassets.com", "github.io",
                "githubusercontent.com")),
    ("ghcr", ("ghcr.io",)),
    ("tmdb", ("themoviedb.org",)),
    ("imdb", ("imdb.com", "media-imdb.com", "media-amazon.com")),
]


def _log(msg):
    line = "[%s] [dom_watch] %s" % (time.strftime("%m-%d %H:%M:%S"), msg)
    try:
        with open(os.path.join(DATA_DIR, "pref.log"), "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
    print(line, file=__import__("sys").stderr)


def read_deny():
    """用户排除清单：每行一个后缀（匹配它自身及其子域）。"""
    out = set()
    try:
        with open(DENY_FILE, encoding="utf-8") as f:
            for ln in f:
                s = ln.split("#", 1)[0].strip().lower().rstrip(".")
                if s:
                    out.add(s)
    except Exception:
        pass
    return out


def mapped_domains():
    """所有 hosts 文件里已映射的域名（精确集合）。"""
    have = set()
    try:
        for name in os.listdir(PREF_DIR):
            if not name.endswith(".hosts") or name.startswith("all.hosts"):
                continue
            with open(os.path.join(PREF_DIR, name), encoding="utf-8") as f:
                for ln in f:
                    p = ln.split()
                    if p:
                        have.add(p[0].lower())
    except Exception:
        pass
    return have


def recent_qnames():
    """日志末尾出现过的查询域名（去重、去尾点、小写）。"""
    names = set()
    try:
        size = os.path.getsize(QLOG)
        with open(QLOG, "rb") as f:
            if size > TAIL_BYTES:
                f.seek(size - TAIL_BYTES)
                f.readline()  # 跳过半行
            for raw in f:
                m = QNAME_RE.search(raw.decode("utf-8", "replace"))
                if m:
                    names.add(m.group(1).rstrip(".").lower())
    except FileNotFoundError:
        pass
    except Exception as e:
        _log("读日志失败：%s" % e)
    return names


def match_route(qname):
    """返回域名所属的优选路；不属任何族返回 None。最长后缀优先。"""
    best, best_len = None, 0
    for route, suffixes in FAMILIES:
        for sfx in suffixes:
            if qname == sfx or qname.endswith("." + sfx):
                if len(sfx) > best_len:
                    best, best_len = route, len(sfx)
    return best


def load_state():
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            st = json.load(f)
        return st if isinstance(st, dict) else {}
    except Exception:
        return {}


def scan():
    now = time.time()
    deny = read_deny()
    have = mapped_domains()
    state = load_state()
    doms = state.get("domains") if isinstance(state.get("domains"), dict) else {}

    seen = recent_qnames()
    found = {}
    for q in seen:
        if q in have or q in doms:
            continue
        route = match_route(q)
        if not route:
            continue
        if any(q == d or q.endswith("." + d) for d in deny):
            continue
        found.setdefault(route, []).append(q)

    if found:
        for route, lst in found.items():
            for q in lst:
                doms[q] = {"route": route, "seen": now}
        _log("发现未映射域名: " + "; ".join(
            "%s 路 %d 个（%s）" % (r, len(v), " ".join(sorted(v)[:5]) + ("…" if len(v) > 5 else ""))
            for r, v in sorted(found.items())))

    # 清掉长期没人查的
    stale = [d for d, v in doms.items() if now - v.get("seen", 0) > KEEP_DAYS * 86400]
    for d in stale:
        doms.pop(d, None)
    if stale:
        _log("清理 %d 个 %d 天没再被查的域名" % (len(stale), KEEP_DAYS))

    # 按路分组写待映射清单（最近查过的排前面，超限截断）
    os.makedirs(AUTO_DIR, exist_ok=True)
    by_route = {}
    for d, v in doms.items():
        by_route.setdefault(v.get("route"), []).append((v.get("seen", 0), d))
    for route, items in by_route.items():
        items.sort(reverse=True)
        keep = [d for _ts, d in items[:MAX_PER_ROUTE]]
        try:
            with open(os.path.join(AUTO_DIR, "%s.txt" % route), "w", encoding="utf-8") as f:
                f.write("\n".join(keep) + ("\n" if keep else ""))
        except Exception as e:
            _log("写 %s 待映射清单失败：%s" % (route, e))
    # 没有条目的路也要清空残留文件，避免旧域名被反复探测
    for route, _sfx in FAMILIES:
        p = os.path.join(AUTO_DIR, "%s.txt" % route)
        if route not in by_route and os.path.exists(p):
            try:
                open(p, "w").close()
            except Exception:
                pass

    state["domains"] = doms
    state["at"] = now
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=1)
    except Exception as e:
        _log("状态写不进 %s：%s" % (STATE_FILE, e))
    return {"found": {r: len(v) for r, v in found.items()},
            "tracked": len(doms), "stale": len(stale)}


def list_state():
    st = load_state()
    return {"at": st.get("at", 0),
            "domains": sorted(st.get("domains", {}).keys())}


if __name__ == "__main__":
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else "scan"
    if cmd == "list":
        print(json.dumps(list_state(), ensure_ascii=False, indent=1))
    else:
        print(json.dumps(scan(), ensure_ascii=False))
