#!/usr/bin/env python3
"""从查询日志里找「实际访问但体验慢」的域名。

前面几轮解决的是「已知的那几路被限速」，这里是补最后一块：用户真正在访问、
但根本没配优选、也没人去管的域名。判据不是猜的，是拿日志里的真实查询量 +
现场实测的响应/吞吐说话：
  1) 从 mosdns.log 尾巴统计最近被查最多的域名（没人访问的域名不折腾）
  2) 对它们现场发一次真实 HTTPS 请求，量出 TTFB 和吞吐
  3) 慢的（TTFB 超阈值 / 吞吐低于阈值）写进 /data/prefs/.slow.json，
     交给 auto_pref.sh 去找更快的 IP 换上

用法: python3 slow_scan.py [prefs_dir]
输出（stdout）: 一行一个 "域名 当前IP 延时ms 速度KB/s 原因"，方便直接看
"""
import json
import os
import subprocess
import sys
import time

_here = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("PREF_DATA_DIR") or "/data"
LOG = os.path.join(DATA_DIR, "mosdns.log")
OUT = os.path.join(os.environ.get("PREF_DATA_DIR") or "/data", "prefs", ".slow.json")

# 这些不归自动治理管：内网/本地名、以及明显是国内的域名（国内直连本来就快，
# 慢也是对方的问题，换 IP 没意义，还容易把国内服务指到国外去）
SKIP_SUFFIX = (".local", ".arpa", ".lan", ".home", ".internal", ".in-addr.arpa",
               "localhost", ".workgroup", ".mshome.net")


def tail_lines(path, n):
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 4 * 1024 * 1024))
            data = f.read().decode("utf-8", "ignore")
        return data.splitlines()[-n:]
    except Exception:
        return []


def _line_ts(ln):
    """取日志行开头的时间戳（mosdns 每行以 2026-10-30T01:02:03 这类开头）。"""
    try:
        s = ln[:25].replace("T", " ")
        return time.mktime(time.strptime(s[:19], "%Y-%m-%d %H:%M:%S"))
    except Exception:
        return None


def top_domains(n=15):
    """取「最该管」的 N 个域名：查询次数多、且持续访问时间长。

    只看次数会被一次性刷屏的域名（装插件、一次性更新）顶掉真正一直在用的；
    只看时长又会把偶尔一条的算进来。所以两个都算：
      score = 查询次数 × (1 + 持续分钟/60)
    持续访问十分钟以上的域名权重明显高于刚出现一次的。
    """
    hits, first, last = {}, {}, {}
    for ln in tail_lines(LOG, 8000):
        if '"qname"' not in ln and "query summary" not in ln:
            continue
        p = ln.find("{")
        if p < 0:
            continue
        try:
            obj = json.loads(ln[p:])
        except Exception:
            continue
        q = (obj.get("qname") or obj.get("QNAME") or "").rstrip(".").lower()
        if not q or q.startswith(("_", "-")):
            continue
        if any(q.endswith(s) for s in SKIP_SUFFIX):
            continue
        if q.count(".") < 1:
            continue
        hits[q] = hits.get(q, 0) + 1
        ts = _line_ts(ln)
        if ts:
            first[q] = min(first.get(q, ts), ts)
            last[q] = max(last.get(q, ts), ts)
    scored = []
    for d, c in hits.items():
        span_min = int((last.get(d, 0) - first.get(d, 0)) / 60.0) if d in first else 0
        scored.append((d, c * (1 + span_min / 60.0), span_min))
    scored.sort(key=lambda x: -x[1])
    return [d for d, _, _ in scored[:n]], hits, {d: sp for d, _, sp in scored}


def resolve(domain, port=53):
    try:
        out = subprocess.run([sys.executable, os.path.join(_here, "dnsq.py"),
                              "127.0.0.1", str(port), domain, "A"],
                             capture_output=True, text=True, timeout=8).stdout
        ips = [x.strip() for x in out.split() if x.strip().count(".") == 3]
        return ips[:3]
    except Exception:
        return []


def probe(domain, ips, conc=6, timeout=5):
    if not ips:
        return []
    try:
        out = subprocess.run([sys.executable, os.path.join(_here, "https_probe.py"),
                              domain, "443", str(timeout), str(conc), "1", "/", "", ""],
                             input="\n".join(ips) + "\n",
                             capture_output=True, text=True, timeout=90).stdout
    except Exception:
        return []
    rows = []
    for line in out.splitlines():
        f = line.split()
        if len(f) < 3 or f[1] != "ok":
            continue
        try:
            lat = float(f[2])
        except ValueError:
            lat = None
        sp = None
        if len(f) > 3 and f[3] not in ("-", ""):
            try:
                sp = float(f[3].lstrip("~"))
            except ValueError:
                sp = None
        rows.append((f[0], lat, sp))
    return rows


def main():
    d = sys.argv[1] if len(sys.argv) > 1 else os.path.join(DATA_DIR, "prefs")
    os.makedirs(d, exist_ok=True)
    out_path = os.path.join(d, ".slow.json")
    ttfb_max = float(os.environ.get("SLOW_TTFB_MS", "1200"))
    min_kb = float(os.environ.get("SLOW_MIN_KBPS", "200"))

    doms, hits, spans = top_domains()
    slow = []
    for dom in doms:
        ips = resolve(dom)
        if not ips:
            continue
        rows = probe(dom, ips)
        if not rows:
            continue
        best = min(rows, key=lambda r: (r[1] or 9e9))
        why = ""
        if best[1] is not None and best[1] > ttfb_max:
            why = "响应 %dms" % int(best[1])
        elif best[2] is not None and best[2] < min_kb:
            why = "吞吐 %dKB/s" % int(best[2])
        if why:
            slow.append({"domain": dom, "ip": best[0], "latency": best[1],
                         "speed": best[2], "why": why, "hits": hits.get(dom, 0),
                         "span_min": spans.get(dom, 0),
                         "all": [r[0] for r in rows]})
            print("%s %s %sms %sKB/s 持续%sm %s" % (dom, best[0],
                  int(best[1] or 0), int(best[2] or 0), spans.get(dom, 0), why), flush=True)
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump({"at": int(time.time()), "slow": slow}, f)
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
