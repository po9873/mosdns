#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""粘滞守卫：定时优选开关开着，也必须「能用就不换 IP」。

调用方：
  common.sh 的 run_route() 在写任何 hosts 之前先问本脚本；
  gt_pref.sh 在跑 gt_pin_refresh 之前再挡一道；
  auto_pref.sh 用 one 模式判断某个域名当前 IP 是否还能用。

判据与常驻守护完全一致（101 容器内 https_probe：严格证书 + TTFB + 可信吞吐），
不健康的补探 2 次，任一次能开就算健康，避免一次跨境抖动误杀好 IP。

退出码：
  0 = 在用 IP 全部能用（调用方立刻返回，hosts 一个字节都不改）
  1 = 有打不开的 IP（已由 101 精确补位，调用方同样不做全量重选）
  2 = 参数错误
"""
import json
import os
import sys
import time

sys.path.insert(0, "/app/scheduler/lib")
import watchdog as wd  # noqa: E402

DATA_DIR = os.environ.get("PREF_DATA_DIR", "/data")
PREF_DIR = os.path.join(DATA_DIR, "prefs")
HEAL_TS = os.path.join(DATA_DIR, ".sticky_heal_ts")
HEAL_GAP = 20  # 单路补位已经很便宜，别把后面几路的坏 IP 压到下一轮
SNAP_FILE = os.path.join(DATA_DIR, "health_snapshot.json")
SNAP_TTL = 90


def read_rows(route):
    path = os.path.join(PREF_DIR, route + ".hosts")
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 2 or parts[0].startswith("#"):
                    continue
                ips = parts[1:]
                # 纯 IPv6 行不算「在用 IP」：它会让 A 查询 NODATA、域名解析不出来。
                # 若这里还把它当成在用的好 IP 沿用，粘滞守卫会一直「保住」这条废行，
                # 导致 merge_hosts 永不重跑、坏记录永远留在 all.hosts 里。
                if not any(":" not in x for x in ips):
                    continue
                out.append((parts[0], ips))
    except Exception:
        pass
    return out


def cached(items):
    """复用常驻守护最近一轮的 101 实测结果，定时优选不再重复探测同一批 IP。"""
    try:
        d = json.load(open(SNAP_FILE, encoding="utf-8"))
        if time.time() - int(d.get("ts", 0)) > SNAP_TTL:
            return None
        raw = d.get("results") or {}
        out = {}
        for k in items:
            v = raw.get("%s|%s|%s" % k)
            if not isinstance(v, list) or len(v) < 4:
                return None
            out[k] = tuple(v[:4])
        return out
    except Exception:
        return None


def check_one(dom, ip, route="auto"):
    key = (route, dom, ip)
    res = wd._batch_health([key])
    return bool(res.get(key, (False, "fail", None, None))[0])


def heal_if_due(route, nbad):
    """同一次优选轮里七路都会调用守卫，别重复补位；补位日志走 stderr，
    不污染调用方从 stdout 读取的 STICKY_* 结果。"""
    now = time.time()
    try:
        last = float(open(HEAL_TS, encoding="utf-8").read().strip() or 0)
    except Exception:
        last = 0
    if now - last < HEAL_GAP:
        return
    old = sys.stdout
    devnull = None
    try:
        with open(HEAL_TS, "w", encoding="utf-8") as f:
            f.write(str(now))
        # wd.log 自己就写 pref.log；把 stdout 丢进 devnull，避免同一行日志
        # 被 shell 的 stderr 重定向再写一遍（日志成对重复的元凶）。
        devnull = open(os.devnull, "w")
        sys.stdout = devnull
        # 只修这一路：以前这里调的是全量 heal_once()，131 个跨境检查点
        # 每路都重跑一遍，优选一轮能拖到 5 分钟以上。
        n = wd.heal_once(route)
        wd.log("粘滞守卫：%s 路发现 %d 个打不开的 IP，101 已精确补位 %d 个；"
               "其余在用 IP 一律不动" % (route, nbad, n))
    except Exception as e:
        wd.log("粘滞守卫补位异常：%s（常驻守护下一轮会自行处理）" % e)
    finally:
        sys.stdout = old
        if devnull:
            try:
                devnull.close()
            except Exception:
                pass


def main():
    args = sys.argv[1:]
    if not args:
        print("usage: sticky_guard.py <route>|one <domain> <ip>", file=sys.stderr)
        return 2
    if args[0] == "one":
        if len(args) < 3:
            return 2
        route = args[3] if len(args) > 3 else "auto"
        return 0 if check_one(args[1], args[2], route) else 1

    route = args[0]
    rows = read_rows(route)
    # gt 路另有真翻自检 + gt_pin_refresh 粘滞模型，只核主域名（与守护一致）
    if route == "gt":
        rows = rows[:1]
    items = [(route, dom, ip) for dom, ips in rows for ip in ips]
    if not items:
        print("STICKY_BAD no-active-ip", end="")
        return 1

    res = cached(items) or wd._batch_health(items)
    bad = []
    for key in items:
        ok, st, _ms, _sp = res.get(key, (False, "fail", None, None))
        if not ok:
            bad.append("%s@%s(%s)" % (key[2], key[1], st))

    if bad:
        msg = "STICKY_BAD " + ",".join(bad[:8])
        rc = 1
        heal_if_due(route, len(bad))
    else:
        msg = "STICKY_OK %d" % len(items)
        rc = 0
    print(msg, end="")
    return rc


if __name__ == "__main__":
    sys.exit(main())
