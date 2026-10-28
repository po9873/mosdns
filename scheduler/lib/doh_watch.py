#!/usr/bin/env python3
# ============================================================
# DoH 上游定时扫描：一直盯着候选池，看有没有新变得可用的。
#
# 为什么要有它：上游是会变的——今天被墙的 DoH 明天可能通了，今天能用的
# 明天可能挂掉。配置里写死的那几条不会自己发现这件事，于是「DNS 活着但
# 用的是一条已经死掉的上游」就成了最难查的故障。
#
# 两种模式的行为刻意不同：
#   auto（没手动配过）：能用的换了就换，失效的自动替换成最快的可用项；
#   manual（控制台手填过）：一条都不动，只把「新可用」记下来给界面提示，
#                            要不要补进来由用户点。
#
# 用法:
#   doh_watch.py scan [--force]   扫描（默认按 settings.doh_scan_min 限频）
#   doh_watch.py status           打印上次扫描结果
# ============================================================
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import doh_config as dc  # noqa: E402
import doh_probe as dp  # noqa: E402

DATA_DIR = dc.DATA_DIR
SETTINGS = os.path.join(DATA_DIR, "settings.json")
SCAN_FILE = dc.SCAN_FILE
POOL = {
    "local": os.path.join(DATA_DIR, "doh_local_candidates.txt"),
    "remote": os.path.join(DATA_DIR, "doh_remote_candidates.txt"),
}
QNAME = {"local": "www.baidu.com", "remote": "www.google.com"}
LABEL = {"local": "国内", "remote": "国外"}
_here = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SEED_DIR = os.environ.get("PREF_SEED_DIR") or ("/app/config" if os.path.isdir("/app/config") else os.path.join(_here, "config"))


def _log(msg):
    print("[doh] " + msg, file=sys.stderr, flush=True)
    try:
        with open(os.path.join(DATA_DIR, "pref.log"), "a", encoding="utf-8") as f:
            f.write("[%s] [doh] %s\n" % (time.strftime("%m-%d %H:%M:%S"), msg))
    except Exception:
        pass


def settings():
    try:
        with open(SETTINGS, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def load_scan():
    try:
        with open(SCAN_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_scan(obj):
    tmp = SCAN_FILE + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
        os.replace(tmp, SCAN_FILE)
    except Exception as e:
        _log("扫描结果写不进去：%s" % e)


def read_pool(path):
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for ln in f:
                ln = ln.split("#", 1)[0].strip()
                if ln:
                    out.append(ln)
    except Exception:
        pass
    return out


def _url(line):
    return str(line).split()[0] if str(line).strip() else ""


def sync_pool(k):
    """候选池 = /data 用户清单 + 镜像内置清单（按 URL 去重）。

    镜像升级时如果内置清单多了新候选，这里会把它们补进 /data 文件，
    让「重启后的启动探测」和「定时扫描」看到的是同一份池子，
    不会出现「扫描用了 A 组、重启后又回到 B 组」的来回跳。
    """
    lines = read_pool(POOL[k])
    seed = read_pool(os.path.join(SEED_DIR, "doh_%s_candidates.txt" % k))
    have = {_url(x) for x in lines}
    added = [s for s in seed if _url(s) not in have]
    if added and lines:
        try:
            with open(POOL[k], "a", encoding="utf-8") as f:
                f.write("\n# 以下由定时扫描从内置清单补入（%s）\n" % time.strftime("%Y-%m-%d"))
                f.write("\n".join(added) + "\n")
            _log("候选池补充 %d 条（%s，来自内置清单）" % (len(added), LABEL[k]))
        except Exception as e:
            _log("候选补充写不进 %s：%s" % (POOL[k], e))
    return lines + added, len(added)


def plan_side(k, alive, current, keep):
    """决定这一侧最终用哪几条。

    规则：
      1) 现在正用着、而且仍然通的，原样留着（连 dial_addr 一起）——避免每轮
         扫描都换一遍，换一次就是一次重载，DNS 会有极短抖动；
      2) 同一地址只是 IP 变了，也仍算活着；
      3) 不够 keep 条，用最快的补；
      4) 一条都不通时返回 None，表示「这侧别动」（多半是整网断了，
         不该因为一次扫描失败就把 DNS 上游全清掉）。
    """
    if not alive:
        return None
    by_line = {r["line"]: r for r in alive}
    by_url = {_url(r["line"]): r for r in alive}
    picked, seen = [], set()
    for line in current:
        u = _url(line)
        if not u or u in seen:
            continue
        if line in by_line:
            picked.append(line)
            seen.add(u)
        elif u in by_url:
            picked.append(by_url[u]["line"])
            seen.add(u)
    for r in alive:
        if len(picked) >= keep:
            break
        u = _url(r["line"])
        if u not in seen:
            picked.append(r["line"])
            seen.add(u)
    return picked[:keep]


def scan(force=False):
    lock = os.path.join(DATA_DIR, ".doh_scan.lock")
    if not _acquire(lock):
        return {"skipped": True, "reason": "已有一次扫描正在进行"}
    try:
        return _scan_locked(force)
    finally:
        try:
            os.remove(lock)
        except Exception:
            pass


def _acquire(lock, stale=900):
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, str(int(time.time())).encode())
        os.close(fd)
        return True
    except FileExistsError:
        try:
            if time.time() - os.path.getmtime(lock) > stale:
                os.remove(lock)
                return _acquire(lock)
        except Exception:
            pass
        return False
    except Exception:
        return True


def _scan_locked(force=False):
    st = settings()
    if str(st.get("doh_scan_enabled", "true")).lower() in ("false", "0", "no"):
        return {"skipped": True, "reason": "定时扫描已在配置中关闭"}

    try:
        due = max(5, int(st.get("doh_scan_min") or 60))
    except Exception:
        due = 60
    try:
        keep = max(1, min(6, int(st.get("doh_keep") or 3)))
    except Exception:
        keep = 3

    prev = load_scan()
    now = int(time.time())
    if not force and prev.get("at") and now - int(prev["at"]) < due * 60 and prev.get("pool_total"):
        return {"skipped": True, "reason": "距上次扫描不足 %d 分钟" % due,
                "at": prev.get("at"), "summary": prev.get("summary", "")}

    t0 = time.time()
    pools, seeded = {}, {}
    for k in ("local", "remote"):
        pools[k], seeded[k] = sync_pool(k)
    # 正在用的那几条也一起测：这样「原样保留」才是验证过的保留，
    # 而不是看着地址一样就默认它还活着（dial_addr 也能一起留住）。
    act = dc.active()
    for k in ("local", "remote"):
        for line in act[k]:
            # 按「整行」判断，不按 URL：候选里可能只有不带 IP 的那种写法，
            # 而正在用的这条带着 dial_addr，必须让它也参加探测，
            # 否则会把验证过的好 IP 顺手丢掉。
            if _url(line) and line not in pools[k]:
                pools[k].append(line)
    results = {}
    for k in ("local", "remote"):
        results[k] = dp.probe_many(pools[k], qname=QNAME[k], timeout=5, workers=12)
    alive = {k: sorted([r for r in results[k] if r["ok"]], key=lambda r: r["ms"]) for k in ("local", "remote")}

    cfg_text = dc.read_cfg()
    act = dc.active(cfg_text)
    manual = dc.is_manual()

    plan, dead, new = {}, [], []
    for k in ("local", "remote"):
        act_urls = {_url(x) for x in act[k]}
        alive_urls = {_url(r["line"]) for r in alive[k]}
        for x in act[k]:
            if alive_urls and _url(x) not in alive_urls:
                dead.append(x)
        for r in alive[k]:
            if _url(r["line"]) not in act_urls and not manual:
                new.append({"side": k, "line": r["line"], "ms": r["ms"], "ip": r["ip"]})
        plan[k] = plan_side(k, alive[k], act[k], keep)

    applied, changed_sides = False, []
    if not manual:
        loc = plan.get("local") or []
        rem = plan.get("remote") or []
        if loc or rem:
            if dc.apply_entries(loc, rem):
                applied = True
                for k, want in (("local", loc), ("remote", rem)):
                    if want and {_url(x) for x in want} != {_url(x) for x in act[k]}:
                        changed_sides.append(LABEL[k])
                dc.reload_engine()

    act_after = dc.active()
    new_after = []
    for k in ("local", "remote"):
        act_urls = {_url(x) for x in act_after[k]}
        for r in alive[k]:
            if _url(r["line"]) not in act_urls:
                new_after.append({"side": k, "line": r["line"], "ms": r["ms"], "ip": r["ip"]})

    summary = "候选 %d/%d 条，可用 %d/%d 条" % (
        len(pools["local"]), len(pools["remote"]), len(alive["local"]), len(alive["remote"]))
    if applied:
        summary += "，已自动换用新上游（%s）" % "、".join(changed_sides or ["已更新"])
    elif manual:
        summary += "，手动模式不动配置"
    if dead:
        summary += "，失效 %d 条" % len(dead)
    if manual and new_after:
        summary += "，发现 %d 条新可用" % len(new_after)

    out = {
        "at": now,
        "took_ms": int((time.time() - t0) * 1000),
        "mode": "manual" if manual else "auto",
        "applied": applied,
        "changed_sides": changed_sides,
        "keep": keep,
        "due_min": due,
        "pool": {k: len(pools[k]) for k in pools},
        "pool_total": len(pools["local"]) + len(pools["remote"]),
        "seeded": seeded,
        "alive": {k: [{"line": r["line"], "ms": r["ms"], "ip": r["ip"]} for r in alive[k]] for k in alive},
        "active": act_after,
        "dead": dead,
        "new": new_after if manual else new,
        "failed": {k: [{"line": r["line"], "err": r["err"]} for r in results[k] if not r["ok"]][:8]
                   for k in results},
        "qname": QNAME,
        "summary": summary,
    }
    save_scan(out)
    _log("扫描完成（%.1fs）：%s" % (out["took_ms"] / 1000.0, summary))
    return out


def main(argv):
    cmd = argv[1] if len(argv) > 1 else "scan"
    if cmd in ("scan", "auto"):
        r = scan(force="--force" in argv)
    elif cmd == "status":
        r = load_scan() or {"at": 0, "summary": "从未扫描"}
    else:
        print("用法: doh_watch.py {scan [--force]|status}", file=sys.stderr)
        return 2
    print(json.dumps(r, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
