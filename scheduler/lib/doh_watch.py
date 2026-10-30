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
import ipaddress
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
WATCH = os.path.join(DATA_DIR, "doh_watchlist.txt")
PROMOTE_AFTER = 2   # 连续可用几轮才收编进候选池
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
    # 老清单里可能有写错的地址（把普通 DNS 的 IP 当 DoH 端点），
    # 扫描时先统一纠正，免得每轮都白跑一趟还写进「不通」
    return dc.normalize_pool(out)


def _url(line):
    return str(line).split()[0] if str(line).strip() else ""


def sync_pool(k):
    """候选池 = /data 用户清单 + 镜像内置清单（按整行去重）。

    镜像升级时如果内置清单多了新候选，这里会把它们补进 /data 文件，
    让「重启后的启动探测」和「定时扫描」看到的是同一份池子，
    不会出现「扫描用了 A 组、重启后又回到 B 组」的来回跳。

    去重键是整行而不是 URL：同一个服务常有多个 anycast 入口
    （dns.controld.com 就有 76.76.2.0~2.5），
    按 URL 去重会把备用入口全吃掉，只剩一条能试。

    补过的种子行记在 .doh_seeded.json：删掉的死条目不会再被补回来，
    否则「扫描删掉 → 下轮种子补回」会死循环，面板上永远挂着一堆不通。
    """
    lines = read_pool(POOL[k])
    seed = read_pool(os.path.join(SEED_DIR, "doh_%s_candidates.txt" % k))
    hist = _seeded_history()
    done = set(hist.get(k) or [])
    have = {x for x in lines}
    added = [s for s in seed if s not in have and s not in done]
    if added and lines:
        try:
            with open(POOL[k], "a", encoding="utf-8") as f:
                f.write("\n# 以下由定时扫描从内置清单补入（%s）\n" % time.strftime("%Y-%m-%d"))
                f.write("\n".join(added) + "\n")
            _log("候选池补充 %d 条（%s，来自内置清单）" % (len(added), LABEL[k]))
        except Exception as e:
            _log("候选补充写不进 %s：%s" % (POOL[k], e))
    if added:
        hist[k] = sorted(done | set(added))
        _save_seeded(hist)
    return lines + added, len(added)


SEED_MARK = os.path.join(DATA_DIR, ".doh_seeded.json")


def _seeded_history():
    try:
        with open(SEED_MARK, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _save_seeded(d):
    try:
        tmp = SEED_MARK + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=1)
        os.replace(tmp, SEED_MARK)
    except Exception:
        pass


# ---- 观察名单：新上游的「转正」通道 ----
# 用户把听说的新 DoH 地址丢进 /data/doh_watchlist.txt，每轮扫描顺带探测：
# 连续 PROMOTE_AFTER 轮可用就自动写进对应候选池（并参与本轮选用），
# 一直不通的留在名单里不碍事。池子边界由此变成「可生长」的：
# 候选池里没有的服务，也有一条不用改配置、不用重启的进院子的路。

def read_watchlist():
    out = []
    try:
        with open(WATCH, encoding="utf-8", errors="replace") as f:
            for ln in f:
                ln = ln.split("#", 1)[0].strip()
                if ln:
                    out.append(ln)
    except Exception:
        pass
    return dc.normalize_pool(out)


def _watch_split(line):
    """行首 @local / @remote 指定侧；不写就按探测连接 IP 的归属自动分侧。"""
    parts = str(line).split(None, 1)
    if parts and parts[0] in ("@local", "@remote"):
        return parts[0][1:], (parts[1].strip() if len(parts) > 1 else "")
    return "", str(line).strip()


_CN_NETS = None


def _is_cn_ip(ip):
    """连接 IP 落在国内段库（china_ip.txt）里才算国内上游。

    为什么不靠「哪侧探测通了」分侧：正常 DoH 会应答任何域名，
    阿里查 google 也返回 200——按通不通分，国内服务全被收进国外池，
    国外域名就拿到污染答案了。IP 归属才是唯一可靠信号。
    """
    global _CN_NETS
    if _CN_NETS is None:
        nets = []
        try:
            with open(os.path.join(DATA_DIR, "china_ip.txt"), encoding="utf-8", errors="replace") as f:
                for ln in f:
                    ln = ln.strip()
                    if ln and not ln.startswith("#"):
                        try:
                            nets.append(ipaddress.ip_network(ln, strict=False))
                        except Exception:
                            pass
        except Exception:
            pass
        _CN_NETS = nets
    try:
        a = ipaddress.ip_address(str(ip or "").strip("[]"))
    except Exception:
        return False
    return any(a in n for n in _CN_NETS)


def process_watchlist(pools, alive, prev):
    """探测观察名单，够格的收编进候选池。返回 (收编记录, 计数状态)。"""
    wlines = read_watchlist()
    if not wlines:
        return [], {}
    raw_state = prev.get("watch_ok") if isinstance(prev, dict) else None
    wst = dict(raw_state) if isinstance(raw_state, dict) else {}
    entries = []
    for raw in wlines:
        side, rest = _watch_split(raw)
        if rest:
            entries.append((raw, side, rest))
    if not entries:
        return []

    # 探测：连通性跟 qname 无关（DoH 都会应答），按侧分组各探一次即可
    by_q = {}
    for _raw, side, rest in entries:
        by_q.setdefault(QNAME[side] if side else dp.pick_qname([rest], "www.baidu.com"), []).append(rest)
    wres = {}
    for qn, lines_s in by_q.items():
        for r in dp.probe_many(lines_s, qname=qn, timeout=5, workers=8):
            wres[r["line"]] = r

    promoted, kept = [], []
    pool_urls = {k: {_url(x) for x in pools[k]} for k in pools}
    changed = False
    for raw, side, rest in entries:
        r = wres.get(rest)
        if not r or not r.get("ok"):
            wst[raw] = 0
            kept.append(raw)
            continue
        if not side:
            # 未指定侧：按实际连接 IP 的归属分——国内段进国内池，其余进国外池
            side = "local" if _is_cn_ip(r.get("ip")) else "remote"
        cand = side
        # 候选池里已有同 URL 的条目 → 无需收编，移出名单即可
        if _url(rest) in pool_urls[cand]:
            wst.pop(raw, None)
            promoted.append({"side": cand, "line": rest, "ms": r["ms"], "ip": r.get("ip", ""),
                             "note": "已在候选池，移出观察名单"})
            changed = True
            continue
        n = wst.get(raw, 0) + 1
        if n < PROMOTE_AFTER:
            wst[raw] = n
            kept.append(raw)
            _log("观察名单 %s 可用 %d/%d（%d ms），再观察一轮" % (rest, n, PROMOTE_AFTER, r["ms"]))
            continue
        # 转正：写进候选池，并并入本轮可用集合参与选用
        try:
            with open(POOL[cand], "a", encoding="utf-8") as f:
                f.write("\n# 以下由观察名单收编（%s）\n%s\n" % (time.strftime("%Y-%m-%d"), rest))
            pool_urls[cand].add(_url(rest))
            pools[cand].append(rest)
            alive[cand].append({"line": rest, "ok": True, "ms": r["ms"],
                                "ip": r.get("ip", ""), "err": ""})
            alive[cand].sort(key=lambda x: x["ms"])
            wst.pop(raw, None)
            promoted.append({"side": cand, "line": rest, "ms": r["ms"], "ip": r.get("ip", ""),
                             "note": "已收编进候选池"})
            changed = True
            _log("观察名单收编：%s -> %s 候选池（%d ms）" % (rest, LABEL[cand], r["ms"]))
        except Exception as e:
            _log("观察名单收编失败（%s）：%s" % (rest, e))
            kept.append(raw)

    if changed:
        # 重写观察名单：注释原样保留，条目只留未收编的
        try:
            comments = []
            with open(WATCH, encoding="utf-8", errors="replace") as f:
                for ln in f:
                    if ln.strip() and not ln.split("#", 1)[0].strip():
                        comments.append(ln.rstrip("\n"))
            tmp = WATCH + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                for c in comments:
                    f.write(c + "\n")
                if kept:
                    f.write("\n".join(kept) + "\n")
            os.replace(tmp, WATCH)
        except Exception as e:
            _log("观察名单重写失败：%s" % e)
    return promoted, wst


def plan_side(k, alive, current, keep, protect=()):
    """决定这一侧最终用哪几条。

    规则：
      0) 延时优先：在用的逐条体检。只要候选池里有一条明显更快（快 30ms 以上
         或快 30% 以上），就把这条慢的换掉——只看「全局最快 vs 在用最快」
         是不够的：在用三条里只要夹着一条 241ms 的，就够拖慢整轮解析
         （同一个 IP 换成域名写法常常就从 241ms 掉到 14ms，那种最该换）；
         上一轮刚换进来的那条给一轮豁免（除非新候选快一倍），否则测量噪声
         会让 A→B→A 来回换，每换一次引擎就要重载一次；
      1) 体检没换掉的，原样留着（连 dial_addr 一起）——换一次就是一次重载，
         在用的本来就是最快的那批时不要没事抖一下；
      2) 第一轮每个服务只取最快的一个入口，先保证「多家」而不是「一家多 IP」；
      3) 还不够 keep 条，再拿同一服务的其它 anycast 入口补（这些是真冗余：
         某条路由被掐时另一条往往还通，对只有一家能用的网络很关键）；
      4) 一条都不通时返回 None，表示「这侧别动」（多半是整网断了，
         不该因为一次扫描失败就把 DNS 上游全清掉）。
    """
    if not alive:
        return None
    by_line = {r["line"]: r for r in alive}
    by_url = {_url(r["line"]): r for r in alive}
    picked = []

    def seen_line():
        return {x["line"] for x in picked}

    def seen_url():
        return {_url(x["line"]) for x in picked}

    def take(r):
        picked.append(r)

    # 正在用、而且这轮还通的（按整行找，找不到再按 URL 找：配置里那条
    # 可能带着 dial_addr，候选里写的是不带 IP 的写法）
    cur_alive = []
    for line in current:
        r = by_line.get(line) or by_url.get(_url(line) or "")
        if r and all(r["line"] != x["line"] for x in cur_alive):
            cur_alive.append(r)
    cur_lines = {x["line"] for x in cur_alive}

    # 先按延时占位：快的先占位，keep 装不下时慢的自然落榜
    for r in sorted(cur_alive, key=lambda x: x["ms"]):
        if len(picked) >= keep:
            break
        take(r)

    def free_best():
        """候选池里还没被挑走的最快一条。

        优先挑「本来没在用」的，免得把 241ms 那条换成一条已经在用的、白换一次；
        再优先挑「落地 IP 还没出现在已选里」的——两条都落在同一个 IP 上，
        快是快，可一旦那个 IP 被掐就一起完，冗余等于没有。
        """
        sl, su = seen_line(), seen_url()
        ips = {x.get("ip") for x in picked if x.get("ip")}
        free = [x for x in alive if x["line"] not in sl and _url(x["line"]) not in su]
        c = [x for x in free if x["line"] not in cur_lines and x.get("ip") not in ips]
        if not c:
            c = [x for x in free if x["line"] not in cur_lines]
        if not c:
            c = free
        return min(c, key=lambda x: x["ms"]) if c else None

    # 0) 延时优先：慢的先挑人，免得快的先把候选池里最快的占走
    protect = {str(x).strip() for x in (protect or ())}
    for r in sorted(picked, key=lambda x: x["ms"], reverse=True):
        c = free_best()
        if not c:
            break
        gain = r["ms"] - c["ms"]
        if gain >= 30 or c["ms"] <= r["ms"] * 0.7:
            # 刚换进来的那条：除非新候选快一倍，否则这轮先不折腾它
            if r["line"] in protect and c["ms"] > r["ms"] * 0.5:
                continue
            _log("up: %s侧 %s 在用 %.0fms 偏慢，换成 %s（%.0fms，快 %.0fms）"
                 % (LABEL.get(k, k), _url(r["line"]), r["ms"], _url(c["line"]), c["ms"], gain))
            picked[picked.index(r)] = c

    # 1) 在用的、仍通的，留着
    for line in current:
        if len(picked) >= keep:
            break
        r = by_line.get(line) or by_url.get(_url(line) or "")
        if not r:
            continue
        if r["line"] in seen_line() or _url(r["line"]) in seen_url():
            continue
        take(r)

    # 2) 先按「一家一条」补齐
    for r in alive:
        if len(picked) >= keep:
            break
        if _url(r["line"]) not in seen_url() and r["line"] not in seen_line():
            take(r)

    # 3) 还不够，再用同服务的其它入口补冗余
    for r in alive:
        if len(picked) >= keep:
            break
        if r["line"] not in seen_line():
            take(r)

    return [r["line"] for r in picked[:keep]]


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
    # 先自己找一遍新上游：内置清单只是种子，每轮重新解析服务商域名、试各端点
    # 路径，能正确应答 DNS 的就写进观察名单，后面的 process_watchlist 照老规矩
    # 「连续两轮可用才收编」。服务商换 IP / 加端点不用人管。
    try:
        import doh_discover
        doh_discover.run_once(force=force)
    except Exception as e:
        _log("doh: 自动发现这轮没跑起来（%s），不影响已配好的上游" % e)

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
        # 并发压到 4：12 路一起握手，谁先抢到谁快，测出来的 ms 里混着排队时间，
        # 同一条上游能被报成 466ms（实际转发 103ms），拿这种数做「换不换」的
        # 判断就是拿噪声当依据。慢一点没关系，一小时才扫一次。
        results[k] = dp.probe_many(pools[k], qname=QNAME[k], timeout=5, workers=4)
    alive = {k: sorted([r for r in results[k] if r["ok"]], key=lambda r: r["ms"]) for k in ("local", "remote")}

    # 观察名单：够格的新上游在这里转正（写候选池 + 并入本轮可用集合）
    promoted, watch_ok = [], {}
    try:
        promoted, watch_ok = process_watchlist(pools, alive, prev)
    except Exception as e:
        _log("观察名单处理失败：%s" % e)

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
        # 上一轮刚换进来的那条，这一轮先别急着再换走（防测量噪声来回抖）
        plan[k] = plan_side(k, alive[k], act[k], keep,
                            protect=(prev.get("swapped") or {}).get(k) or ())

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
    if promoted:
        n = len([p for p in promoted if p["note"].startswith("已收编")])
        m = len([p for p in promoted if p["note"].startswith("已在")])
        if n:
            summary += "，观察名单收编 %d 条" % n
        if m:
            summary += "，观察名单去重移除 %d 条" % m

    # 收编写进了候选池，但本轮没有走 apply_entries（没换上游/手动模式），
    # 测速入口就要在这里单独补渲染，否则新条目要到下次换上游才出现在配置里
    if promoted and not applied and any(p["note"].startswith("已收编") for p in promoted):
        try:
            t = dc.read_cfg()
            nt = dc.render_diag(t)
            if nt and nt != t:
                dc.write_cfg(nt)
                dc.reload_engine()
        except Exception as e:
            _log("收编后重渲染失败：%s" % e)

    # 本轮新换进来的那几条：下一轮给它们一轮豁免，免得延时测量的一点点
    # 抖动就把刚换好的又换回去，每换一次引擎都要重载
    swapped = {}
    for k in ("local", "remote"):
        act_urls_now = {_url(x) for x in act[k]}
        swapped[k] = [x for x in (plan.get(k) or []) if _url(x) not in act_urls_now]

    out = {
        "at": now,
        "took_ms": int((time.time() - t0) * 1000),
        "mode": "manual" if manual else "auto",
        "applied": applied,
        "swapped": swapped,
        "changed_sides": changed_sides,
        "keep": keep,
        "due_min": due,
        "pool": {k: len(pools[k]) for k in pools},
        "pool_total": len(pools["local"]) + len(pools["remote"]),
        "seeded": seeded,
        "alive": {k: [{"line": r["line"], "ms": r["ms"], "ip": r["ip"]} for r in alive[k]] for k in alive},
        "active": act_after,
        "dead": dead,
        "watch": promoted,
        "watch_ok": watch_ok,
        "new": new_after if manual else new,
        # 不截断：界面上要能把整池摊开，让人看清「12 条候选只有 1 条通」
        # 到底是没探还是真探不到——只报前 8 条会被误读成「就试了这么几条」。
        "failed": {k: [{"line": r["line"], "err": r["err"]} for r in results[k] if not r["ok"]]
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
