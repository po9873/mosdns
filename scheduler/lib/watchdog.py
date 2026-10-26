#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""换 IP 看门狗：定时巡检「当前正在生效」的 IP，发现 1034 立刻换掉。

与优选流程的分工：
  scheduler  负责「找新的」——按间隔重跑五路优选
  watchdog   负责「守住旧的」——几分钟一轮，专门盯 1034 / 证书 / 5xx，
             坏一个立刻从 hosts 摘掉，并从候选池补一个通过校验的进来

这就是「1034 一触发就换 IP」：不用等下一轮优选（默认 60 分钟），
默认 3 分钟内就会把坏 IP 换成可用的；找不到替补就撤下该路，绝不继续用坏 IP。

用法： python3 watchdog.py [--once]
"""
import json
import os
import signal
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import https_probe          # noqa: E402
import subs                 # noqa: E402

DATA_DIR = os.environ.get("PREF_DATA_DIR", "/data")
PREF_DIR = os.path.join(DATA_DIR, "prefs")
PID_FILE = os.path.join(DATA_DIR, "mosdns.pid")
LOCK_DIR = os.path.join(DATA_DIR, ".pref.lock")
STATE_FILE = os.path.join(DATA_DIR, "watchdog_state.json")
LOG_FILE = os.path.join(DATA_DIR, "pref.log")
SEED_DIR = "/app/config/seeds"
INTERVAL = int(os.environ.get("PREF_WATCHDOG_SEC", "180"))
TIMEOUT = float(os.environ.get("PREF_WATCHDOG_TIMEOUT", "6"))
MAX_STRIKES = int(os.environ.get("PREF_WATCHDOG_STRIKES", "3"))
PORT = int(os.environ.get("PREF_WATCHDOG_PORT", "443"))
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")


def runtime_cfg():
    """巡检间隔/开关可以在界面上改，不用重启容器：每轮重新读 settings.json。"""
    sec, on = INTERVAL, True
    try:
        with open(SETTINGS_FILE, encoding="utf-8") as f:
            d = json.load(f)
        if isinstance(d.get("watchdog_sec"), (int, float)) and 30 <= int(d["watchdog_sec"]) <= 3600:
            sec = int(d["watchdog_sec"])
        if d.get("watchdog_enabled") is False:
            on = False
    except Exception:
        pass
    return sec, on

HARD = ("cf", "cert")        # 状态名以这些开头 = 明确不可用


def log(msg):
    line = "[%s] [watchdog] %s" % (time.strftime("%m-%d %H:%M:%S"), msg)
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def jload(p, dft):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return dft


def jsave(p, obj):
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)
    os.replace(tmp, p)


def reload_mosdns():
    try:
        pid = int(open(PID_FILE).read().strip())
        os.kill(pid, signal.SIGTERM)
        log("已请求重载 mosdns（pid %d）" % pid)
        return True
    except Exception:
        return False


def read_hosts(path):
    """返回 (domain, [ip...])，格式与 mosdns hosts 一致：域名在前。"""
    try:
        raw = open(path, encoding="utf-8").read().splitlines()
    except Exception:
        return None, []
    for ln in raw:
        p = ln.split()
        if len(p) >= 2:
            return p[0], p[1:]
    return None, []


def write_hosts(route, domain, ips):
    path = os.path.join(PREF_DIR, "%s.hosts" % route)
    if not ips:
        try:
            os.remove(path)
        except Exception:
            pass
    else:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(" ".join([domain] + ips) + "\n")
        os.replace(tmp, path)
    # 合并成 mosdns 实际读取的 all.hosts
    out = []
    try:
        for name in os.listdir(PREF_DIR):
            if not name.endswith(".hosts"):
                continue
            for ln in open(os.path.join(PREF_DIR, name), encoding="utf-8"):
                if ln.strip():
                    out.append(ln.strip())
    except Exception:
        pass
    allp = os.path.join(PREF_DIR, "all.hosts")
    tmp = allp + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(set(out))) + ("\n" if out else ""))
    os.replace(tmp, allp)


def seed_ips(route):
    """该路的种子兜底 IP（镜像内置，无需联网）。"""
    out = []
    path = os.path.join(SEED_DIR, "%s.txt" % route)
    try:
        for ln in open(path, encoding="utf-8"):
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            tok = ln.split()[0]
            if tok.count(".") == 3 or ":" in tok:
                out.append(tok)
    except Exception:
        pass
    return out


def candidates(route, domain, skip):
    """补位候选：订阅池 + 种子，去掉已在用的和已拉黑的。"""
    bad = subs._bad_set()
    out = []
    for ip in subs.cmd_pool(route, 12, smart=True):
        if ip not in skip and ip not in bad:
            out.append(ip)
    for ip in seed_ips(route):
        if ip not in skip and ip not in bad and ip not in out:
            out.append(ip)
    return out


def probe(ip, domain):
    try:
        return https_probe.check(ip, domain, PORT, TIMEOUT)
    except Exception:
        return ip, "fail", None


def run_once():
    if os.path.isdir(LOCK_DIR):
        log("优选正在运行，本轮跳过（避免抢写 hosts）")
        return 0

    state = jload(STATE_FILE, {})
    changed = False
    checked = 0
    swapped = 0

    for name in sorted(os.listdir(PREF_DIR)):
        if not name.endswith(".hosts"):
            continue
        route = name[:-6]
        domain, ips = read_hosts(os.path.join(PREF_DIR, name))
        if not domain or not ips:
            continue

        keep, dropped = [], []
        for ip in ips:
            _ip, st, ms = probe(ip, domain)      # check() 返回 (ip, 状态, 耗时)
            checked += 1
            if st == "ok":
                state.pop("%s|%s" % (route, ip), None)
                keep.append(ip)          # 健康 IP 必须留在 hosts 里
                continue
            if st.startswith(HARD):
                dropped.append((ip, st))
                continue
            # 超时/连不上：不是确定坏，连续 3 次才换，避免网络抖动误杀
            key = "%s|%s" % (route, ip)
            n = int((state.get(key) or {}).get("fails", 0)) + 1
            state[key] = {"fails": n, "ts": int(time.time()), "reason": st}
            if n >= MAX_STRIKES:
                dropped.append((ip, st + "x%d" % n))
            else:
                keep.append(ip)

        if not dropped:
            continue

        for ip, why in dropped:
            subs.mark_bad(ip, why, route)
            state.pop("%s|%s" % (route, ip), None)
            log("%s: %s 不可用（%s），已拉黑" % (route, ip, why))

        # 剩下的继续留着；缺的从池子里补
        need = max(0, len(ips) - len(keep))
        added = []
        if need:
            for cand in candidates(route, domain, set(ips) | {d[0] for d in dropped}):
                if len(added) >= need:
                    break
                _ip2, st2, _ms2 = probe(cand, domain)
                checked += 1
                if st2 == "ok":
                    added.append(cand)
                    subs.cmd_bump(route, cand, "ok")
                elif st2.startswith(HARD):
                    subs.mark_bad(cand, st2, route)

        final = keep + added
        write_hosts(route, domain, final)
        changed = True
        swapped += len(dropped)

        for ip, why in dropped:
            subs.add_event("swap", route, ip, why, " ".join(added) or "(撤下，回退上游)")
        if added:
            log("%s: 换 IP 完成 %s -> %s" % (route,
                                            ",".join(d[0] for d in dropped),
                                            ",".join(added)))
        elif final:
            log("%s: 撤下 %s，保留 %d 个仍可用" % (route,
                                                 ",".join(d[0] for d in dropped),
                                                 len(final)))
        else:
            log("%s: %s 全部不可用且无替补，已撤下该路（域名回退上游）"
                % (route, ",".join(d[0] for d in dropped)))

    try:
        jsave(STATE_FILE, state)
    except Exception:
        pass

    if changed:
        reload_mosdns()
    log("巡检完成：检查 %d 个 IP，换掉 %d 个" % (checked, swapped))
    return swapped


def main():
    once = "--once" in sys.argv
    sec, on = runtime_cfg()
    log("启动，间隔 %d 秒，超时 %.0fs，连不上 %d 次才换%s"
        % (sec, TIMEOUT, MAX_STRIKES, "" if on else "（当前已关闭巡检）"))
    if once:
        run_once()
        return 0
    while True:
        sec, on = runtime_cfg()
        if on:
            try:
                run_once()
            except Exception as e:
                log("异常：%s" % e)
        time.sleep(max(30, sec))


if __name__ == "__main__":
    sys.exit(main())
