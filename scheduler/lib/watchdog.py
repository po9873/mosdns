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

HARD = ("cf", "cert", "wrong")   # 状态名以这些开头 = 明确不可用

# Google 系域名专用判定：这些节点的根路径回什么都有可能（翻译首页 200、其他路径 404），
# 光看「HTTP 通不通」分不出好坏；而翻译接口有配额，巡检频繁调用会被 429，
# 反而把好 IP 判成坏的换掉。所以统一看首页标题（<title>Google…）。
_TRANS_DOMS = ("translate.googleapis.com", "translate.google.com")
_GOOGLE_DOMS = ("www.google.com", "www.google.com.hk")


def spec_for(domain):
    """这一路该请求什么路径、正文里该出现什么（默认根路径，不校验内容）。

    翻译首页是纯 JS 壳，整页没有 <title>；搜索首页有 <title>Google。
    用这两种特征判断，既不用调翻译接口（有配额，巡检频繁会被 429 限速），
    也能把「能连但不提供该服务」的节点筛掉。
    """
    if domain in _TRANS_DOMS:
        return "/", "translate"
    if domain in _GOOGLE_DOMS:
        return "/", "<title>Google"
    return "/", None


def log(msg):
    # 前缀用中文，避免日志里一堆 [watchdog] 让人看不懂在干什么
    line = "[%s] 【守护】%s" % (time.strftime("%m-%d %H:%M:%S"), msg)
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def why_label(why):
    """把内部状态码翻成人话，日志里不出现 cf1034 这种裸代码。"""
    w = str(why or "")
    if w == "timeout":
        return "超时"
    if w == "fail":
        return "连不上"
    if w == "cert":
        return "证书不对"
    if w.startswith("cf10"):
        return "Cloudflare %s 错误" % w[2:]
    if w.startswith("http5"):
        return "源站 %s 错误" % w[4:]
    if w == "unverified":
        return "没通过 HTTPS 校验"
    return w or "打不开"


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
    """巡检只关心「能不能打开」，但 https_probe.check 现在返回 4 个字段
    （ip / 状态 / TTFB / 吞吐）。这里统一补成 4 元组，避免以后它再加字段
    又把守护线程整个搞崩（之前就崩过：too many values to unpack）。"""
    path, expect = spec_for(domain)
    try:
        r = https_probe.check(ip, domain, PORT, TIMEOUT, 1, path, expect)
    except Exception:
        return ip, "fail", None, None
    r = tuple(r)
    if len(r) < 4:
        r = r + (None,) * (4 - len(r))
    return r[0], r[1], r[2], r[3]


def run_once():
    if os.path.isdir(LOCK_DIR):
        log("优选任务正在跑，这轮巡检先跳过（避免两边同时改写 hosts 打架）")
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
            _ip, st, ms, _sp = probe(ip, domain)  # check() 返回 (ip, 状态, TTFB, 吞吐)
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
            log("%s 路：%s 打不开（%s），已加入黑名单，%d 小时内不再用"
                % (route, ip, why_label(why), subs.BAD_TTL_H))

        # 剩下的继续留着；缺的从池子里补
        need = max(0, len(ips) - len(keep))
        added = []
        if need:
            for cand in candidates(route, domain, set(ips) | {d[0] for d in dropped}):
                if len(added) >= need:
                    break
                _ip2, st2, _ms2, _sp2 = probe(cand, domain)
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
            log("%s 路：%s 打不开，换成 %s（新 IP 已实测通过）"
                % (route, ",".join(d[0] for d in dropped), ",".join(added)))
        elif final:
            log("%s 路：撤下打不开的 %s，保留 %d 个仍可用"
                % (route, ",".join(d[0] for d in dropped), len(final)))
        else:
            log("%s 路：%s 全打不开、也没有可换的，已撤下这一路（该域名改走上游解析）"
                % (route, ",".join(d[0] for d in dropped)))

    try:
        jsave(STATE_FILE, state)
    except Exception:
        pass

    if changed:
        reload_mosdns()
    log("这轮巡检结束：检查 %d 个 IP，换掉 %d 个（其余都能正常打开）" % (checked, swapped))
    return swapped


def main():
    once = "--once" in sys.argv
    sec, on = runtime_cfg()
    log("启动：每 %d 秒把每路在用的 IP 各打开一次（单个超时 %.0fs），"
        "打不开（1034/证书/5xx/连不上）就换 IP；同一 IP 连续 %d 次不行才换%s"
        % (sec, TIMEOUT, MAX_STRIKES, "（当前巡检已关闭）" if not on else ""))
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
