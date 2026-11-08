#!/usr/bin/env python3
"""把 XIU2/CloudflareSpeedTest 真正接进 mosdns 的每一路优选。

这个模块只在 mosdns 容器（101）里跑：收集该路已有候选 IP → 调镜像内
/app/bin/cft/cfst 按「该路自己的域名」实测排序 → 结果灌进该路候选池 +
写成该路的补位种子。cfst 官方就支持任意 CDN / 网站 IP（-f 任意 IP 段、
-url 自定义测速地址、-httping 用真实 HTTP 请求判可用），不是只能测 CF。

边界（刻意如此，别改）：
  * 只负责「找候选 + 排序」，**不写 hosts**。最终生效仍由 101 的
    https_probe 严格证书 + 真实请求复核，watchdog 在补位时才会用到。
  * 粘滞守卫保证在用 IP 全健康时沿用不换，cfst 选出再快的 IP 也不会洗牌。
  * 低占用：cf 路每轮一次（与旧行为一致）；其余路 6 小时才重测一次，
    期间复用上次排序结果，坏了才由 101 触发补位。不常驻、不起新容器。
  * HTTPing 判据比 101 复核松（只认指定状态码、不校验证书）。所以
    HTTPing 全军覆没时自动回退纯 TCPing 排序，绝不让工具把该路选空；
    两条路都没结果就不写种子，原逻辑照常工作。
"""
import csv
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import subs  # noqa: E402

DATA = os.environ.get("DATA_DIR", "/data")
CFST = "/app/bin/cft/cfst"

# 每路自己的测速地址（HTTPing 时的 -url / SNI / Host）、种子主域名与原始种子。
# ttl=0 表示每轮都测（cf 路保留旧行为、面板时间会一直刷新）；其它路 6 小时。
ROUTES = {
    "cf": {
        "dom": "cloudflare.com", "seed": "/app/config/seeds/cloudflare.txt",
        "url": None, "code": None, "fallback": ["1.1.1.1", "1.0.0.1"],
        "conc": 12, "times": 2, "max_input": 150, "top": 24,
        "timeout": 120, "ttl": 0,
    },
    "github": {
        "dom": "github.com", "seed": "/app/config/seeds/github.txt",
        "url": "https://github.com/", "code": None, "fallback": [],
        "conc": 6, "times": 2, "max_input": 60, "top": 12,
        "timeout": 45, "ttl": 21600,
    },
    "ghcr": {
        "dom": "ghcr.io", "seed": "/app/config/seeds/ghcr.txt",
        # 真 registry 对 /v2/ 回 401（缺 Bearer token），拿它当身份证明
        "url": "https://ghcr.io/v2/", "code": 401, "fallback": [],
        "conc": 6, "times": 2, "max_input": 60, "top": 12,
        "timeout": 45, "ttl": 21600,
    },
    "gt": {
        "dom": "translate.googleapis.com", "seed": "/app/config/seeds/ghtranslate.txt",
        # Chrome 整页翻译 loader，社区节点必须能真返回这个 JS
        "url": "https://translate.googleapis.com/translate_a/element.js",
        "code": 200, "fallback": [],
        "conc": 6, "times": 2, "max_input": 60, "top": 12,
        "timeout": 45, "ttl": 21600,
    },
    "google": {
        "dom": "www.google.com", "seed": "/app/config/seeds/google.txt",
        "url": "https://www.google.com/", "code": None, "fallback": [],
        "conc": 6, "times": 2, "max_input": 60, "top": 12,
        "timeout": 45, "ttl": 21600,
    },
    "tmdb": {
        "dom": "www.themoviedb.org", "seed": "/app/config/seeds/tmdb.txt",
        "url": "https://www.themoviedb.org/", "code": None, "fallback": [],
        "conc": 6, "times": 2, "max_input": 60, "top": 12,
        "timeout": 45, "ttl": 21600,
    },
    "imdb": {
        "dom": "www.imdb.com", "seed": "/app/config/seeds/imdb.txt",
        "url": "https://www.imdb.com/", "code": None, "fallback": [],
        "conc": 6, "times": 2, "max_input": 60, "top": 12,
        "timeout": 45, "ttl": 21600,
    },
}


def status_path(route):
    # cf 路沿用旧文件名，面板与既有验收脚本不用改
    return os.path.join(DATA, "cfst_status.json" if route == "cf"
                        else "cfst_%s_status.json" % route)


def seed_path(route):
    return os.path.join(DATA, "cfst_seed.txt" if route == "cf"
                        else "cfst_%s_seed.txt" % route)


def collect_ips(route, cfg):
    """候选只来自本路已有的池子 / 在用 hosts / 种子里的兜底 IP。

    刻意不做任意公网 IP 段扫描：这些 IP 都是 101 之前实测过的，
    工具只负责给它们排序，不引入未验证的新地址。
    非 cf 路用 subs 的智能取样（社区实测源优先），别从几千条官方网段
    里按字典顺序抓前 60 个——那批地址从没验过，扫半天也没有结果。
    """
    limit = int(os.environ.get("CFST_MAX_INPUT", cfg["max_input"]))
    ips = []
    if route == "cf":
        # cf 路保持已验证的旧行为：按池子原顺序取前 150 个
        try:
            with open(os.path.join(DATA, "pool", "cf.json"), encoding="utf-8") as f:
                ips += [ip for ip in json.load(f).get("ips", {}) if "." in ip]
        except Exception:
            pass
    else:
        try:
            ips += subs.cmd_pool(route, limit, smart=True)
        except Exception:
            pass
    try:
        with open(os.path.join(DATA, "prefs", "%s.hosts" % route), encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                for tok in line.split()[1:]:
                    if "." in tok and tok[:1].isdigit():
                        ips.append(tok)
    except Exception:
        pass
    try:
        with open(cfg["seed"], encoding="utf-8") as f:
            for line in f:
                tok = line.split("#", 1)[0].strip()
                parts = tok.split(".")
                if len(parts) == 4 and all(p.isdigit() for p in parts):
                    ips.append(tok)
    except Exception:
        pass
    ips += cfg["fallback"]
    # 101 判定的坏 IP 不参与排序：否则历史黑名单里的地址会占掉 seed 前几名，
    # 补位 watchdog 还得再过滤一次，白浪费候选名额。
    try:
        bad = subs._bad_set()
    except Exception:
        bad = set()
    out, seen = [], set()
    for ip in ips:
        if ip in bad or ip in seen or "." not in ip:
            continue
        seen.add(ip)
        out.append(ip)
    return out[:limit]


def measure(route, cfg, ips, httping):
    """跑一次 cfst，返回 (排序 IP, 耗时, 模式)。失败返回空列表。"""
    tmp_ip = "/tmp/cfst_%s_input.txt" % route
    tmp_csv = "/tmp/cfst_%s_result.csv" % route
    with open(tmp_ip, "w", encoding="utf-8") as f:
        f.write("\n".join(ips) + "\n")
    try:
        os.unlink(tmp_csv)
    except OSError:
        pass

    cmd = [CFST, "-f", tmp_ip,
           "-n", str(int(os.environ.get("CFST_CONC", cfg["conc"]))),
           "-t", str(cfg["times"]), "-dd", "-p", "0",
           "-o", tmp_csv, "-tl", "9999", "-tlr", "1"]
    mode = "tcping"
    if httping and cfg["url"]:
        cmd += ["-httping", "-url", cfg["url"]]
        if cfg["code"]:
            cmd += ["-httping-code", str(cfg["code"])]
        mode = "httping"
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL,
                              timeout=int(os.environ.get("CFST_TIMEOUT", cfg["timeout"])))
        rc = proc.returncode
    except Exception:
        return [], round(time.time() - t0, 1), mode
    cost = round(time.time() - t0, 1)

    ranked = []
    try:
        with open(tmp_csv, encoding="utf-8-sig") as f:
            for row in csv.reader(f):
                if not row or "." not in row[0]:
                    continue
                ip = row[0].strip()
                if ip and not ip.startswith("IP"):
                    ranked.append(ip)
    except Exception:
        return [], cost, mode
    try:
        os.unlink(tmp_ip)
        os.unlink(tmp_csv)
    except OSError:
        pass
    return ranked, cost, mode


def has_bad_ip(route):
    """守护快照里这一路有明确打不开的 IP → 立刻重测，不等 TTL。"""
    try:
        with open(os.path.join(DATA, "health_snapshot.json"), encoding="utf-8") as f:
            snap = json.load(f)
        if time.time() - int(snap.get("ts", 0)) > 300:
            return False
        for key, val in (snap.get("results") or {}).items():
            if key.startswith(route + "|") and isinstance(val, list) and val and val[0] is False:
                return True
    except Exception:
        pass
    return False


def should_skip(route, cfg):
    ttl = int(os.environ.get("CFST_TTL", cfg["ttl"]))
    if os.environ.get("CFST_FORCE") == "1" or ttl <= 0:
        return False
    try:
        with open(status_path(route), encoding="utf-8") as f:
            st = json.load(f)
        if st.get("ok") and time.time() - int(st.get("ts", 0)) < ttl:
            return not has_bad_ip(route)
    except Exception:
        pass
    return False


def run(route):
    cfg = ROUTES.get(route)
    if not cfg:
        return {"ok": False, "route": route, "why": "未知优选路"}
    if not os.path.isfile(CFST) or not os.access(CFST, os.X_OK):
        return {"ok": False, "route": route, "why": "cfst 二进制不在镜像里"}
    if should_skip(route, cfg):
        return {"ok": True, "route": route, "skipped": True,
                "why": "在用 IP 全健康，沿用上次排序（TTL 内不重复测速）"}

    ips = collect_ips(route, cfg)
    if len(ips) < 3:
        return {"ok": False, "route": route, "why": "候选不足 %d 个" % len(ips)}

    ranked, cost, mode = measure(route, cfg, ips, True)
    if not ranked and cfg["url"]:
        # HTTPing 判据太严（403/401/超时）时回退纯 TCP 延迟排序，
        # 结果一样要过 101 严格复核，不会把坏 IP 放进 hosts。
        ranked, cost2, mode = measure(route, cfg, ips, False)
        cost = round(cost + cost2, 1)
    ranked = ranked[:int(os.environ.get("CFST_TOP", cfg["top"]))]
    # 工具对某些路的 HTTPing 判据太严（imdb 202 空响应、TMDB 403 挑战页），
    # 排序结果可能只剩 2 个，坏一个就没得补。不足 6 个时从本路候选池再取
    # 一批，用 101 同一套严格判据实测，通过的追加到后面；工具排出来的仍
    # 排在最前，兜底只补弹药，不改变「由工具选 IP」。
    if len(ranked) < 6:
        try:
            import watchdog as wd
            try:
                bad = subs._bad_set()
            except Exception:
                bad = set()
            for ip in subs.cmd_pool(route, 40, smart=True):
                if len(ranked) >= 12:
                    break
                if ip in ranked or ip in bad or "." not in ip:
                    continue
                try:
                    if wd.health(ip, cfg["dom"], route)[0]:
                        ranked.append(ip)
                except Exception:
                    pass
        except Exception:
            pass
    if not ranked:
        return {"ok": False, "route": route, "why": "cfst 本轮没测出可用 IP",
                "cost": cost, "input": len(ips)}

    # ① 排序结果进该路候选池（都是已有 IP，只是提升新鲜度）
    try:
        fed = subs.cmd_feed(route, [(ip, "cfst") for ip in ranked])
    except Exception as e:
        fed = {"error": str(e)}

    # ② 补位/强制重选用的种子：首行目标域名 + cfst 排序 IP
    try:
        with open(seed_path(route), "w", encoding="utf-8") as f:
            f.write("%s\n" % cfg["dom"])
            f.write("# CloudflareSpeedTest 101 实测排序，仅供 %s 路重选/补位\n" % route)
            f.write("\n".join(ranked) + "\n")
    except Exception:
        pass

    st = {"ok": True, "route": route, "ts": int(time.time()), "cost": cost,
          "mode": mode, "input": len(ips), "ranked": len(ranked),
          "top": ranked[:6], "fed": fed}
    try:
        with open(status_path(route), "w", encoding="utf-8") as f:
            json.dump(st, f, ensure_ascii=False)
    except Exception:
        pass
    return st


if __name__ == "__main__":
    print(json.dumps(run(sys.argv[1] if len(sys.argv) > 1 else "cf"),
                     ensure_ascii=False))
