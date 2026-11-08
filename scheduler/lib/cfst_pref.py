#!/usr/bin/env python3
"""把 XIU2/CloudflareSpeedTest 真正接进 cf 路。

这个模块只在 mosdns 容器（101）里跑：收集 cf 路已有候选 IP → 调镜像内
/app/bin/cft/cfst 做 TCP 延迟实测排序 → 把结果灌进 cf 候选池。

边界（刻意如此，别改）：
  * 只负责「找候选 + 排序」，**不写 hosts**。最终生效仍由 101 的
    https_probe 严格证书 + 真实请求复核，watchdog 在补位时才会用到。
  * 粘滞守卫保证在用 IP 全健康时沿用不换，cfst 选出再快的 IP 也不会洗牌。
  * 低占用：每次定时优选跑一次，并发/次数/输入量都有上限，不常驻。
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
POOL = os.path.join(DATA, "pool", "cf.json")
HOSTS = os.path.join(DATA, "prefs", "cf.hosts")
STATUS = os.path.join(DATA, "cfst_status.json")
SEED_OUT = os.path.join(DATA, "cfst_seed.txt")
TMP_IP = "/tmp/cfst_input.txt"
TMP_CSV = "/tmp/cfst_result.csv"

CONC = int(os.environ.get("CFST_CONC", "12"))
TIMES = int(os.environ.get("CFST_TIMES", "2"))
MAX_INPUT = int(os.environ.get("CFST_MAX_INPUT", "150"))
TOP = int(os.environ.get("CFST_TOP", "24"))
TIMEOUT = int(os.environ.get("CFST_TIMEOUT", "120"))


def collect_ips():
    """候选来源：订阅池 + 在用 IP + 两个公开兜底，去重后限量。"""
    ips = []
    try:
        with open(POOL, encoding="utf-8") as f:
            pool = json.load(f).get("ips", {})
        ips += [ip for ip in pool if "." in ip]
    except Exception:
        pass
    try:
        with open(HOSTS, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                for tok in line.split()[1:]:
                    if "." in tok and tok[:1].isdigit():
                        ips.append(tok)
    except Exception:
        pass
    ips += ["1.1.1.1", "1.0.0.1"]
    out, seen = [], set()
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out[:MAX_INPUT]


def run():
    if not os.path.isfile(CFST) or not os.access(CFST, os.X_OK):
        return {"ok": False, "why": "cfst 二进制不在镜像里"}
    candidate = collect_ips()
    if len(candidate) < 3:
        return {"ok": False, "why": "cf 候选不足 %d 个" % len(candidate)}
    with open(TMP_IP, "w", encoding="utf-8") as f:
        f.write("\n".join(candidate) + "\n")
    try:
        os.unlink(TMP_CSV)
    except OSError:
        pass

    cmd = [CFST, "-f", TMP_IP, "-n", str(CONC), "-t", str(TIMES),
           "-dd", "-p", "0", "-o", TMP_CSV, "-tl", "9999", "-tlr", "1"]
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=TIMEOUT)
        rc = proc.returncode
    except Exception as e:
        return {"ok": False, "why": "cfst 执行异常: %s" % e,
                "cost": round(time.time() - t0, 1)}
    cost = round(time.time() - t0, 1)

    ranked = []
    try:
        with open(TMP_CSV, encoding="utf-8-sig") as f:
            for row in csv.reader(f):
                if not row or "." not in row[0]:
                    continue
                ip = row[0].strip()
                if ip and not ip.startswith("IP"):
                    ranked.append(ip)
    except Exception as e:
        return {"ok": False, "why": "cfst 结果解析失败: %s" % e,
                "cost": cost, "rc": rc}
    ranked = ranked[:TOP]
    if not ranked:
        return {"ok": False, "why": "cfst 本轮没测出可用 IP",
                "cost": cost, "rc": rc, "input": len(candidate)}

    # ① 排序结果进 cf 候选池：watchdog 补位时优先取样，101 复核通过才写 hosts
    fed = {}
    try:
        fed = subs.cmd_feed("cf", [(ip, "cfst") for ip in ranked])
    except Exception as e:
        fed = {"error": str(e)}

    # ② 手工强制重选（PREF_RESELECT=1）时用的种子：首行目标域名 + cfst 排序 IP
    try:
        with open(SEED_OUT, "w", encoding="utf-8") as f:
            f.write("cloudflare.com\n")
            f.write("# CloudflareSpeedTest 101 实测排序，仅供 cf 路重选\n")
            f.write("\n".join(ranked) + "\n")
    except Exception:
        pass

    st = {"ok": True, "ts": int(time.time()), "cost": cost, "rc": rc,
          "input": len(candidate), "ranked": len(ranked), "top": ranked[:6],
          "fed": fed}
    try:
        with open(STATUS, "w", encoding="utf-8") as f:
            json.dump(st, f, ensure_ascii=False)
    except Exception:
        pass
    return st


if __name__ == "__main__":
    print(json.dumps(run(), ensure_ascii=False))
