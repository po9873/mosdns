#!/usr/bin/env python3
"""同 CDN 横向扩段：当地这段被限速时，去找同一家 CDN 的其它网段。

为什么需要它：优选选出来的 IP 常常是「全段被运营商限速」——不是 IP 坏了，
而是这一段（比如 Fastly 的 185.199.108~111）在国内就是 6~20KB/s。这种时候
在原来那一段里再怎么重探、再怎么换 IP 都没用，必须换到同一家 CDN 的其它
网段去（实测 Fastly 的 151.101.x.217 组对同样的 SNI 能跑到 5MB/s）。

CDN 普遍按 SNI 路由，所以同一家 CDN 的其它边缘 IP 也能服务同一域名、证书
也是同一张，换过去对客户端完全透明——这正是「纯 DNS 就能修好」的前提。

用法（IP 列表从 stdin 或参数给，用来判 CDN 归属和取主机位）:
    echo "$ips" | python3 cdn_expand.py --domain D --port 443 --timeout 6 \
        --conc 4 --path / --expect "" --speed-url "" --min-kbps 200 \
        --keep 3 --ranges /app/config/cdn_ranges.txt

输出: 每行 "ip 延时ms ok 速度KB/s"，按「快的在前」排序（有吞吐就比吞吐，
没有就比延时）。调用方拿去喂候选池或直接写 hosts。
"""
import argparse
import ipaddress
import os
import subprocess
import sys

SELF_DIR = os.path.dirname(os.path.abspath(__file__))
PROBE = os.path.join(SELF_DIR, "https_probe.py")

# 每家 CDN 的 anycast 地址布局不一样，但这些第三段是各家里反复出现的
# 「组号」，抽样的命中率最高。随便撒点意义不大——有些地址根本不属于任何
# 组，连过去就是 307/空响应，白等一个超时。
CANON_THIRDS = (0, 2, 64, 66, 128, 130, 192, 194)
# 主机位比网段号更关键：Fastly 的 151.101.0.0/16 里 GitHub 的服务就在 .217 上，
# 换成 .1/.154 连过去根本没人认（TLS 直接失败）。所以 .217 排最前先试。
CANON_HOSTS = (217, 1, 65, 129, 193, 254)


def load_ranges(path):
    fam = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                p = line.split()
                if len(p) >= 2:
                    fam.setdefault(p[0], []).extend(p[1:])
    except Exception:
        pass
    return fam


def family_of(ip, fams):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for name, cidrs in fams.items():
        for c in cidrs:
            try:
                if a in ipaddress.ip_network(c, strict=False):
                    return name
            except ValueError:
                continue
    return None


def gen_candidates(cur_ips, cidrs, cap):
    """按「同主机位 + 兄弟网段」生成候选：这是 anycast CDN 的真实布局。

    例：185.199.109.154（慢段）在 Fastly 里对应的兄弟组是 151.101.{0,64,
    128,192}.154，而 151.101.2.217 这种快段则要靠 CANON_HOSTS 抽样撞到。
    两类都生成，谁先被探测到、谁快就用谁。
    """
    hosts = []
    for ip in cur_ips:
        if "." in ip:
            h = int(ip.split(".")[-1])
            if h not in hosts:
                hosts.append(h)
    for h in CANON_HOSTS:
        if h not in hosts:
            hosts.append(h)

    out, seen = [], set(cur_ips)
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        if net.version != 4:
            continue
        a, b = str(net.network_address).split(".")[:2]
        if net.prefixlen <= 16:
            thirds = list(CANON_THIRDS)
            # 带上「当前 IP 所在的第三段」及其邻居：Cloudflare 这类 /13 里真正
            # 服务的段常常不在上面那几个经典段号里（实测落在 172.67.220），
            # 光靠经典段号一个也撞不上。
            for ip in cur_ips:
                if ip.count(".") != 3 or not ip.startswith(a + "." + b + "."):
                    continue
                try:
                    t0 = int(ip.split(".")[2])
                except ValueError:
                    continue
                for t in (t0, t0 - 1, t0 + 1, t0 - 2, t0 + 2):
                    if 0 <= t <= 255 and t not in thirds:
                        thirds.append(t)
        elif net.prefixlen <= 24:
            # /17~/24：只在本段里扫，第三段就是它自己的那几个
            thirds = [int(x) for x in str(net.network_address).split(".")[2:3]]
            extra = int(str(net.broadcast_address).split(".")[2])
            while extra != thirds[0] and len(thirds) < 8:
                thirds.append(extra)
                extra -= 1
        else:
            continue
        picked = 0
        # 主机位在外、网段号在内：先把「某个主机位 × 各个网段」铺满一排再换下一个
        # 主机位。反过来的话每个网段只试一个主机位，很容易整排错过真正服务的那个
        # （151.101.x.217 就是这么被漏掉的）。
        for h in hosts:
            for t in thirds:
                ip = "%s.%s.%d.%d" % (a, b, t, h)
                if ip in seen:
                    continue
                seen.add(ip)
                out.append(ip)
                picked += 1
                if len(out) >= cap:
                    break
            if picked >= 8 or len(out) >= cap:
                break
        if len(out) >= cap:
            break
    return out[:cap]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--domain", required=True)
    ap.add_argument("--port", default="443")
    ap.add_argument("--timeout", default="6")
    ap.add_argument("--conc", default="4")
    ap.add_argument("--path", default="/")
    ap.add_argument("--expect", default="")
    ap.add_argument("--speed-url", default="")
    ap.add_argument("--min-kbps", type=int, default=200)
    ap.add_argument("--keep", type=int, default=3)
    ap.add_argument("--cap", type=int, default=48)
    ap.add_argument("--ranges", default="/app/config/cdn_ranges.txt")
    ap.add_argument("ips", nargs="*")
    a = ap.parse_args()

    cur = list(a.ips)
    if not sys.stdin.isatty():
        try:
            cur += [x.strip() for x in sys.stdin.read().split() if x.strip()]
        except Exception:
            pass
    cur = [x for x in dict.fromkeys(cur) if x]
    if not cur:
        return 0

    fams = load_ranges(a.ranges)
    fam = family_of(cur[0], fams)
    if not fam:
        # 认不出是哪家的段就没法横向扩——宁可不猜，别瞎扫一堆无关地址
        sys.stderr.write("cdn_expand: %s 不在已知 CDN 段表里，跳过\n" % cur[0])
        return 0
    cands = gen_candidates(cur, fams[fam], a.cap)
    if not cands:
        return 0
    sys.stderr.write("cdn_expand: %s 段被限速，横向试 %s 的 %d 个地址\n"
                     % (fam, fam, len(cands)))

    cmd = [sys.executable, PROBE, a.domain, a.port, a.timeout, a.conc, "1",
           a.path, a.expect, a.speed_url]
    try:
        p = subprocess.run(cmd, input="\n".join(cands) + "\n",
                           capture_output=True, text=True, timeout=180)
    except Exception:
        return 0

    rows = []
    for line in p.stdout.splitlines():
        f = line.split()
        if len(f) < 3 or f[1] != "ok":
            continue
        try:
            lat = float(f[2])
        except ValueError:
            lat = 9e9
        sp = None
        if len(f) > 3 and f[3] not in ("-", ""):
            try:
                sp = float(f[3].lstrip("~"))
            except ValueError:
                sp = None
        rows.append((f[0], lat, sp))
    if not rows:
        return 0

    # 有吞吐就按吞吐排（这才是"限速"的直接证据），没有就退回按延时排。
    # 门槛：至少要比 min_kbps 快，否则换过去也没意义。
    good = [r for r in rows if r[2] is not None and r[2] >= a.min_kbps]
    use = good if good else rows
    use.sort(key=lambda r: (-(r[2] or 0), r[1]))
    for ip, lat, sp in use[:a.keep]:
        print("%s %.0f ok %s" % (ip, lat, ("%.0f" % sp) if sp is not None else "-"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
