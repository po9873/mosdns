#!/usr/bin/env python3
"""把每路当前生效的 IP 整理成一段纯文本，供推送和控制台预览用。

只推「几路成功」这种摘要等于什么都没说——收到消息的人根本不知道
现在到底在用哪些 IP。这里逐路列出域名和 IP（带响应时间和吞吐）。

用法: python3 route_brief.py [prefs_dir]
"""
import os
import sys

ROUTES = ["cf", "google", "gt", "github", "ghcr", "tmdb", "imdb"]
LABEL = {
    "cf": "Cloudflare", "google": "Google 搜索", "gt": "Google 翻译",
    "github": "GitHub", "ghcr": "ghcr", "tmdb": "TMDB", "imdb": "IMDb",
}


def fmt_speed(v, est):
    if v is None:
        return ""
    s = "~" if est else ""
    if v >= 1024:
        return "%s%.1fMB/s" % (s, v / 1024.0)
    return "%s%dKB/s" % (s, round(v))


def main():
    d = sys.argv[1] if len(sys.argv) > 1 else "/data/prefs"
    out = []
    for r in ROUTES:
        hp = os.path.join(d, "%s.hosts" % r)
        mp = os.path.join(d, "%s.meta" % r)
        meta = {}
        try:
            with open(mp, encoding="utf-8") as f:
                for ln in f:
                    p = ln.split()
                    if len(p) >= 2:
                        st = p[2] if len(p) > 2 else "ok"
                        sp = None
                        est = False
                        if len(p) > 3 and p[3] not in ("-", ""):
                            est = p[3].startswith("~")
                            try:
                                sp = float(p[3].lstrip("~"))
                            except ValueError:
                                sp = None
                        try:
                            meta[p[0]] = (float(p[1]), st, sp, est)
                        except ValueError:
                            pass
        except Exception:
            pass
        try:
            lines = [x.split() for x in open(hp, encoding="utf-8") if x.strip()]
        except Exception:
            lines = []
        if not lines:
            out.append("%s：暂无结果" % LABEL.get(r, r))
            continue
        domains = [x[0] for x in lines]
        ips = [x for x in lines[0][1:] if x]
        head = "%s · %s" % (LABEL.get(r, r), domains[0])
        if len(domains) > 1:
            head += "（同批还映射 %s）" % "、".join(domains[1:])
        out.append(head)
        for i, ip in enumerate(ips[:4], 1):
            lt, st, sp, est = meta.get(ip, (None, "ok", None, False))
            bits = []
            if lt is not None:
                bits.append("%dms" % round(lt))
            sps = fmt_speed(sp, est)
            if sps:
                bits.append(sps)
            if st and st not in ("ok", ""):
                bits.append(st)
            out.append("  %d. %s%s" % (i, ip, (" · " + " · ".join(bits)) if bits else ""))
        if len(ips) > 4:
            out.append("  …还有 %d 个" % (len(ips) - 4))
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
