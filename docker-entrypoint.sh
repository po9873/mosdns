#!/bin/bash
# ============================================================
# 容器入口：渲染配置 / 种入账号 / 自动线程 / 拉起三进程
# 三进程：mosdns（supervisor 守护）、scheduler（后台）、UI（前台）
# 全部由环境变量驱动，零硬编码；运行数据只写 /data。
# ============================================================
set -u

source /app/scheduler/common.sh

DATA_DIR="${PREF_DATA_DIR:-/data}"
DNS_PORT="${PREF_DNS_PORT:-53}"
API_PORT="${PREF_API_PORT:-9099}"
UI_PORT="${PREF_UI_PORT:-80}"
# 上游 DoH 不再写死：启动时本地探测 /data/doh_*_candidates.txt 候选清单，
# 自动选用当地能通的（见下方「渲染配置」段）。如需整体替换，直接改这两个文本文件即可。
THREADS="${PREF_THREADS:-}"
CACHE_SIZE="${PREF_CACHE_SIZE:-8192}"

elog() { echo "[entrypoint] $*"; }

mkdir -p "$DATA_DIR/prefs"

# ---------- 初始化运行数据（只在不存在时创建，绝不覆盖用户数据）----------
[ -f "$DATA_DIR/prefs/all.hosts" ] || : > "$DATA_DIR/prefs/all.hosts"

# hosts 自检：每一行必须是「域名 + 全是 IP」。只要有一行不是，mosdns 会以
# "invalid ip addr" 直接 FATAL，起来就死、DNS 全断。历史上有过一句日志被
# 重定向写进 hosts 的先例，所以每次启动都过一遍，坏行丢掉、all.hosts 重算。
python3 - "$DATA_DIR/prefs" <<'PY' || true
import ipaddress, os, re, sys

d = sys.argv[1]
DOM = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]*[a-z0-9])?\.)+[a-z]{2,}$", re.I)

def ok(line):
    p = line.split()
    if len(p) < 2 or not DOM.match(p[0]):
        return None
    ips = []
    for x in p[1:]:
        try:
            ips.append(str(ipaddress.ip_address(x)))
        except ValueError:
            return None
    return p[0], ips

dropped = 0
try:
    names = sorted(n for n in os.listdir(d) if n.endswith(".hosts") and n != "all.hosts")
except OSError:
    names = []
for n in names:
    p = os.path.join(d, n)
    out = []
    try:
        lines = open(p, encoding="utf-8", errors="replace").read().splitlines()
    except OSError:
        continue
    for ln in lines:
        r = ok(ln)
        if r is None:
            if ln.strip():
                dropped += 1
            continue
        out.append(ln.strip())
    if len(out) != len([x for x in lines if x.strip()]):
        tmp = p + ".fix"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write("\n".join(out) + ("\n" if out else ""))
        os.replace(tmp, p)

allp = os.path.join(d, "all.hosts")
merged = []
try:
    for n in names:
        for ln in open(os.path.join(d, n), encoding="utf-8", errors="replace"):
            if ok(ln):
                merged.append(ln.strip())
except OSError:
    pass
with open(allp + ".tmp", "w", encoding="utf-8") as f:
    f.write("\n".join(sorted(set(merged))) + ("\n" if merged else ""))
os.replace(allp + ".tmp", allp)

if dropped:
    print("[entrypoint] hosts 自检：丢掉 %d 行非法内容（不是「域名+IP」的），已重建 all.hosts" % dropped)
PY
# 清单：缺失时从镜像补齐（镜像里是构建时固化的完整版），并写入来源元数据
python3 /app/scheduler/lib/lists.py init >/dev/null 2>&1 || true
# 兜底（python 异常时也能保证文件存在）
[ -f "$DATA_DIR/cn_domains.txt" ] || cp /app/config/cn_domains.txt "$DATA_DIR/cn_domains.txt" 2>/dev/null || : > "$DATA_DIR/cn_domains.txt"
[ -f "$DATA_DIR/gfw_domains.txt" ] || cp /app/config/gfw_domains.txt "$DATA_DIR/gfw_domains.txt" 2>/dev/null || : > "$DATA_DIR/gfw_domains.txt"
[ -f "$DATA_DIR/china_ip.txt" ] || cp /app/config/china_ip.txt "$DATA_DIR/china_ip.txt" 2>/dev/null || : > "$DATA_DIR/china_ip.txt"
elog "分流清单: $(wc -l < "$DATA_DIR/china_ip.txt" 2>/dev/null || echo 0) 条国内 IP 段"
# IP 源与候选池：首次启动写入内置源（官方 + 第三方 + 镜像）
python3 /app/scheduler/lib/subs.py init >/dev/null 2>&1 || true
# 上游 DoH 候选清单：/data 缺文件时从镜像补齐，绝不覆盖用户已修改的版本
[ -f "$DATA_DIR/doh_remote_candidates.txt" ] || cp /app/config/doh_remote_candidates.txt "$DATA_DIR/doh_remote_candidates.txt"
[ -f "$DATA_DIR/doh_local_candidates.txt"  ] || cp /app/config/doh_local_candidates.txt  "$DATA_DIR/doh_local_candidates.txt"
# 观察名单：用户往里丢想试的新上游，扫描探测可用后自动收编进候选池
[ -f "$DATA_DIR/doh_watchlist.txt" ] || cp /app/config/doh_watchlist.txt "$DATA_DIR/doh_watchlist.txt"
elog "DoH 候选清单: 国外 $(wc -l < "$DATA_DIR/doh_remote_candidates.txt" 2>/dev/null || echo 0) 行 / 国内 $(wc -l < "$DATA_DIR/doh_local_candidates.txt" 2>/dev/null || echo 0) 行（可改 /data 下文件增删）"
# 老清单里可能留着写错的 DoH 地址（把普通 DNS 的 IP 当成 DoH 端点），
# 这种条目每次探测都白跑、页面上还挂着「不通」。启动时统一修一次。
if FIXED=$(PREF_DATA_DIR="$DATA_DIR" python3 /app/scheduler/lib/doh_config.py pool-fix 2>&1); then
  [ -n "$FIXED" ] && elog "候选清单整理: $(echo "$FIXED" | tr '\n' ' ')"
else
  elog "候选清单整理跳过（不影响解析）"
fi

# ---------- 自动线程 ----------
if [ -z "$THREADS" ] || [ "$THREADS" = "auto" ]; then
  THREADS=$(detect_threads)
fi
elog "优选并发线程: $THREADS"

# ---------- 账号密码：固定初始 admin/admin，不再读环境变量 ----------
# 规则：① 已存在 /data/auth.json → 沿用（控制台改过的密码，重启不会被冲掉）
#       ② 不存在 → 写入 admin/admin；首次登录强制改密（前端不给进，接口也拦）
if [ ! -f "$DATA_DIR/auth.json" ]; then
  python3 - "$DATA_DIR/auth.json" <<'PY'
import json, os, sys
p = sys.argv[1]
tmp = p + ".tmp"
with open(tmp, "w") as f:
    json.dump({"user": "admin", "pass": "admin", "default": True}, f, ensure_ascii=False)
os.replace(tmp, p)
PY
  elog "初始登录账号: admin / admin（首次登录会强制修改密码）"
else
  elog "沿用已保存的登录账号（首次登录若仍是 admin/admin 会被强制改密）"
fi

# ---------- 默认设置 ----------
if [ ! -f "$DATA_DIR/settings.json" ]; then
  cat > "$DATA_DIR/settings.json" <<EOF
{"interval_min":60,"threads":$THREADS,"auto_reload":true,"list_auto_update":true,"list_update_hours":24,"top_n":3,"ipv6":true,"verify_https":true,"bad_ttl_hours":${PREF_BAD_TTL_HOURS:-6},"watchdog_sec":${PREF_WATCHDOG_SEC:-180},"sub_ttl_days":${PREF_SUB_TTL_DAYS:-14},"pool_max":${PREF_POOL_MAX:-4000},"stable_hours":${PREF_STABLE_HOURS:-6},"stable_ttfb_ms":${PREF_STABLE_TTFB_MS:-1200},"stable_speed_kbps":${PREF_STABLE_SPEED_KBPS:-200},"pref_stable":true,"doh_scan_enabled":true,"doh_scan_min":${PREF_DOH_SCAN_MIN:-60},"doh_keep":3,"push":{"enabled":false,"url":"","events":"round,warn,login"},"keep_min":3,"routes":{"cf":true,"google":true,"gt":true,"github":true,"ghcr":true,"tmdb":true,"imdb":true}}
EOF
else
  # 老部署升级：新版本加的设置项要补进去。
  # 为什么必须补：控制台那一栏读不到值就是空的，用户看到空白会以为坏了；
  # 而且一保存就会被覆盖成默认值，等于白改了。已存在的值一律不动。
  python3 - "$DATA_DIR/settings.json" <<'PY'
import json, os, sys
p = sys.argv[1]
try:
    with open(p) as f:
        d = json.load(f)
except Exception:
    raise SystemExit(0)
add = {"keep_min": 3,
       "doh_scan_enabled": True, "doh_scan_min": 60, "doh_keep": 3,
       "routes": {"cf": True, "google": True, "gt": True,
                  "github": True, "ghcr": True, "tmdb": True, "imdb": True}}
chg = False
for k, v in add.items():
    if k not in d:
        d[k] = v
        chg = True
    elif isinstance(v, dict) and isinstance(d.get(k), dict):
        for rk, rv in v.items():
            if rk not in d[k]:
                d[k][rk] = rv
                chg = True
if chg:
    tmp = p + ".tmp"
    with open(tmp, "w") as f:
        json.dump(d, f, ensure_ascii=False)
    os.replace(tmp, p)
PY
fi

# ---------- 渲染 mosdns 配置 ----------
# 上游 DoH 由本地探测结果注入（不写死任何厂商）：
#   select_doh.py 在【容器内】逐个连候选 IP、发真实 DoH 请求，只收录当地真能通的。
esc() { printf '%s' "$1" | sed 's/[&|\\]/\\&/g'; }

# 控制台里手动指定了上游（/data/doh_*_custom.txt）就直接用，不再探测：
# 用户填什么就用什么，容器重启也照办；只有没填的才自动探测。
_p1=""; _p2=""

# 上次扫描（doh_watch）按实测延时挑出来的那几条，重启时原样沿用。
#
# 为什么必须先问它：启动时 select_doh 是「新探一遍、挑最快 3 条」，它和扫描
# 用的不是同一套测量，而且顺序也不一样 —— 每重启一次就把扫描辛苦换好的上游
# 换回去，界面上就成了「明明有 55ms 的，在用的却是 111ms」。数据还新（6 小时
# 内）就以扫描结果为准，扫描自然会继续按延时优化。
carry_scan() { # $1=side $2=输出文件
  python3 - "$1" "$2" <<'PY'
import json, sys, time
side, out = sys.argv[1], sys.argv[2]
try:
    d = json.load(open("/data/doh_scan.json", encoding="utf-8"))
except Exception:
    sys.exit(1)
if time.time() - float(d.get("at") or 0) > 6 * 3600:
    sys.exit(1)
lines = (d.get("active") or {}).get(side) or []
if not lines:
    sys.exit(1)
buf = []
for ln in lines:
    parts = str(ln).split()
    if not parts:
        continue
    buf.append('        - addr: "%s"' % parts[0])
    if len(parts) > 1:
        buf.append('          dial_addr: "%s:443"' % parts[1].strip("[]"))
    buf.append("          insecure_skip_verify: true")
if not buf:
    sys.exit(1)
with open(out, "w", encoding="utf-8") as f:
    f.write("\n".join(buf) + "\n")
PY
}

if [ -s "$DATA_DIR/doh_remote_custom.txt" ]; then
  cp -f "$DATA_DIR/doh_remote_custom.txt" /tmp/remote_list.txt
  elog "国外上游：沿用控制台手动配置"
elif carry_scan remote /tmp/remote_list.txt; then
  elog "国外上游：沿用上次扫描结果（实测延时排序）"
else
  python3 /app/scheduler/lib/select_doh.py "$DATA_DIR/doh_remote_candidates.txt" www.google.com 3 6 >/tmp/remote_list.txt 2>/tmp/remote_doh.log &
  _p1=$!
fi
if [ -s "$DATA_DIR/doh_local_custom.txt" ]; then
  cp -f "$DATA_DIR/doh_local_custom.txt" /tmp/local_list.txt
  elog "国内上游：沿用控制台手动配置"
elif carry_scan local /tmp/local_list.txt; then
  elog "国内上游：沿用上次扫描结果（实测延时排序）"
else
  python3 /app/scheduler/lib/select_doh.py "$DATA_DIR/doh_local_candidates.txt"  www.baidu.com  3 6 >/tmp/local_list.txt  2>/tmp/local_doh.log &
  _p2=$!
fi
[ -n "$_p1" ] && wait "$_p1" 2>/dev/null || true
[ -n "$_p2" ] && wait "$_p2" 2>/dev/null || true

# 本次探测结果落到 /data 存档；下次若是瞬时网络抖动探测不到，直接沿用上次能用的，
# 不会因为一次探测失败就把线上解析能力清空。
settle() { # $1=探测输出 $2=存档文件 $3=标签 $4=候选清单
  if grep -q 'addr:' "$1" 2>/dev/null; then
    cp -f "$1" "$2" 2>/dev/null || true
    return 0
  fi
  if [ -s "$2" ]; then
    cp -f "$2" "$1" 2>/dev/null || true
    elog "$3 本次探测无可用上游，沿用上次选中的结果"
    return 0
  fi
  # 两处都空：取候选清单首条占位，保证配置合法（不写死任何厂商）
  local cand url boot
  cand=$(grep -v '^[[:space:]]*#' "$4" 2>/dev/null | awk 'NF{print $1"|"$2; exit}')
  url=${cand%%|*}
  boot=${cand#*|}
  if [ -n "$url" ]; then
    {
      printf '        - addr: "%s"\n' "$url"
      [ -n "$boot" ] && printf '          dial_addr: "%s:443"\n' "$boot"
      printf '          insecure_skip_verify: true\n'
    } > "$1"
    elog "$3 无可用上游且无存档，暂用候选清单首条占位（解析可能失败）"
  else
    : > "$1"
    elog "$3 候选清单为空，没有可用上游"
  fi
}
settle /tmp/remote_list.txt "$DATA_DIR/doh_remote_selected.txt" "国外" "$DATA_DIR/doh_remote_candidates.txt"
settle /tmp/local_list.txt  "$DATA_DIR/doh_local_selected.txt"  "国内" "$DATA_DIR/doh_local_candidates.txt"
elog "上游 DoH 本地探测：国外 $(grep -c 'addr:' /tmp/remote_list.txt 2>/dev/null || echo 0) 个 / 国内 $(grep -c 'addr:' /tmp/local_list.txt 2>/dev/null || echo 0) 个"

sed \
  -e "s|__DNS_PORT__|$(esc "$DNS_PORT")|g" \
  -e "s|__API_PORT__|$(esc "$API_PORT")|g" \
  -e "s|__CACHE_SIZE__|$(esc "$CACHE_SIZE")|g" \
  -e "/__REMOTE_DOH_LIST__/r /tmp/remote_list.txt" -e "/__REMOTE_DOH_LIST__/d" \
  -e "/__LOCAL_DOH_LIST__/r /tmp/local_list.txt"  -e "/__LOCAL_DOH_LIST__/d" \
  /app/config/config.yaml > "$DATA_DIR/config.yaml"

# 给每条在用上游开一个只走它的环回入口（监测页用它测 mosdns 自己的转发耗时）
if PREF_DATA_DIR="$DATA_DIR" python3 /app/scheduler/lib/doh_config.py diag >>"$DATA_DIR/pref.log" 2>&1; then
  elog "$(tail -1 "$DATA_DIR/pref.log" 2>/dev/null | sed 's/^/测速入口: /')"
else
  elog "测速入口生成失败（不影响解析，监测页会显示不出来）"
fi
elog "配置已渲染: $DATA_DIR/config.yaml (DNS:$DNS_PORT API:$API_PORT UI:$UI_PORT)"

# ---------- mosdns supervisor ----------
start_mosdns() {
  /usr/local/bin/mosdns start -c "$DATA_DIR/config.yaml" -d "$DATA_DIR" >>"$DATA_DIR/mosdns.out" 2>&1 &
  echo $! > "$DATA_DIR/mosdns.pid"
}

mosdns_loop() {
  while true; do
    pid=""
    if [ -f "$DATA_DIR/mosdns.pid" ]; then
      pid=$(cat "$DATA_DIR/mosdns.pid" 2>/dev/null)
      # pid 号会跨容器复用：重建容器后旧 pid 很可能被 UI/调度器占上，
      # 这时 kill -0 依然成功，就会一直以为引擎还活着、永远不启动它。
      # 所以必须确认这个号上跑的确实是 mosdns。
      cmdline=""
      if [ -n "$pid" ] && [ -r "/proc/$pid/cmdline" ]; then
        cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
      fi
      case "$cmdline" in
        *mosdns*) sleep 1; continue ;;
        *) rm -f "$DATA_DIR/mosdns.pid"; pid="" ;;
      esac
    fi
    start_mosdns
    sleep 1
    pid=$(cat "$DATA_DIR/mosdns.pid" 2>/dev/null)
    if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
      elog "mosdns 启动失败，5 秒后重试（详见 $DATA_DIR/mosdns.out）"
      sleep 5
    else
      elog "mosdns 已启动 (pid $pid)"
      sleep 2
    fi
  done
}
mosdns_loop &

# ---------- scheduler（等 mosdns 就绪后再起）----------
# 容器里 PID 1 是 UI，调度器收不到 SIGTERM，上一轮如果正好跑到一半被重建，
# 优选锁会残留在 /data 里（持久化目录），不清掉的话之后每一路都要空等超时。
rm -rf "$DATA_DIR/.pref.lock" 2>/dev/null || true
( sleep 6; exec /app/scheduler/scheduler.sh daemon ) &

# ---------- watchdog（盯住 1034，一出现就换 IP）----------
export PREF_WATCHDOG_SEC="${PREF_WATCHDOG_SEC:-180}"
export PREF_DATA_DIR="$DATA_DIR"
( sleep 20; exec python3 /app/scheduler/lib/watchdog.py ) &

# ---------- UI（前台，容器主进程）----------
export PREF_UI_PORT="$UI_PORT"
export PREF_DATA_DIR="$DATA_DIR"
export PREF_DNS_PORT="$DNS_PORT"
export PREF_API_PORT="$API_PORT"
exec python3 /app/ui/server.py
