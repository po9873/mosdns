#!/bin/bash
# ============================================================
# 公共函数库（被 entrypoint 与七路优选脚本 source）
# 设计原则：运行时零外网下载；候选 IP 靠向 mosdns 实时查询 +
#           订阅池 + 种子兜底；延迟靠纯 TCP 直连探测；
#           真实 HTTPS 校验，1034 一出现就换 IP，绝不降级使用坏 IP。
# ============================================================

DATA_DIR="${PREF_DATA_DIR:-/data}"
PREF_DIR="$DATA_DIR/prefs"
SETTINGS_FILE="$DATA_DIR/settings.json"
MOSDNS_PID_FILE="$DATA_DIR/mosdns.pid"
LOCK_DIR="$DATA_DIR/.pref.lock"
SELF_DIR="/app/scheduler"
SUB_PY="$SELF_DIR/lib/subs.py"
BAD_TTL_H="${PREF_BAD_TTL_HOURS:-6}"

log() {
  local m
  m="[$(date '+%m-%d %H:%M:%S')] $*"
  echo "$m"
  echo "$m" >> "${PREF_LOG:-$DATA_DIR/pref.log}" 2>/dev/null || true
}

# 自动并发线程：取 CPU 核数，受 cgroup 限制约束，虚拟机折半，最低 1
detect_threads() {
  local n
  n=$(nproc 2>/dev/null || echo 2)
  if [ -r /sys/fs/cgroup/cpu.max ]; then
    local q p
    read -r q p < /sys/fs/cgroup/cpu.max 2>/dev/null || true
    if [ -n "${q:-}" ] && [ "$q" != "max" ] && [ -n "${p:-}" ] && [ "$p" -gt 0 ] 2>/dev/null; then
      local cg=$(( (q + p - 1) / p ))
      [ "$cg" -lt "$n" ] && n=$cg
    fi
  elif [ -r /sys/fs/cgroup/cpu/cpu.cfs_quota_us ]; then
    local quota period
    quota=$(cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us 2>/dev/null || echo -1)
    period=$(cat /sys/fs/cgroup/cpu/cpu.cfs_period_us 2>/dev/null || echo 100000)
    if [ "${quota:--1}" -gt 0 ] 2>/dev/null && [ "${period:-0}" -gt 0 ] 2>/dev/null; then
      local cg=$(( (quota + period - 1) / period ))
      [ "$cg" -lt "$n" ] && n=$cg
    fi
  fi
  if [ -r /sys/class/dmi/id/product_name ]; then
    local pn
    pn=$(cat /sys/class/dmi/id/product_name 2>/dev/null || true)
    case "$pn" in
      *VirtualBox*|*VMware*|*KVM*|*Virtual*|*QEMU*|*Bochs*) n=$(( (n + 1) / 2 )) ;;
    esac
  fi
  [ "$n" -lt 1 ] && n=1
  echo "$n"
}

# 读 settings.json 的键（支持 a.b 形式），布尔输出 true/false
setting() {
  python3 - "$SETTINGS_FILE" "$1" <<'PY' 2>/dev/null
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print(""); raise SystemExit
v = d
for k in sys.argv[2].split("."):
    if isinstance(v, dict) and k in v:
        v = v[k]
    else:
        v = None; break
if v is True: print("true")
elif v is False: print("false")
elif v is None: print("")
else: print(v)
PY
}

# ---------- 全局串行锁（任一时刻只允许一路优选运行）----------
# 优选锁。容器里 PID 1 是 UI 进程，调度器收不到 SIGTERM，
# 容器被重建/强杀时 trap 不会执行，锁目录会残留在持久化的 /data 里。
# 所以每次抢锁前先判断持有者是否还活着，别对着一个死锁干等 30 分钟。
acquire_lock() {
  local waited=0 pidfile="$LOCK_DIR/pid" owner=""
  while ! mkdir "$LOCK_DIR" 2>/dev/null; do
    owner=""
    if [ -f "$pidfile" ]; then
      owner=$(tr -dc '0-9' < "$pidfile" 2>/dev/null)
    fi
    # 1) 持有进程已经不存在（容器重启后留下的旧 pid）→ 直接接管
    if [ -n "$owner" ] && [ ! -d "/proc/$owner" ]; then
      log "发现残留优选锁（持有进程 $owner 已退出），清理后继续"
      rm -rf "$LOCK_DIR" 2>/dev/null || true
      continue
    fi
    # 2) 兜底：锁存在超过 2 小时，一律按过期处理
    if find "$LOCK_DIR" -maxdepth 0 -mmin +120 2>/dev/null | grep -q .; then
      log "优选锁已持有时长超过 2 小时，判定为过期，清理后继续"
      rm -rf "$LOCK_DIR" 2>/dev/null || true
      continue
    fi
    sleep 1
    waited=$((waited + 1))
    if [ "$waited" -ge 600 ]; then
      log "等待优选锁超时（10 分钟），放弃"
      return 1
    fi
  done
  echo $$ > "$LOCK_DIR/pid" 2>/dev/null || true
  trap 'release_lock' EXIT INT TERM
  return 0
}
release_lock() {
  rm -rf "$LOCK_DIR" 2>/dev/null || true
}

# ---------- 候选与探测 ----------
is_ip4() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
is_ip6() { [[ "$1" == *:* ]]; }
is_ip() { is_ip4 "$1" || is_ip6 "$1"; }

first_domain() {
  awk '!/^[[:space:]]*#/ && NF {print; exit}' "$1" 2>/dev/null
}

# 种子里所有域名（用于全部解析，而不是只解析第一个）
seed_domains() {
  awk '!/^[[:space:]]*#/ && NF {print $1}' "$1" 2>/dev/null | grep -E '\.[a-zA-Z]{2,}$'
}

# 种子里写死的兜底 IP（v4 / v6 都认）
fallback_ips() {
  awk '!/^[[:space:]]*#/ && NF {print $1}' "$1" 2>/dev/null \
    | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-fA-F:]+$'
}

# 向本机 mosdns 查询（不依赖系统 resolv.conf，避免自解析循环）
resolve_ips() {
  local domain="$1" port="${2:-${PREF_DNS_PORT:-53}}" qtype="${3:-A}"
  [ -z "$port" ] && port="${PREF_DNS_PORT:-53}"
  python3 "$SELF_DIR/lib/dnsq.py" 127.0.0.1 "$port" "$domain" "$qtype" 2>/dev/null
}

# 并发 TCP 探测，返回延迟最低的前 N 个（每行 "ip 延迟ms"）
probe_top() {
  local ips="$1" port="${2:-443}" conc="${3:-4}" tmo="${4:-3}" n="${5:-3}"
  [ -z "$ips" ] && return 0
  printf '%s\n' "$ips" \
    | python3 "$SELF_DIR/lib/probe.py" "$port" "$tmo" "$conc" 2>/dev/null \
    | head -n "$n"
}

probe_best() {
  probe_top "$1" "${2:-443}" "${3:-4}" "${4:-3}" 1 | awk 'NR==1{print $1}'
}

# 取文件 mtime（秒），跨平台用 python 实现，避免 busybox/coreutils 差异
stat_mtime() {
  python3 -c "import os,sys; print(int(os.path.getmtime(sys.argv[1])))" "$1" 2>/dev/null
}

# ---------- 失败退避 ----------
# 为什么需要：某一路的 IP 在当地整层不通时（比如 Google 的 IP 被墙），
# 每轮全量探测都要白跑 2~3 分钟，最后仍然「TCP 探测全部失败」。
# 既然这条路本来就走上游解析、能用，就不该反复折腾。
# 规则：连续失败 → 退避 1h → 2h → 4h → 6h（封顶）；一旦选出结果立即清零。
# 手动「立即执行」走 PREF_FORCE=1，忽略退避。
retry_next() {   # 打印下次可重试的时间戳；无退避则打印 0
  python3 - "$PREF_DIR/$1.retry" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print(int(d.get("next", 0)))
except Exception:
    print(0)
PY
}

retry_fail() {   # 记一次失败：次数+1，按 1/2/4/6h 递增退避
  python3 - "$PREF_DIR/$1.retry" <<'PY'
import json, sys, time
p = sys.argv[1]
try:
    d = json.load(open(p))
except Exception:
    d = {"fails": 0, "next": 0}
n = int(d.get("fails", 0)) + 1
step = [3600, 7200, 14400, 21600][min(n - 1, 3)]
now = int(time.time())
d = {"fails": n, "next": now + step, "last": now, "wait": step}
json.dump(d, open(p, "w"))
print("%d %d" % (n, step))
PY
}

retry_clear() { rm -f "$PREF_DIR/$1.retry" 2>/dev/null; }

# 从候选里排除已经试过的一批
exclude_ips() {
  local all="$1" drop="$2" a b
  a=$(mktemp); b=$(mktemp)
  printf '%s\n' "$all" | awk 'NF{print $1}' | sort -u > "$a"
  printf '%s\n' "$drop" | awk 'NF{print $1}' | sort -u > "$b"
  comm -23 "$a" "$b" 2>/dev/null
  rm -f "$a" "$b"
}

# ---------- 订阅池 / 黑名单 ----------
sub_cli() {
  python3 "$SUB_PY" "$@" 2>/dev/null
}

# stdin 过滤掉黑名单里的 IP
filter_bad_ips() {
  sub_cli filter
}

# ---------- 结果落盘 ----------
# mosdns hosts 格式：每行「域名 ip1 ip2 ...」，域名必须在第一位，
# 后面可跟任意多个 IP（v4/v6 可混在同一行，引擎会自动按查询类型分开应答）。
write_route() {
  local route="$1" domain="$2"
  shift 2
  local pairs ips dok
  pairs=$(printf '%s\n' "$@" | awk 'NF')
  if [ -z "$pairs" ]; then
    log "$route: 无可用 IP，保留上一轮结果"
    return 1
  fi
  ips=$(printf '%s\n' "$pairs" | awk '{print $1}' | awk '!seen[$0]++')
  {
    printf '%s' "$domain"
    printf ' %s' $ips
    printf '\n'
    # 同一批 IP 还要一并映射的域名（PREF_EXTRA_DOMAINS，空格分隔）。
    # 只给「确定共用同一批边缘节点」的路用：翻译的网页端 translate.google.com
    # 和接口端 translate.googleapis.com 就是同一批节点，两个都得映射，
    # 否则浏览器/插件走接口那个域名时仍会被解析到上游的污染结果。
    # 不能所有路都这么干：github.com 和 raw.githubusercontent.com 根本不是一批 IP。
    for d in ${PREF_EXTRA_DOMAINS:-}; do
      [ "$d" = "$domain" ] && continue
      # 附加域名也得逐个 IP 验一遍，不能照抄主域名的 IP。
      # 「这个 IP 能服务 A 域名」不等于「能服务 B 域名」——CloudFront 上实测
      # IMDb 那批 IP 里就有一个对 m.media-amazon.com 回 421 Misdirected，
      # 照抄过去的结果是网页能开、海报全裂。
      dok=$(printf '%s\n' $ips \
            | python3 "$SELF_DIR/lib/https_probe.py" "$d" 443 6 4 1 / "" "" 2>/dev/null \
            | awk '$2=="ok"{print $1}')
      if [ -z "$dok" ]; then
        log "$route: 附加域名 $d 没有 IP 通过校验，本次不映射（否则那个域名会打不开）"
        continue
      fi
      printf '%s' "$d"
      printf ' %s' $dok
      printf '\n'
    done
  } > "$PREF_DIR/$route.hosts"
  # 额外域名组：写在文件里，每行「域名 ip1 ip2 ...」，每个域名配自己的那批 IP。
  # 为什么不能复用 PREF_EXTRA_DOMAINS：那是「同一批节点」的域名（翻译的网页端和
  # 接口端）。ghcr 不一样——ghcr.io 与 pkg-containers.githubusercontent.com
  # 是两个完全不同的 CDN，共用一批 IP 必然有一个打不开。
  if [ -n "${PREF_EXTRA_LINES:-}" ] && [ -s "$PREF_EXTRA_LINES" ]; then
    awk 'NF' "$PREF_EXTRA_LINES" >> "$PREF_DIR/$route.hosts"
  fi
  printf '%s\n' "$pairs" > "$PREF_DIR/$route.meta"
  merge_hosts
}

merge_hosts() {
  # 注意：不能 cat "$PREF_DIR"/*.hosts —— 那样会把 all.hosts 自己也合进去，
  # 每跑一轮就把上一轮内容再追加一遍，文件无限膨胀、同一域名堆一堆重复行。
  # 只合并各路自己的 cf.hosts / google.hosts / ... ，再整体去重。
  local f base out="$PREF_DIR/all.hosts.tmp"
  : > "$out"
  for f in "$PREF_DIR"/*.hosts; do
    [ -f "$f" ] || continue
    base=$(basename "$f")
    case "$base" in
      all.hosts|all.hosts.*) continue ;;
    esac
    awk 'NF' "$f" >> "$out"
  done
  # 同一域名只留一行；IP 先归一化再去重
  # （同一个 IPv6 可能有 2606:4700:0:af:… 和 2606:4700:0000:00af:… 两种写法，其实是同一个地址）
  python3 - "$out" <<'PY'
import sys, ipaddress
src = sys.argv[1]

def norm(x):
    try:
        return str(ipaddress.ip_address(x))
    except ValueError:
        return x

best = {}
for ln in open(src, encoding="utf-8"):
    p = ln.split()
    if not p:
        continue
    dom = p[0]
    ips, seen = [], set()
    for x in p[1:]:
        k = norm(x)
        if k in seen:
            continue
        seen.add(k)
        ips.append(k)
    if not ips:
        continue
    cur = best.get(dom)
    if cur is None or len(ips) > len(cur):
        best[dom] = ips

with open(src, "w", encoding="utf-8") as f:
    for dom in sorted(best):
        f.write(dom + " " + " ".join(best[dom]) + "\n")
PY
  mv "$out" "$PREF_DIR/all.hosts"
}

# 让最新 hosts 生效：杀掉 mosdns，由 entrypoint supervisor 自动重启（约 1 秒）
reload_mosdns() {
  if [ -f "$MOSDNS_PID_FILE" ]; then
    local pid
    pid=$(cat "$MOSDNS_PID_FILE" 2>/dev/null)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null && log "已请求重载 mosdns"
      return 0
    fi
  fi
  return 1
}

file_sig() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" 2>/dev/null | awk '{print $1}'
  else
    cksum "$1" 2>/dev/null | awk '{print $1"-"$2}'
  fi
}

# 只有内容真的变化（或清单被更新）才重启；否则一次都不重启。
reload_if_changed() {
  local before="$1" after
  case "$(setting auto_reload)" in
    false|False|0) log "已关闭自动重载，结果将在下次重启后生效"; return 0 ;;
  esac
  after=$(file_sig "$PREF_DIR/all.hosts")
  if [ -f "$DATA_DIR/.lists_dirty" ]; then
    rm -f "$DATA_DIR/.lists_dirty"
    reload_mosdns
    return 0
  fi
  if [ "$before" != "$after" ]; then
    reload_mosdns
  else
    log "本轮结果与上轮一致，跳过重启（DNS 零中断）"
  fi
}

# ---------- 换 IP：立即止血 ----------
# 把坏 IP 从「当前正在生效」的 hosts 里立刻摘掉并重载，
# 不等本轮优选跑完，也不等下一个周期。
purge_bad_from_hosts() {
  local route="$1"; shift
  [ "$#" -eq 0 ] && return 0
  local hf="$PREF_DIR/$route.hosts" tmp left
  [ -f "$hf" ] || return 0
  tmp="$hf.purge"
  python3 - "$hf" "$tmp" "$@" <<'PY'
import sys
hf, tmp = sys.argv[1], sys.argv[2]
bad = set(sys.argv[3:])
out = []
try:
    lines = open(hf, encoding="utf-8").read().splitlines()
except Exception:
    lines = []
for ln in lines:
    parts = ln.split()
    if not parts:
        continue
    keep = [x for x in parts[1:] if x not in bad]
    if keep:
        out.append(" ".join([parts[0]] + keep))
open(tmp, "w", encoding="utf-8").write("\n".join(out) + ("\n" if out else ""))
PY
  left=$(awk 'NF' "$tmp" 2>/dev/null | wc -l | tr -d ' ')
  if [ "${left:-0}" -gt 0 ]; then
    mv "$tmp" "$hf"
    merge_hosts
    log "$route: 立即撤下坏 IP（$*），保留剩余 $left 条记录继续服务"
    reload_mosdns
    return 0
  fi
  rm -f "$tmp" "$hf" 2>/dev/null
  merge_hosts
  log "$route: 该路 IP 全部不可用，已撤下 hosts（域名回退上游解析），等待补位"
  reload_mosdns
  return 2
}

# 每路状态（供控制台展示：选了什么、拒了什么、为什么）
write_state() {
  local route="$1" domain="$2" status="$3" sel="$4" rej="$5" dns="$6" seed="$7" sub="$8"
  python3 - "$PREF_DIR/$route.state.json" "$route" "$domain" "$status" \
           "$sel" "$rej" "$dns" "$seed" "$sub" <<'PY' 2>/dev/null
import json, os, sys, time
path, route, domain, status, sel, rej, dns, seed, sub = sys.argv[1:10]
def sel_lines(s):
    out = []
    for ln in (s or "").splitlines():
        p = ln.split()
        if len(p) >= 2:
            out.append({"ip": p[0], "ms": p[1], "verify": p[2] if len(p) > 2 else ""})
    return out
def rej_lines(s):
    out = []
    for ln in (s or "").splitlines():
        p = ln.split()
        if len(p) >= 2:
            out.append({"ip": p[0], "reason": p[1]})
    return out
obj = {
    "route": route, "domain": domain, "status": status, "ts": int(time.time()),
    "selected": sel_lines(sel), "rejected": rej_lines(rej),
    "source": {"dns": int(dns or 0), "seed": int(seed or 0), "pool": int(sub or 0)},
}
tmp = path + ".tmp"
open(tmp, "w", encoding="utf-8").write(json.dumps(obj, ensure_ascii=False))
os.replace(tmp, path)
PY
}

# ---------- 消息推送（企业微信 / 钉钉 / 飞书 机器人）----------
notify() {
  local ev="$1" title="$2" body="$3"
  case "$(setting push.enabled)" in
    true|True|1) ;;
    *) return 0 ;;
  esac
  local url evs
  url=$(setting push.url)
  [ -z "$url" ] && return 0
  evs=$(setting push.events)
  case "$evs" in
    ""|None) ;;
    *)
      case ",$evs," in
        *",$ev,"*) ;;
        *) return 0 ;;
      esac
      ;;
  esac
  timeout 8 python3 "$SELF_DIR/lib/push.py" "$url" "$title" "$body" >/dev/null 2>&1 || true
}

# ---------- 选结果：最快的一批 + 保底备胎 ----------
# 输入 stdin：「ip TTFB 状态 吞吐」（已按 TTFB 升序），输出选中的若干行。
#   1) 先只看最快的那个，同族里 TTFB 不超过它 1.5 倍的都算「最快的一批」，
#      最多留 n 个 —— 慢的没必要留着占位置，用户要的就是最快的那批。
#   2) 但这批不足 k 个时，按 TTFB 顺序继续往下补到 k 个。
#      为什么：一路只剩 1 个 IP 是最危险的，它抖一下整路就没得换，只能等下一轮
#      重扫（几分钟）。宁可多留两个稍慢的备胎，也不要「孤零零一个」。
pick_best() {
  local n="${1:-3}" k="${2:-3}"
  awk -v n="$n" -v k="$k" '
    NF { cnt++; rows[cnt] = $0; t = $2 + 0; if (t <= 0) t = 999999; tv[cnt] = t }
    END {
      if (!cnt) exit
      for (i = 1; i <= cnt; i++)
        for (j = i + 1; j <= cnt; j++)
          if (tv[j] < tv[i]) {
            x = tv[i]; tv[i] = tv[j]; tv[j] = x
            y = rows[i]; rows[i] = rows[j]; rows[j] = y
          }
      lim = tv[1] * 1.5
      if (lim < tv[1] + 150) lim = tv[1] + 150   # 最快只有 100ms 时 1.5 倍太苛刻，放宽到 +150ms
      out = 0
      for (i = 1; i <= cnt && out < n; i++)
        if (tv[i] <= lim || out < k) { print rows[i]; out++ }
    }'
}

# 从候选池里补「历史验证通过」的备胎。
# 参数：route、还差几个、已经在用的行（多行 "ip ..."）
# 输出：每行「ip - backup -」（TTFB 未知，界面显示为「备胎」）
# 为什么只认 ok>0 的：这些 IP 以前真被本机验证通过过，比换一个从没测过的安全。
fill_backup() {
  local route="$1" need="$2" have="$3"
  local bf="$PREF_DIR/.$route.have" cf="$PREF_DIR/.$route.cand" ex
  [ "${need:-0}" -lt 1 ] && return 0
  printf '%s\n' "$have" | awk 'NF{print $1}' > "$bf"
  sub_cli pool "$route" 40 --verified > "$cf" 2>/dev/null
  ex=$(grep -vxF -f "$bf" "$cf" 2>/dev/null | awk 'NF' | head -n "$need")
  rm -f "$bf" "$cf" 2>/dev/null
  [ -n "$ex" ] && printf '%s\n' "$ex" | awk 'NF{print $1, "-", "backup", "-"}'
  return 0
}

# ---------- 单路优选主流程 ----------
run_route() {
  local route="$1" seed="$2" port="${3:-443}"
  local target conc top_n want6
  local seed_v4 seed_v6 seed_doms pool_ips pool_v4 pool_v6 pool_n
  local v4 v6 n4 n6 b4 b6 batch vres
  local ok hard soft best4 best6 total downgrade=0 keep_min

  target=$(first_domain "$seed")
  if [ -z "$target" ]; then
    log "$route: 种子文件无目标域名"
    return 1
  fi

  # ---- 这一路「怎么算能用」----
  # 默认请求 / 看 HTTP 正常即可；但有的服务根路径本来就返回 404（Google 前端节点
  # 全是这样），用 GET / 判断会把真能用的 IP 全判成不可用。所以允许按路指定：
  #   PREF_PROBE_TARGET  探测时用的域名（默认 = 种子域名）
  #   PREF_PROBE_PATH    请求路径（默认 /）
  #   PREF_PROBE_EXPECT  正文里必须出现的内容，没出现就判定「不提供该服务」
  local ptarget="${PREF_PROBE_TARGET:-$target}"
  local ppath="${PREF_PROBE_PATH:-/}"
  local pexp="${PREF_PROBE_EXPECT:-}"

  # ---- 失败退避：这一路当地整层不通时，别每轮白跑几分钟 ----
  local rnext rnow rleft
  if [ "${PREF_FORCE:-0}" != "1" ]; then
    rnow=$(date +%s)
    rnext=$(retry_next "$route")
    if [ -n "$rnext" ] && [ "${rnext:-0}" -gt "$rnow" ] 2>/dev/null; then
      rleft=$(( (rnext - rnow + 59) / 60 ))
      log "$route: 当地直连整层不通，暂停优选（${rleft} 分钟后再试；当前域名走上游解析，照常可用）"
      write_state "$route" "$target" "paused" "" "" 0 0 0
      return 0
    fi
  fi

  conc=$(setting threads)
  if [ -z "$conc" ] || [ "$conc" = "0" ] || [ "$conc" -lt 1 ] 2>/dev/null; then
    conc=$(detect_threads)
  fi
  [ "$conc" -lt 1 ] 2>/dev/null && conc=1

  top_n=$(setting top_n)
  case "$top_n" in ''|*[!0-9]*) top_n=3 ;; esac
  [ "$top_n" -lt 1 ] && top_n=1
  [ "$top_n" -gt 8 ] && top_n=8

  # 保底个数：每路至少留几个可用 IP（不足就从池里历史验证通过的补）。
  # 默认 3，且不超过 top_n —— 「留几个」本来就不该超过「每轮最多留几个」。
  keep_min=$(setting keep_min)
  case "$keep_min" in ''|*[!0-9]*) keep_min=3 ;; esac
  [ "$keep_min" -lt 1 ] && keep_min=1
  [ "$keep_min" -gt "$top_n" ] && keep_min=$top_n

  case "$(setting ipv6)" in
    false|False|0) want6=0 ;;
    *) want6=1 ;;
  esac
  # 单条路线可以自己关掉 v6（PREF_NO_V6=1）。为什么需要：IPv6 通不通是「按网段」
  # 的，不是「按机器」的。这台机器 v6 本身没问题（CloudFront 的 2600:9000 段能过校验），
  # 但 GitHub 公布的 v6 段（2a0a:a440::/32 这些）从当地根本不可路由，每轮白探十几个
  # 候选、每个等 6 秒，最后还是 0 个。既然选不出来，就别浪费这一分钟。
  [ "${PREF_NO_V6:-0}" = "1" ] && want6=0

  # ---- 稳定模式：守住已选 IP，不全量重探（多源池仅作「切换依据」）----
  # 判据不是「TCP 通」，而是「真能打开页面且不慢」：
  #   对当前选中的 IP 发真实 HTTPS 请求（SNI/Host=目标域名），拿到 TTFB 和吞吐。
  #   - 全部打不开（1034/证书/5xx/超时）→ 说明实际已坏，立刻全量重探换 IP
  #   - 能打开但 TTFB 超过 stable_ttfb_ms，或实测吞吐低于 stable_speed_kbps → 变慢了，重探
  #   - 能打开且不慢 → 完事，不动它（stable_hours 内不再全量扫）
  # 为什么每个 IP 测两次（samples=2）：单次吞吐抖动很大，实测同一个 IP 能测出
  # 158/289/532 KB/s。拿一次结果就判「慢」会天天误触发三分钟的全量重探，
  # 与「能用就别折腾」完全相反。两次取更好的那次——只要有一次证明它不慢，就不算慢。
  # 为什么带 ~ 的速度不参与判决：响应体只有几 KB 时算出来的 KB/s 是噪音
  # （TCP 一个窗口就传完，跨度 0.1s 以内），只用来给界面看个大概。
  local rhf="$PREF_DIR/$route.hosts" stable_hours mnow mprev cur live_out live_n
  local st_ttfb st_speed vchk vok vbest vspeed afail="$PREF_DIR/$route.allfail"
  stable_hours=$(setting stable_hours)
  case "$stable_hours" in ''|*[!0-9]*) stable_hours=6 ;; esac
  st_ttfb=$(setting stable_ttfb_ms); case "$st_ttfb" in ''|*[!0-9]*) st_ttfb=1200 ;; esac
  st_speed=$(setting stable_speed_kbps); case "$st_speed" in ''|*[!0-9]*) st_speed=200 ;; esac
  # 手动点「立即执行」= 你说了算：PREF_FORCE=1 时不做稳定模式判断，直接真跑
  # （否则点了按钮只看到「跳过全量重探」，会以为按钮坏了）
  if [ "${stable_hours:-0}" -gt 0 ] && [ -s "$rhf" ] && [ "$(setting pref_stable)" != "false" ] \
     && [ "${PREF_FORCE:-0}" != "1" ]; then
    mnow=$(date +%s)
    mprev=$(stat_mtime "$rhf")
    # 注意单位：mprev 是秒，stable_hours 是小时 → 必须换算成秒再比。
    # （早先写成「分钟数 < 小时数」，导致 24 分钟就被判成窗口过期、每轮都全量重扫。）
    if [ -n "$mprev" ] && [ $(( mnow - ${mprev:-0} )) -lt $(( stable_hours * 3600 )) ]; then
      cur=$(awk 'NR==1{for(i=2;i<=NF;i++) print $i}' "$rhf" | grep -E '^[0-9a-fA-F:.]+$')
      if [ -n "$cur" ]; then
        case "$(setting verify_https)" in
          false|False|0) vchk=$(printf '%s\n' "$cur" | awk '{print $1, "ok", "?", "-"}') ;;
          *) vchk=$(printf '%s\n' "$cur" | python3 "$SELF_DIR/lib/https_probe.py" "$ptarget" "$port" 6 "$conc" 2 "$ppath" "$pexp" "${PREF_SPEED_URL:-}" 2>/dev/null) ;;
        esac
        live_out=$(printf '%s\n' "$vchk" | awk '$2=="ok"')
        live_n=$(printf '%s\n' "$live_out" | awk 'NF' | wc -l | tr -d ' ')
        if [ "${live_n:-0}" -ge 1 ]; then
          # 最快那个就是这一路的实际体验：TTFB 看响应快慢，speed 看吞吐（拿不到时为空）
          vbest=$(printf '%s\n' "$live_out" | awk '$3!="-"{print $3}' | sort -n | head -1)
          # 只取可信样本（不带 ~）：~ 是样本太小的估算值，抖动大到不能当判决依据
          vspeed=$(printf '%s\n' "$live_out" | awk '$4!="-" && $4 !~ /^~/ {print $4}' | sort -n | tail -1)
          local slow="" why=""
          if [ -n "$vbest" ] && [ "${vbest%%.*}" -gt "$st_ttfb" ] 2>/dev/null; then
            slow=1; why="响应 ${vbest%.*}ms 超过 ${st_ttfb}ms"
          elif [ -n "$vspeed" ] && [ "${vspeed%%.*}" -lt "$st_speed" ] 2>/dev/null; then
            slow=1; why="两轮实测吞吐都只有 ${vspeed%.*}KB/s（低于 ${st_speed}KB/s）"
          fi
          if [ -z "$slow" ]; then
            local shown_speed live_rows orig_n state_rows
            shown_speed=$(printf '%s\n' "$live_out" | awk '$4!="-"{print $4}' | sort -n | tail -1)
            rm -f "$afail" 2>/dev/null
            log "$route: 稳定模式，${live_n} 个 IP 能打开且不慢（响应 ${vbest:-?}ms${shown_speed:+ / ${shown_speed#\~}KB/s}），跳过全量重探（约 $(( (mnow - mprev) / 60 )) 分钟前优选过）"
            live_rows=$(printf '%s\n' "$live_out" | awk 'NF{print $1, $3, "ok", $4}')
            state_rows="$live_rows"
            # 稳定归稳定，但「在用的 IP 太少」也得管：ghcr 这种天然只选得出 1 个，
            # 它一抖整路就没得换。这里只做一件事——补到 keep_min 个，别的不动。
            if [ "${live_n:-0}" -lt "$keep_min" ]; then
              orig_n="$live_n"
              local want hf candf candlist vres added extra2 nb2
              want=$(( (keep_min - live_n) * 8 ))
              [ "$want" -lt 12 ] && want=12
              [ "$want" -gt 24 ] && want=24
              hf="$PREF_DIR/.$route.have"; candf="$PREF_DIR/.$route.cand"
              printf '%s\n' "$live_rows" | awk 'NF{print $1}' > "$hf"
              sub_cli pool "$route" 40 > "$candf" 2>/dev/null
              candlist=$(grep -vxF -f "$hf" "$candf" 2>/dev/null | awk 'NF' | head -n "$want")
              rm -f "$hf" "$candf" 2>/dev/null
              # ① 先现场验几个池里的新候选：它们可能比备胎更好，验证通过才算数
              if [ -n "$candlist" ]; then
                vres=$(printf '%s\n' "$candlist" \
                       | python3 "$SELF_DIR/lib/https_probe.py" "$ptarget" "$port" 6 "$conc" 1 "$ppath" "$pexp" "${PREF_SPEED_URL:-}" 2>/dev/null \
                       | awk '$2=="ok"{print $1, $3, "ok", ($4==""?"-":$4)}' | sort -k2 -n \
                       | head -n $(( keep_min - live_n )))
                if [ -n "$vres" ]; then
                  added=$(printf '%s\n' "$vres" | awk 'NF' | wc -l | tr -d ' ')
                  printf '%s\n' "$vres" | awk 'NF{print $1, "verify"}' | sub_cli feed "$route" >/dev/null 2>&1
                  printf '%s\n' "$vres" | awk 'NF{print $1, "ok"}' | sub_cli bump-many "$route" >/dev/null
                  live_rows=$(printf '%s\n%s' "$live_rows" "$vres")
                  state_rows="$live_rows"
                  live_n=$(( orig_n + added ))
                  log "$route: 在用的只有 ${orig_n} 个，现场验了池内 $(printf '%s\n' "$candlist" | awk 'NF' | wc -l | tr -d ' ') 个候选，补进 ${added} 个"
                fi
              fi
              # ② 还不够就用池里历史验证通过的备胎（没复测，标 backup）
              if [ "${live_n:-0}" -lt "$keep_min" ]; then
                extra2=$(fill_backup "$route" $(( keep_min - live_n )) "$live_rows")
                nb2=$(printf '%s\n' "$extra2" | awk 'NF' | wc -l | tr -d ' ')
                if [ "${nb2:-0}" -gt 0 ]; then
                  live_rows=$(printf '%s\n%s' "$live_rows" "$extra2")
                  state_rows="$live_rows"
                  live_n=$(( live_n + nb2 ))
                  log "$route: 再从池里补了 ${nb2} 个历史验证过的备胎"
                fi
              fi
              # 补过就重写 hosts（没补出东西就不动它，别白改一次文件触发重载）
              if [ "${live_n:-0}" -gt "$orig_n" ]; then
                write_route "$route" "$target" "$live_rows" || true
              fi
            fi
            # 把本轮实测结果写回，界面「已选 IP + 速度」不会因为跳过重探而变空
            write_state "$route" "$target" "stable" "$state_rows" "" "${live_n}" 0 0
            return 0
          fi
          log "$route: 稳定模式检测到变慢（$why），触发全量重探"
        else
          # 这一轮全打不开：先别急着花三分钟全量重探。
          # 单轮偶发失败（对方抖动/本机瞬时断流）很常见，守护进程每几分钟就会
          # 用单次探测换掉真坏的 IP；连续两轮都全打不开才算真坏，才值得重扫。
          local nfail=0
          [ -s "$afail" ] && nfail=$(cat "$afail" 2>/dev/null)
          case "$nfail" in ''|*[!0-9]*) nfail=0 ;; esac
          nfail=$(( nfail + 1 ))
          if [ "$nfail" -lt 2 ]; then
            echo "$nfail" > "$afail" 2>/dev/null
            log "$route: 稳定模式这一轮 ${live_n:-0} 个 IP 全打不开（第 ${nfail} 次），先交给守护进程换 IP，下一轮再复核"
            write_state "$route" "$target" "degraded" "" "" 0 0 0
            return 0
          fi
          rm -f "$afail" 2>/dev/null
          log "$route: 连续 ${nfail} 轮全打不开（1034/证书/5xx/超时），触发全量重探换 IP"
        fi
      fi
    fi
  fi

  # ---- 候选组装：种子域名全解析 + 订阅池 + 种子兜底 IP ----
  seed_doms=$(seed_domains "$seed")
  seed_v4=$(printf '%s\n' "$seed_doms" | while read -r d; do
              [ -n "$d" ] && resolve_ips "$d" "" A
            done)
  if [ "$want6" = "1" ]; then
    seed_v6=$(printf '%s\n' "$seed_doms" | while read -r d; do
                [ -n "$d" ] && resolve_ips "$d" "" AAAA
              done)
  else
    seed_v6=""
  fi

  # 每轮从池子里取多少个候选来试。
  # 为什么不是 top_n*20：CloudFront 这条路池里有 2000 多个边缘地址（AWS 官方段
  # 展开），一轮只试 60 个的话，要把池子摸一遍得几十轮。TCP 粗筛很快
  # （16 并发、3 秒超时，120 个也就半分钟），多试一些反而更快摸到快的节点。
  pool_ips=$(sub_cli take "$route" $(( top_n * 40 )))
  pool_n=$(printf '%s\n' "$pool_ips" | awk 'NF' | wc -l | tr -d ' ')
  pool_v4=$(printf '%s\n' "$pool_ips" | awk 'NF && !/:/')
  pool_v6=$(printf '%s\n' "$pool_ips" | awk 'NF && /:/')

  v4=$( { printf '%s\n' "$seed_v4"; fallback_ips "$seed"; printf '%s\n' "$pool_v4"; } \
        | awk 'NF' | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | sort -u | filter_bad_ips )
  v6=""
  if [ "$want6" = "1" ]; then
    v6=$( { printf '%s\n' "$seed_v6"; fallback_ips "$seed"; printf '%s\n' "$pool_v6"; } \
          | awk 'NF' | grep ':' | grep -E '^[0-9a-fA-F:]+$' | sort -u | filter_bad_ips )
  fi

  n4=$(printf '%s\n' "$v4" | awk 'NF' | wc -l | tr -d ' ')
  n6=$(printf '%s\n' "$v6" | awk 'NF' | wc -l | tr -d ' ')

  if [ "${n4:-0}" = "0" ] && [ "${n6:-0}" = "0" ]; then
    log "$route: 无候选 IP（DNS 未就绪、订阅池为空且无兜底）"
    write_state "$route" "$target" "no_candidate" "" "" 0 0 0
    log "$route: 无候选 IP（$(retry_fail "$route" | awk "{print \"第 \"\$1\" 次失败，\"\$2/3600\" 小时后重试\"}")）"
    return 1
  fi

  # ---- 把本轮候选来源回填进池：DNS 实时解析 + 种子兜底 ----
  # 没有公开订阅源的路线（Google/翻译/GitHub/ghcr）靠这一步积累候选，
  # 否则池子永远是 0，看门狗想补位也无米可炊。
  {
    printf '%s\n' "$v4" | awk 'NF{print $1, "dns"}'
    printf '%s\n' "$v6" | awk 'NF{print $1, "dns"}'
    printf '%s\n' "$seed_v4" | awk 'NF{print $1, "seed"}'
    printf '%s\n' "$seed_v6" | awk 'NF{print $1, "seed"}'
  } | sub_cli feed "$route" >/dev/null 2>&1

  log "$route: 目标 $target，候选 v4 ${n4} / v6 ${n6}（订阅池贡献 ${pool_n}），并发 $conc，每族保留 $top_n"

  # ---- 第一步：TCP 粗筛（多取若干倍，给校验失败留补位余量）----
  # 为什么取 12 倍而不是 3 倍：TCP 快 ≠ 能用。CloudFront 的中国大陆边缘
  # （120.52 / 180.163 / 111.13 这几段）就在国内，TCP 延迟最低，但它们只服务
  # 已备案的中国区加速域名，对 TMDB/IMDb 这种境外 distribution 一律不回话。
  # 只拿最快的 9 个去校验，等于让这批「快但不可用」的 IP 把真正能用的全挤掉，
  # 结果是「一个都选不出来」。多取一些一起校验，才能把能用的捞出来。
  b4=$(probe_top "$v4" "$port" "$conc" 3 $((top_n * 12)))
  b6=$(probe_top "$v6" "$port" "$conc" 3 $((top_n * 12)))
  batch=$( { printf '%s\n' "$b4"; printf '%s\n' "$b6"; } | awk 'NF' )

  # 种子文件里手写的 IP 是「已知能用」的清单，必须无条件进校验环节。
  # 为什么：池子里那些从大网段随机采样来的候选，TCP 往往更快——它们只是回了
  # SYN-ACK，压根不提供这个服务（CloudFront 中国区边缘、GitHub 的 192.30 段都是），
  # 一按连接时间排序就把种子 IP 挤出前 N 名。ghcr 那 10 个入口就是这么被挤掉、
  # 常年只剩 1 个的。宁可为这十几个 IP 多花一秒校验，也别让它们没机会说话。
  seed_fb=$(fallback_ips "$seed" 2>/dev/null | awk 'NF')
  if [ -n "$seed_fb" ]; then
    batch=$( { printf '%s\n' "$batch"; printf '%s\n' "$seed_fb"; } \
             | awk 'NF && !seen[$1]++' )
  fi

  if [ -z "$batch" ]; then
    log "$route: TCP 探测全部失败"
    write_state "$route" "$target" "no_tcp" "" "" 0 0 0
    log "$route: 候选全部 TCP 不通（$(retry_fail "$route" | awk "{print \"第 \"\$1\" 次失败，\"\$2/3600\" 小时后重试\"}")）"
    return 1
  fi

  # ---- 第二步：真实 HTTPS 校验（SNI/Host = 目标域名）----
  case "$(setting verify_https)" in
    false|False|0)
      vres=$(printf '%s\n' "$batch" | awk '{print $1, "ok", $2, "-"}')
      ;;
    *)
      vres=$(printf '%s\n' "$batch" | python3 "$SELF_DIR/lib/https_probe.py" "$ptarget" "$port" 6 4 1 "$ppath" "$pexp" "${PREF_SPEED_URL:-}" 2>/dev/null)
      # 补位：通过的不足 top_n 时，把没试过的候选再探一批，别急着降级
      ok=$(printf '%s\n' "$vres" | awk '$2=="ok"' | wc -l | tr -d ' ')
      if [ "${ok:-0}" -lt "$top_n" ]; then
        local more more_n
        more=$(exclude_ips "$(printf '%s\n%s\n' "$v4" "$v6")" "$batch" | head -n $((top_n * 6)))
        more_n=$(printf '%s\n' "$more" | awk 'NF' | wc -l | tr -d ' ')
        if [ "${more_n:-0}" -gt 0 ]; then
          log "$route: 仅 $ok 个通过校验，补探 $more_n 个候补"
          vres=$(printf '%s\n%s\n' "$vres" \
                 "$(printf '%s\n' "$more" | python3 "$SELF_DIR/lib/https_probe.py" "$ptarget" "$port" 6 4 1 "$ppath" "$pexp" "${PREF_SPEED_URL:-}" 2>/dev/null)")
        fi
      fi
      ;;
  esac

  # 通过校验的：ip TTFB ok 吞吐（TTFB 排序，界面显示的就是这个真实响应时间）
  ok=$(printf '%s\n' "$vres" | awk '$2=="ok"{print $1, $3, "ok", ($4==""?"-":$4)}' | sort -k2 -n)
  # 明确不可用：1034/1010/1020、证书不符、5xx、以及「能连但这个地址不提供该服务」
  hard=$(printf '%s\n' "$vres" | awk '$2!="ok" && $2!="timeout" && $2!="fail" && $2!="busy"{print $1" "$2}')
  # 不确定（可能只是网络抖动或对方限速）：超时、连接失败、429
  soft=$(printf '%s\n' "$vres" | awk '$2=="timeout"||$2=="fail"||$2=="busy"{print $1" "$2}')

  # ---- 第三步：坏 IP 立即拉黑 + 立即撤下，这一步就是「1034 一触发就换 IP」----
  if [ -n "$hard" ]; then
    local bad_ips n_hard
    bad_ips=$(printf '%s\n' "$hard" | awk '{print $1}')
    n_hard=$(printf '%s\n' "$hard" | awk 'NF' | wc -l | tr -d ' ')
    printf '%s\n' "$hard" | while read -r ip why; do
      [ -z "$ip" ] && continue
      sub_cli mark-bad "$ip" "$why" "$route" >/dev/null
    done
    log "$route: 校验拒绝 $n_hard 个（$(printf '%s' "$hard" | tr '\n' ' ')），已拉黑 ${BAD_TTL_H}h 并立即撤下"
    # shellcheck disable=SC2086
    purge_bad_from_hosts "$route" $bad_ips
  fi

  # ---- 第四步：选结果。绝不把「明确坏」的 IP 写进 hosts ----
  # 只留最快的那批（不只看 github，所有路一个标准），不足 keep_min 个再往下补。
  best4=""; best6=""
  if [ -n "$ok" ]; then
    best4=$(printf '%s\n' "$ok" | awk '!/:/' | pick_best "$top_n" "$keep_min")
    best6=$(printf '%s\n' "$ok" | awk '/:/' | pick_best "$top_n" "$keep_min")
  fi
  total=$( { printf '%s\n' "$best4"; printf '%s\n' "$best6"; } | awk 'NF' | wc -l | tr -d ' ' )

  # ---- 保底备胎：通过校验的太少时，从池里「历史验证通过过」的 IP 补到 keep_min ----
  # 典型就是 ghcr.io：实测 768 个 20.27.x 地址里只有 20.27.177.117 的证书覆盖
  # ghcr.io，本轮通过校验的自然只有 1 个。只剩 1 个的话它一抖整路就没得换，
  # 只能干等下一轮重扫。所以从池里挑「以前真验证通过、最近还成功过」的补上，
  # 标 backup —— 界面上看得出来是备胎，守护进程也会优先复核它们。
  local n_backup=0
  if [ "${total:-0}" -gt 0 ] && [ "$total" -lt "$keep_min" ]; then
    local extra need
    need=$(( keep_min - total ))
    extra=$(fill_backup "$route" "$need" "$(printf '%s\n%s' "$best4" "$best6")")
    if [ -n "$extra" ]; then
      best4=$(printf '%s\n%s\n' "$best4" "$(printf '%s\n' "$extra" | awk '!/:/{print $1, "-", "backup", "-"}')" | awk 'NF')
      best6=$(printf '%s\n%s\n' "$best6" "$(printf '%s\n' "$extra" | awk '/:/{print $1, "-", "backup", "-"}')" | awk 'NF')
      n_backup=$(printf '%s\n' "$extra" | awk 'NF' | wc -l | tr -d ' ')
      total=$( { printf '%s\n' "$best4"; printf '%s\n' "$best6"; } | awk 'NF' | wc -l | tr -d ' ' )
      log "$route: 本轮只选出 $(( total - n_backup )) 个，从池里补了 ${n_backup} 个历史验证过的备胎（防止只剩 1 个没得换）"
    fi
  fi

  if [ "$total" = "0" ]; then
    if [ -n "$soft" ] && [ -s "$rhf" ]; then
      # 只有超时/连不上、一个都没通过校验时，绝不拿「TCP 通但请求没回来的 IP」顶替。
      # 实测教训：把 Fastly 的 151.101.x / 185.199.x 写成 github.com 之后，
      # github.com 直接打不开——端口开着不代表这个 IP 认这个域名。
      # 保留上一轮已验证的结果，比换上一批没验证过的 IP 安全得多。
      log "$route: 本轮无 IP 通过校验，保留上一轮的 hosts 不动（不给没验证过的 IP 顶替）"
      write_state "$route" "$target" "degraded" "" "" "${n4:-0}" 0 "${pool_n}"
      return 2
    fi
    if [ -n "$soft" ] && [ "${PREF_ALLOW_DOWNGRADE:-0}" = "1" ]; then
      # 只有 Cloudflare 路允许这么干（见 cf_pref.sh）：它的「TCP 通」基本等于能开，
      # 首轮没结果时降级使用，起码让站点能动。
      # 其它路（Google / GitHub / TMDB / IMDb…）端口开着完全不代表这个 IP 认这个域名，
      # 降级写进去就是给用户一个打不开的 IP——不如让域名走上游解析，好歹能用。
      downgrade=1
      best4=$(printf '%s\n' "$soft" | awk '!/:/{print $1, "?", "unverified", "-"}' | head -n "$top_n")
      best6=$(printf '%s\n' "$soft" | awk '/:/{print $1, "?", "unverified", "-"}' | head -n "$top_n")
      total=$( { printf '%s\n' "$best4"; printf '%s\n' "$best6"; } | awk 'NF' | wc -l | tr -d ' ' )
      log "$route: 无 IP 通过校验（仅超时/连接失败），降级用 TCP 结果并标记 unverified"
      notify "warn" "$route 路优选降级" "无 IP 通过 HTTPS 校验（仅超时），已降级使用 TCP 结果，控制台显示为 unverified。"
    else
      # 全都没通过校验 → 撤下该路，宁可回退上游解析也不用没验证过的 IP
      rm -f "$PREF_DIR/$route.hosts" 2>/dev/null
      merge_hosts
      write_state "$route" "$target" "no_valid" "" "${hard:-$soft}" "${n4:-0}" 0 "${pool_n}"
      if [ -n "$hard" ]; then
        log "$route: 全部候选被拒绝（$(printf '%s' "$hard" | awk '{print $2}' | sort -u | tr '\n' ' ')），已撤下该路 hosts，域名回退上游解析"
        notify "warn" "$route 路无可用 IP" "全部候选被 HTTPS 校验拒绝（1034/证书/5xx），已撤下该路 hosts，回退上游解析，不使用任何坏 IP。"
      else
        log "$route: ${n4:-0} 个候选全部超时/连不上，没有验证通过的 IP，已撤下该路 hosts（不做未验证降级），域名回退上游解析，下一轮继续找"
      fi
      log "$route: 已进入退避（$(retry_fail "$route" | awk "{print \"第 \"\$1\" 次失败\"}")），期间不再空跑"
      return 3
    fi
  fi

  # ---- 第五步：回写池统计（通过的加分，超时的记失败）----
  # 备胎本轮没验证过，不参与加减分（否则「没测过」会被记成「通过」）
  {
    printf '%s\n' "$best4"; printf '%s\n' "$best6"
  } | awk 'NF && $3!="backup"{print $1, "ok"}' | sub_cli bump-many "$route" >/dev/null
  if [ -n "$soft" ]; then
    printf '%s\n' "$soft" | awk 'NF{print $1, "fail"}' | sub_cli bump-many "$route" >/dev/null
  fi

  # 通过 HTTPS 校验的 IP 记进池（verify 来源，权重最高）
  { printf '%s\n' "$best4"; printf '%s\n' "$best6"; } \
    | awk 'NF && $3!="backup"{print $1, "verify"}' | sub_cli feed "$route" >/dev/null 2>&1

  retry_clear "$route"
  write_route "$route" "$target" "$best4" "$best6" || return 1
  write_state "$route" "$target" "$( [ "$downgrade" = "1" ] && echo degraded || echo ok )" \
              "$(printf '%s\n%s\n' "$best4" "$best6")" "$hard" "${n4:-0}" 0 "${pool_n}"
  log "$route: 选中 $total 个 -> $target：$( { printf '%s\n' "$best4"; printf '%s\n' "$best6"; } | awk 'NF {printf "%s(%s) ", $1, ($3=="backup" ? "备胎" : $2"ms")}' )"
  [ "$downgrade" = "1" ] && return 2
  return 0
}
