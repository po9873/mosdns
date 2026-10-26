#!/bin/bash
# ============================================================
# 公共函数库（被 entrypoint 与五路优选脚本 source）
# 设计原则：运行时零外网下载；候选 IP 靠向 mosdns 实时查询，
#           延迟靠纯 TCP 直连探测；不依赖任何外部二进制或代理。
# ============================================================

DATA_DIR="${PREF_DATA_DIR:-/data}"
PREF_DIR="$DATA_DIR/prefs"
SETTINGS_FILE="$DATA_DIR/settings.json"
MOSDNS_PID_FILE="$DATA_DIR/mosdns.pid"
LOCK_DIR="$DATA_DIR/.pref.lock"
SELF_DIR="/app/scheduler"

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
acquire_lock() {
  local waited=0
  while ! mkdir "$LOCK_DIR" 2>/dev/null; do
    sleep 1
    waited=$((waited + 1))
    if [ "$waited" -ge 1800 ]; then
      log "等待优选锁超时（30 分钟），放弃"
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

fallback_ips() {
  awk '!/^[[:space:]]*#/ && NF && $0 !~ /[a-zA-Z]/ {print}' "$1" 2>/dev/null
}

# 向本机 mosdns 查询（不依赖系统 resolv.conf，避免自解析循环）
# $3 = A / AAAA / ALL
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

# 兼容旧调用：只要第一个 IP
probe_best() {
  probe_top "$1" "${2:-443}" "${3:-4}" "${4:-3}" 1 | awk 'NR==1{print $1}'
}

# ---------- 结果落盘 ----------
# mosdns hosts 文件格式：每行「域名 ip1 ip2 ...」，域名必须在第一位，
# 后面可跟任意多个 IP（v4/v6 可混在同一行，引擎会自动按查询类型分开应答）。
# 同时写一个 <route>.meta 记录延迟，供控制台展示。
write_route() {
  local route="$1" domain="$2"
  shift 2
  local pairs ips
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
  } > "$PREF_DIR/$route.hosts"
  printf '%s\n' "$pairs" > "$PREF_DIR/$route.meta"
  merge_hosts
}
merge_hosts() {
  cat "$PREF_DIR"/*.hosts 2>/dev/null | awk 'NF' | sort -u > "$PREF_DIR/all.hosts.tmp"
  mv "$PREF_DIR/all.hosts.tmp" "$PREF_DIR/all.hosts"
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

# 文件指纹（用于判断这轮优选结果是否真的变了）
file_sig() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" 2>/dev/null | awk '{print $1}'
  else
    cksum "$1" 2>/dev/null | awk '{print $1"-"$2}'
  fi
}

# 只有内容真的变化（或清单被更新）才重启；否则一次都不重启。
# 一轮五路跑完只调用一次，绝不会"每路重启一次"。
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

# ---------- 消息推送（企业微信 / 钉钉 / 飞书 机器人）----------
# 事件类型：round(每轮完成) / warn(失败或降级) / login(登录提醒) / daily(日报)
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

# ---------- 单路优选主流程 ----------
# 每路保留 top_n 个最优 IP（v4/v6 各自排），一次写入 hosts
run_route() {
  local route="$1" seed="$2" port="${3:-443}"
  local target conc top_n want6 v4 v6 best4 best6 total

  target=$(first_domain "$seed")
  if [ -z "$target" ]; then
    log "$route: 种子文件无目标域名"
    return 1
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

  case "$(setting ipv6)" in
    false|False|0) want6=0 ;;
    *) want6=1 ;;
  esac

  v4=$( { resolve_ips "$target" "" A; fallback_ips "$seed"; } \
        | awk 'NF' | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' | sort -u )
  v6=""
  if [ "$want6" = "1" ]; then
    v6=$( { resolve_ips "$target" "" AAAA; fallback_ips "$seed"; } \
          | awk 'NF' | grep ':' | sort -u )
  fi

  if [ -z "$v4" ] && [ -z "$v6" ]; then
    log "$route: 无候选 IP（DNS 未就绪且无兜底）"
    return 1
  fi

  log "$route: 目标 $target，候选 v4 $(printf '%s\n' "$v4" | awk 'NF' | wc -l | tr -d ' ') 个 / v6 $(printf '%s\n' "$v6" | awk 'NF' | wc -l | tr -d ' ') 个，并发 $conc，每族保留 $top_n 个"

  # 第一步：TCP 粗筛（快，取 2 倍名额）
  local cand4 cand6 cand vres verified bad downgrade
  cand4=$(probe_top "$v4" "$port" "$conc" 3 $((top_n * 2)))
  cand6=$(probe_top "$v6" "$port" "$conc" 3 $((top_n * 2)))
  cand=$( { printf '%s\n' "$cand4"; printf '%s\n' "$cand6"; } | awk 'NF' )

  if [ -z "$cand" ]; then
    log "$route: TCP 探测全部失败"
    return 1
  fi

  # 第二步：真实 HTTPS 校验（SNI/Host = 目标域名），揪出 1034 / 证书不符 / 5xx
  case "$(setting verify_https)" in
    false|False|0) verified=""; bad="" ;;
    *)
      vres=$(printf '%s\n' "$cand" | python3 "$SELF_DIR/lib/https_probe.py" "$target" "$port" 6 2>/dev/null)
      verified=$(printf '%s\n' "$vres" | awk '$2=="ok"{print $1, $3, "ok"}' | sort -k2 -n)
      bad=$(printf '%s\n' "$vres" | awk '$2!="ok"{printf "%s(%s) ", $1, $2}')
      ;;
  esac

  downgrade=0
  if [ -n "$verified" ]; then
    best4=$(printf '%s\n' "$verified" | awk '!/:/' | head -n "$top_n")
    best6=$(printf '%s\n' "$verified" | awk '/:/' | head -n "$top_n")
  fi

  total=$( { printf '%s\n' "$best4"; printf '%s\n' "$best6"; } | awk 'NF' | wc -l | tr -d ' ')
  if [ "$total" = "0" ]; then
    # 全都没通过校验：降级用 TCP 结果，但标记 unverified，控制台会显红
    downgrade=1
    best4=$(printf '%s\n' "$cand4" | awk 'NF{print $1, $2, "unverified"}' | head -n "$top_n")
    best6=$(printf '%s\n' "$cand6" | awk 'NF{print $1, $2, "unverified"}' | head -n "$top_n")
    total=$( { printf '%s\n' "$best4"; printf '%s\n' "$best6"; } | awk 'NF' | wc -l | tr -d ' ')
    [ "$total" = "0" ] && { log "$route: 探测全部失败"; return 1; }
    log "$route: 警告：候选均未通过 HTTPS 校验（${bad:-未知}），降级使用 TCP 最优结果"
    notify "warn" "$route 路优选降级" "所有候选未通过 HTTPS 校验：${bad:-未知}，已降级使用 TCP 结果。"
  elif [ -n "$bad" ]; then
    log "$route: 已剔除 $(printf '%s\n' "$bad" | wc -w | tr -d ' ') 个不可用 IP：$bad"
  fi

  write_route "$route" "$target" "$best4" "$best6" || return 1
  log "$route: 选中 $total 个 -> $target：$( { printf '%s\n' "$best4"; printf '%s\n' "$best6"; } | awk 'NF {printf "%s(%sms) ", $1, $2}' )"
  [ "$downgrade" = "1" ] && return 2
  return 0
}
