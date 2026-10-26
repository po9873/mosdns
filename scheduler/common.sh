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
is_ip() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }

first_domain() {
  awk '!/^[[:space:]]*#/ && NF {print; exit}' "$1" 2>/dev/null
}

fallback_ips() {
  awk '!/^[[:space:]]*#/ && NF && $0 !~ /[a-zA-Z]/ {print}' "$1" 2>/dev/null
}

# 向本机 mosdns 查询 A 记录（不依赖系统 resolv.conf，避免自解析循环）
resolve_ips() {
  local domain="$1" port="${2:-${PREF_DNS_PORT:-53}}"
  python3 "$SELF_DIR/lib/dnsq.py" 127.0.0.1 "$port" "$domain" 2>/dev/null
}

# 并发 TCP 探测，返回延迟最小的 IP
probe_best() {
  local ips="$1" port="${2:-443}" conc="${3:-4}" tmo="${4:-3}"
  printf '%s\n' "$ips" \
    | python3 "$SELF_DIR/lib/probe.py" "$port" "$tmo" "$conc" 2>/dev/null \
    | head -1 | awk '{print $1}'
}

# ---------- 结果落盘 ----------
write_route() {
  local route="$1" domain="$2" ip="$3"
  echo "$ip $domain" > "$PREF_DIR/$route.hosts"
  merge_hosts
}

merge_hosts() {
  cat "$PREF_DIR"/*.hosts 2>/dev/null | awk 'NF' | sort -u > "$PREF_DIR/all.hosts.tmp"
  mv "$PREF_DIR/all.hosts.tmp" "$PREF_DIR/all.hosts"
}

# 让最新 hosts 生效：杀掉 mosdns，由 entrypoint supervisor 自动重启
reload_mosdns() {
  if [ -f "$MOSDNS_PID_FILE" ]; then
    local pid
    pid=$(cat "$MOSDNS_PID_FILE" 2>/dev/null)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null && log "已请求重启 mosdns 以加载最新 hosts"
    fi
  fi
}

# ---------- 单路优选主流程 ----------
run_route() {
  local route="$1" seed="$2" port="${3:-443}"
  local target ips best conc

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

  ips=$( { resolve_ips "$target"; fallback_ips "$seed"; } | awk 'NF' | sort -u )
  if [ -z "$ips" ]; then
    log "$route: 无候选 IP（DNS 未就绪且无兜底）"
    return 1
  fi

  log "$route: 目标 $target，候选 $(printf '%s\n' "$ips" | wc -l | tr -d ' ') 个，并发 $conc"
  best=$(probe_best "$ips" "$port" "$conc" 3)
  if [ -z "$best" ]; then
    log "$route: 探测全部失败"
    return 1
  fi

  write_route "$route" "$target" "$best"
  log "$route: 选中 $best -> $target"
  return 0
}
