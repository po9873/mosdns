#!/bin/bash
# ============================================================
# 主调度：daemon 模式按间隔轮询五路（串行，靠全局锁保证互斥）；
#         once 模式供 UI 手动触发单路或全部；
#         lists 供 UI 手动更新分流清单；reload 让 mosdns 重载配置。
# ============================================================
set -u
source /app/scheduler/common.sh

ROUTES="cf google gt github ghcr"
LISTS_PY="/app/scheduler/lib/lists.py"

# 清单过期才更新（默认 24 小时）；更新成功才重载引擎
maybe_update_lists() {
  local on hrs
  on=$(setting list_auto_update)
  case "$on" in
    false|False|0) return 0 ;;
  esac
  hrs=$(setting list_update_hours)
  [ -z "$hrs" ] && hrs=24
  if python3 "$LISTS_PY" auto "$hrs" >>"${PREF_LOG:-$DATA_DIR/pref.log}" 2>&1; then
    log "分流清单已更新，将在本轮结束时统一重载"
    : > "$DATA_DIR/.lists_dirty"
  fi
}

run_all() {
  local r en fp
  fp=$(file_sig "$PREF_DIR/all.hosts")
  for r in $ROUTES; do
    en=$(setting "routes.$r")
    case "$en" in
      true|True|1) ;;
      *) log "跳过 $r（已在配置中关闭）"; continue ;;
    esac
    log "== 开始 $r 路 =="
    "/app/scheduler/${r}_pref.sh" || log "$r 路未选出结果"
  done
  # 五路全部跑完，只在这里判断一次是否需要重载
  reload_if_changed "$fp"
}

once_mode() {
  local which="${1:-all}" fp
  if [ "$which" = "all" ]; then
    run_all
  else
    case " $ROUTES " in
      *" $which "*) ;;
      *) echo "未知路: $which"; exit 1 ;;
    esac
    fp=$(file_sig "$PREF_DIR/all.hosts")
    "/app/scheduler/${which}_pref.sh" || exit 1
    reload_if_changed "$fp"
  fi
}

lists_mode() {
  local name="${1:-all}"
  python3 "$LISTS_PY" update "$name" || true
  reload_mosdns
}

daemon_mode() {
  local interval
  interval=$(setting interval_min)
  if [ -z "$interval" ] || [ "$interval" -lt 1 ] 2>/dev/null; then
    interval=60
  fi
  log "调度器启动，间隔 ${interval} 分钟，五路串行"
  maybe_update_lists
  while true; do
    run_all
    maybe_update_lists
    log "本轮完成，${interval} 分钟后再次执行"
    sleep $(( interval * 60 ))
  done
}

case "${1:-daemon}" in
  daemon) daemon_mode ;;
  once) once_mode "${2:-all}" ;;
  lists) lists_mode "${2:-all}" ;;
  reload) reload_mosdns ;;
  *)
    echo "用法: $0 {daemon|once [route|all]|lists [name|all]|reload}"
    exit 1
    ;;
esac
