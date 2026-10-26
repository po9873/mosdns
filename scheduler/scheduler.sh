#!/bin/bash
# ============================================================
# 主调度：daemon 模式按间隔轮询五路（串行，靠全局锁保证互斥）；
#         once 模式供 UI 手动触发单路或全部。
# ============================================================
set -u
source /app/scheduler/common.sh

ROUTES="cf google gt github ghcr"

run_all() {
  local r en
  for r in $ROUTES; do
    en=$(setting "routes.$r")
    case "$en" in
      true|True|1) ;;
      *) log "跳过 $r（已在配置中关闭）"; continue ;;
    esac
    log "== 开始 $r 路 =="
    "/app/scheduler/${r}_pref.sh" || log "$r 路未选出结果"
  done
  reload_mosdns
}

once_mode() {
  local which="${1:-all}"
  if [ "$which" = "all" ]; then
    run_all
  else
    case " $ROUTES " in
      *" $which "*) ;;
      *) echo "未知路: $which"; exit 1 ;;
    esac
    "/app/scheduler/${which}_pref.sh" || exit 1
    reload_mosdns
  fi
}

daemon_mode() {
  local interval
  interval=$(setting interval_min)
  if [ -z "$interval" ] || [ "$interval" -lt 1 ] 2>/dev/null; then
    interval=60
  fi
  log "调度器启动，间隔 ${interval} 分钟，五路串行"
  while true; do
    run_all
    log "本轮完成，${interval} 分钟后再次执行"
    sleep $(( interval * 60 ))
  done
}

case "${1:-daemon}" in
  daemon) daemon_mode ;;
  once) once_mode "${2:-all}" ;;
  *)
    echo "用法: $0 {daemon|once [route|all]}"
    exit 1
    ;;
esac
