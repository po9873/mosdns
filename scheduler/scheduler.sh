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
SUB_PY="/app/scheduler/lib/subs.py"

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

# IP 源到点就拉（间隔由「源」页配置，默认 6 小时），并顺手清理失效 IP。
# 这就是「公开精选源要定时扫描」：不拉就会越来越少可用。
maybe_pull_sources() {
  local out okn tot cn gn
  out=$(python3 "$SUB_PY" pull-if-due 2>>"${PREF_LOG:-$DATA_DIR/pref.log}")
  case "$out" in
    *'"skipped": true'*) return 0 ;;
  esac
  okn=$(printf '%s' "$out" | sed -n 's/.*"succeeded": *\([0-9]*\).*/\1/p')
  tot=$(printf '%s' "$out" | sed -n 's/.*"sources": *\([0-9]*\).*/\1/p')
  if [ -n "$okn" ]; then
    log "IP 源定时拉取：成功 ${okn:-0} / 共 ${tot:-0} 个源"
  fi
  python3 "$SUB_PY" prune >>"${PREF_LOG:-$DATA_DIR/pref.log}" 2>&1 || true
  # 定时扫描新源（默认关闭，可在「源」页打开）
  out=$(python3 "$SUB_PY" discover 2>>"${PREF_LOG:-$DATA_DIR/pref.log}")
  case "$out" in
    *'"checked": 0'*|*'"skipped": true'*) return 0 ;;
  esac
  cn=$(printf '%s' "$out" | sed -n 's/.*"checked": *\([0-9]*\).*/\1/p')
  gn=$(printf '%s' "$out" | sed -n 's/.*"good": *\([0-9]*\).*/\1/p')
  log "源扫描完成：检查 ${cn:-0} 个，可用 ${gn:-0} 个"
}

run_all() {
  local r en fp ok=0 bad=0 names="" rc
  fp=$(file_sig "$PREF_DIR/all.hosts")
  for r in $ROUTES; do
    en=$(setting "routes.$r")
    case "$en" in
      true|True|1) ;;
      *) log "跳过 $r（已在配置中关闭）"; continue ;;
    esac
    log "== 开始 $r 路 =="
    "/app/scheduler/${r}_pref.sh"
    rc=$?
    if [ "$rc" -eq 0 ] || [ "$rc" -eq 2 ]; then
      ok=$((ok + 1))
      names="$names $r"
    else
      bad=$((bad + 1))
      if [ "$rc" -eq 3 ]; then
        log "$r 路：候选全部被校验拒绝，已撤下该路（不使用坏 IP）"
      else
        log "$r 路未选出结果"
      fi
    fi
  done
  # 五路全部跑完，只在这里判断一次是否需要重载
  reload_if_changed "$fp"
  notify "round" "五路优选完成" "成功 ${ok} 路（${names# }），失败 ${bad} 路。"
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
  maybe_pull_sources
  while true; do
    run_all
    maybe_update_lists
    maybe_pull_sources
    log "本轮完成，${interval} 分钟后再次执行"
    sleep $(( interval * 60 ))
  done
}

case "${1:-daemon}" in
  daemon) daemon_mode ;;
  once) once_mode "${2:-all}" ;;
  lists) lists_mode "${2:-all}" ;;
  sources)
    case "${2:-pull}" in
      pull)   python3 "$SUB_PY" pull --force ;;
      sync)   python3 "$SUB_PY" sync ;;
      disc*)  python3 "$SUB_PY" discover --force ;;
      prune)  python3 "$SUB_PY" prune ;;
      test)   python3 "$SUB_PY" test "$3" ;;
      *)      echo "用法: $0 sources {pull|sync|discover|prune|test KEY}" ;;
    esac
    ;;
  reload) reload_mosdns ;;
  *)
    echo "用法: $0 {daemon|once [route|all]|lists [name|all]|sources {pull|sync|discover|prune|test KEY}|reload}"
    exit 1
    ;;
esac
