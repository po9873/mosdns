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
# 从 JSON 里抠一个整数字段（不依赖 jq）
jget() {
  printf '%s' "$1" | grep -oE "\"$2\": *[0-9]+" | head -1 | grep -oE '[0-9]+'
}

maybe_pull_sources() {
  local out okn tot lout cn gn
  local LOGF="${PREF_LOG:-$DATA_DIR/pref.log}"

  # ---- 1) 定时拉取启用中的源（把新 IP 收进候选池）----
  out=$(python3 "$SUB_PY" pull-if-due 2>>"$LOGF")
  case "$out" in
    *'"skipped": true'*) ;;
    *)
      okn=$(jget "$out" succeeded)
      tot=$(jget "$out" sources)
      log "IP 源定时拉取：成功 ${okn:-0} / 共 ${tot:-0} 个源"
      python3 "$SUB_PY" prune >>"$LOGF" 2>&1 || true
      ;;
  esac

  # ---- 2) 源体检：官方 + 第三方全部复检一遍 ----
  # 官方源失败只标红（它是权威定义，多半是临时断网）；
  # 第三方源连续失败会自动停用，避免每轮白等超时。
  out=$(python3 "$SUB_PY" health 2>>"$LOGF")
  case "$out" in
    *'"skipped": true'*) ;;
    *)
      cn=$(jget "$out" checked)
      gn=$(jget "$out" good)
      tot=$(jget "$out" bad)
      lout=$(jget "$out" auto_disabled)
      if [ -n "$cn" ] && [ "$cn" != "0" ]; then
        log "源体检完成：检查 ${cn} 个，可用 ${gn:-0} 个，失效 ${tot:-0} 个，自动停用 ${lout:-0} 个"
        if [ "${tot:-0}" != "0" ]; then
          notify "warn" "IP 源体检有失效" \
            "共检查 ${cn} 个源，可用 ${gn:-0} 个，失效 ${tot} 个（连续失败 3 次的第三方源已自动停用）。控制台「源」页可查看详情并重新启用。"
        fi
      fi
      ;;
  esac

  # ---- 3) 扫描还没测过的源（默认关闭，可在「源」页打开）----
  out=$(python3 "$SUB_PY" discover 2>>"$LOGF")
  case "$out" in
    *'"skipped": true'*) return 0 ;;
  esac
  cn=$(jget "$out" checked)
  gn=$(jget "$out" good)
  case "${cn:-0}" in
    0|"") return 0 ;;
  esac
  log "源扫描完成：检查 ${cn} 个，可用 ${gn:-0} 个"
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
      health) python3 "$SUB_PY" health --force ;;
      prune)  python3 "$SUB_PY" prune ;;
      test)   python3 "$SUB_PY" test "$3" ;;
      *)      echo "用法: $0 sources {pull|sync|discover|health|prune|test KEY}" ;;
    esac
    ;;
  reload) reload_mosdns ;;
  *)
    echo "用法: $0 {daemon|once [route|all]|lists [name|all]|sources {pull|sync|discover|prune|test KEY}|reload}"
    exit 1
    ;;
esac
