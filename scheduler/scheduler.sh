#!/bin/bash
# ============================================================
# 主调度：daemon 模式按间隔轮询优选任务（串行，靠全局锁保证互斥）；
#         once 模式供 UI 手动触发单路或全部；
#         lists 供 UI 手动更新分流清单；reload 让 mosdns 重载配置。
# ============================================================
set -u
source /app/scheduler/common.sh

ROUTES="cf google gt github ghcr tmdb imdb"
LISTS_PY="/app/scheduler/lib/lists.py"
SUB_PY="/app/scheduler/lib/subs.py"
DOH_WATCH="/app/scheduler/lib/doh_watch.py"

# 四份清单（国内 IP 段 / 国内域名 / 国外域名 / CDN 网段）按「周期 + 时刻」自动拉一遍。
# 计划存在 settings.json（list_upd_enabled / list_upd_cycle / list_upd_hour），
# 只有内容真的变了才重载引擎（没变就不重启，DNS 零中断）。
maybe_update_lists() {
  local out nchk nchg
  local LOGF="${PREF_LOG:-$DATA_DIR/pref.log}"
  out=$(python3 "$LISTS_PY" auto 2>>"$LOGF")
  nchk=$(printf '%s' "$out" | grep -o '"label"' | wc -l | tr -d ' ')
  nchg=$(jget "$out" changed)
  if [ -n "${nchg:-}" ] && [ "$nchg" != "0" ]; then
    log "分流清单自动更新：检查 ${nchk:-0} 份，内容有变化 ${nchg} 份"
    case "$(setting auto_reload)" in
      false|False|0) log "已关闭自动重载，新清单将在下次重启容器后生效" ;;
      *) reload_mosdns && log "新清单已生效（引擎已重载）" ;;
    esac
  elif [ "${nchk:-0}" != "0" ]; then
    log "分流清单自动检查：${nchk} 份已是最新，内容没变不重载"
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

# 上游 DoH 定时扫描：候选池里有没有新变得可用的、在用的有没有已经死的。
# 限频在 python 里（settings.doh_scan_min，默认 60 分钟），这里每次循环都调一下，
# 没到点会立刻返回；真正的重活由 watchdog 的常驻线程承担。
maybe_scan_doh() {
  # stdout 是给界面看的 JSON，这里丢掉；python 自己的日志走 stderr 进 pref.log
  python3 "$DOH_WATCH" scan >/dev/null 2>>"${PREF_LOG:-$DATA_DIR/pref.log}" || true
}

# 各路串行跑一遍，全部跑完只判断一次是否需要重载引擎
run_all() {
  local r en fp ok=0 bad=0 names="" rc
  fp=$(file_sig "$PREF_DIR/all.hosts")
  for r in $ROUTES; do
    en=$(setting "routes.$r")
    # 只有明确关掉才跳过：老版本的 settings.json 里没有后加的几路键，
    # 空值当成「没配置过」= 开着，否则新加的路永远跑不起来。
    case "$en" in
      false|False|0) log "跳过 $r（已在配置中关闭）"; continue ;;
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
  # 全部跑完，只在这里判断一次是否需要重载
  reload_if_changed "$fp"
  # 推送正文带上每路当前生效的域名和 IP：只报「几路成功」看不出到底用了什么
  local brief
  brief=$(route_brief)
  notify "round" "优选完成" "成功 ${ok} 路（${names# }），失败 ${bad} 路。${brief:+$'\n'}${brief}"
}

# UI 的「立即测试」走这里：once 单路 或 once all
once_mode() {
  local which="${1:-all}" fp
  # 「立即测试」：忽略失败退避，立即执行
  export PREF_FORCE=1
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

# UI 的「更新分流清单」走这里
lists_mode() {
  local name="${1:-all}"
  python3 "$LISTS_PY" update "$name" || true
  reload_mosdns
}

daemon_mode() {
  local interval
  log "调度器启动，各路串行"
  maybe_update_lists
  maybe_pull_sources
  while true; do
    # 每轮重新读一次设置：界面上改了间隔/开关，不用重启容器就生效
    interval=$(setting interval_min)
    if [ -z "$interval" ] || [ "$interval" -lt 1 ] 2>/dev/null; then
      interval=60
    fi
    # 清单更新跟优选开关无关：优选暂停了，四份清单也照常自动更新
    maybe_update_lists
    if [ "$(setting pref_enabled)" = "false" ]; then
      maybe_scan_doh
      log "定时优选已关闭，本轮跳过（每分钟检查一次开关）"
      sleep 60
      continue
    fi
    run_all
    maybe_pull_sources
    maybe_scan_doh
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
  doh)
    case "${2:-scan}" in
      scan) python3 "$DOH_WATCH" scan ${3:+--force} ;;
      status) python3 "$DOH_WATCH" status ;;
      *) echo "用法: $0 doh {scan [--force]|status}" ;;
    esac
    ;;
  *)
    echo "用法: $0 {daemon|once [route|all]|lists [name|all]|sources {pull|sync|discover|prune|test KEY}|doh {scan|status}|reload}"
    exit 1
    ;;
esac
