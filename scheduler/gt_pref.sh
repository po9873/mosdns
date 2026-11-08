#!/bin/bash
# Google 翻译路优选：目标 translate.google.com / translate.googleapis.com
#
# 关键原则：翻译「能不能用」不在网页壳，而在翻译后台接口。早先只验「首页含
# translate 字样」，把一批「只代理网页壳、后台翻译接口 403/404」的半吊子反代
# 收了进去——页面能打开、翻译做不出来（用户原话：假的你加载进去干嘛）。
#
# 现在两层保险：
#   ① 主优选改用强判定：探针目标直接指向翻译接口 translate.googleapis.com，
#      必须真翻出译文（响应含原文 hello）才算 ok，半吊子 403/404 直接出局。
#   ② 翻译路由各域（接口端 / Chrome 翻译接口 / 静态资源域）由 gt_pin_refresh.py
#      独立强校验后写进 .gt.extra，经 PREF_EXTRA_LINES 注入；只有「真能翻」的 IP
#      才会被写进任何翻译域，杜绝假可用。
# 两路结果合并进 gt.hosts，稳定模式同样用强判定复核（已选 IP 若不再能翻会重探）。
set -u

# 主优选探针：直击翻译接口，必须真翻出译文（响应里回显原文 hello）
#
# client 必须是 dict-chrome-ex —— Chrome 浏览器翻译/划词翻译真实使用的接口。
# 同一个 IP 在 HTTP/2 下：client=gtx → 429「Sorry」、client=webapp → 403、
# 只有 client=dict-chrome-ex → 200 真译文。拿错 client 会把自己骗过去。
export PREF_PROBE_TARGET=translate.googleapis.com
export PREF_PROBE_PATH='/translate_a/single?client=dict-chrome-ex&sl=en&tl=zh-CN&dt=t&q=hello'
export PREF_PROBE_EXPECT='hello'

# 翻译各域的「真能力」由 gt_pin_refresh 强校验后注入；主优选不再靠弱判定写域名
export PREF_EXTRA_DOMAINS=""

source /app/scheduler/common.sh
acquire_lock || exit 1

# CloudflareSpeedTest：101 内按 translate.googleapis.com 实测排序候选；
# 工具只挑 IP，写不写 hosts 仍由 101 严格复核 + 粘滞守卫「能用不换」决定。
# GoogleTranslateIpCheck 的社区 IP 清单就是这里喂给工具的候选来源。
python3 "$SELF_DIR/lib/cfst_pref.py" gt 2>>"${PREF_LOG:-$DATA_DIR/pref.log}" >/dev/null || true
gt_seed="$DATA_DIR/cfst_gt_seed.txt"
[ -s "$gt_seed" ] || gt_seed="/app/config/seeds/ghtranslate.txt"

pref_log="${PREF_LOG:-$DATA_DIR/pref.log}"
gt_extra="$PREF_DIR/.gt.extra"

# 粘滞守卫：主用 IP 全能用就整路沿用，连 .gt.extra 都不重跑
if [ "${PREF_RESELECT:-0}" != "1" ] && \
   python3 "$SELF_DIR/lib/sticky_guard.py" gt 2>>"$pref_log" >/dev/null; then
  log "gt: 粘滞守卫，主用 IP 全部能用 → 沿用不换（不重跑 gt_pin_refresh）"
  exit 0
fi

# 翻译路真能力验证（接口能翻出译文才算数），结果供主优选合并注入
if ! python3 /app/scheduler/lib/gt_pin_refresh.py "$gt_extra" 2>>"$pref_log" \
   || [ ! -s "$gt_extra" ]; then
  [ -s "$gt_extra" ] \
    && log "gt: gt_pin_refresh 本轮未产出新结果，沿用旧 .gt.extra" \
    || log "gt: 本轮未能选出任何真能翻的 IP，翻译将回退上游解析（不写假 IP）"
fi
export PREF_EXTRA_LINES="$gt_extra"

run_route "gt" "$gt_seed" 443

# 兜底：若主优选因整层不通撤下了 gt.hosts，但 .gt.extra 有强校验过的可用 IP，
# 仍把它写进去，避免「明明有真能翻的 IP 却整路回退」
if [ ! -s "$PREF_DIR/gt.hosts" ] && [ -s "$gt_extra" ]; then
  cp "$gt_extra" "$PREF_DIR/gt.hosts"
  merge_hosts
  log "gt: 主优选未选出，已用强校验结果兜底写入 gt.hosts"
fi
