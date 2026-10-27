#!/bin/bash
# Google Translate 路优选：目标 translate.google.com
set -u

# 这一路「什么算能用」= 真能打开 Google 翻译的页面，而不是「HTTP 通就算」。
# 踩过的两个坑（都已修在 https_probe 里 / 这里）：
#   1) 不能用 GET / 只看状态码：Google 前端节点对不认识的路径一律回 404，
#      状态码判断等于把所有真能用的节点全判死。
#   2) 不能拿 translate_a/single 接口做校验：无 key 的接口有配额，探测太频繁会被
#      429 限速，于是所有节点都「失败」——我们自己的探测把配额打爆了。
# 现在用首页 + 页面特征判定，不消耗接口配额。
# 注意：translate.google.com 首页是纯 JS 壳，整页没有 <title>（实测 70KB 内都没有），
# 所以这里不能用标题判断，用页面里必然出现的 translate 字样。
export PREF_PROBE_TARGET=translate.google.com
export PREF_PROBE_PATH='/'
export PREF_PROBE_EXPECT='translate'

# 网页端和接口端是同一批边缘节点，两个域名都要写进 hosts：
# 只映射 translate.google.com 的话，浏览器插件/接口走 translate.googleapis.com
# 时仍会去上游拿解析结果，那多半是污染值，等于白优选。
export PREF_EXTRA_DOMAINS="translate.googleapis.com"

source /app/scheduler/common.sh
acquire_lock || exit 1
run_route "gt" "/app/config/seeds/ghtranslate.txt" 443
