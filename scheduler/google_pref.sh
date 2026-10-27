#!/bin/bash
# Google 搜索路优选：目标 www.google.com
set -u

# 这一路「什么算能用」= 真能打开 Google 搜索页，而不是「HTTP 通就算」。
# 用首页 + 标题判定，理由同翻译路：/search?q= 虽然也能用，但它有配额
# （探测频繁会被 429），首页判定不消耗配额，也不会把好节点误判成坏节点。
# 标题一律以 Google 开头（英文是 Google Search，中文是 Google 搜索），
# 所以用 <title>Google 判断，语言无关。
export PREF_PROBE_TARGET=www.google.com
export PREF_PROBE_PATH='/'
export PREF_PROBE_EXPECT='<title>Google'

# 香港站、裸域和主站是同一批前端节点，一起映射；否则 google.com.hk / google.com
# 仍会拿到上游的污染结果（实测上游返回的是 Facebook 段 69.171.x 这种脏答案）。
export PREF_EXTRA_DOMAINS="www.google.com.hk google.com"

source /app/scheduler/common.sh
acquire_lock || exit 1
run_route "google" "/app/config/seeds/google.txt" 443
