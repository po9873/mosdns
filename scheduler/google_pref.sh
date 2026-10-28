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
# Gmail 同属 Google 前端：mail 是网页版，accounts 是登录，www.googleapis 是
# 网页端调用的接口。不一起映射的话搜索能开、登录/收发信仍走污染解析。
# 注：没有 www.google.com.hk —— 中转节点对它直接握手失败（同 IP 上 .com 正常 200，
# 说明是不支持这个 SNI 的节点，不是本地问题）。写进去每轮只会白探一遍。
# 除上面这些，网页版 Google / Gmail 还会拉这几个域名：clients6 是 Gmail 的接口，
# ogs 是右上角账号栏，apis 是 JS 接口，lh3~lh6.googleusercontent 是头像/附件/缩略图。
# 不映射的话：搜索页能出，登录后信箱一直转圈、附件和头像全是破图。
export PREF_EXTRA_DOMAINS="google.com gmail.com mail.google.com accounts.google.com www.googleapis.com myaccount.google.com drive.google.com docs.google.com calendar.google.com contacts.google.com photos.google.com keep.google.com maps.google.com play.google.com www.gstatic.com ssl.gstatic.com fonts.gstatic.com clients6.google.com ogs.google.com apis.google.com notifications.google.com lh3.googleusercontent.com lh4.googleusercontent.com lh5.googleusercontent.com lh6.googleusercontent.com mail-attachment.googleusercontent.com content-gmail.googleapis.com kidsmanagement-pa.clients6.google.com kidsmanagement-pa.googleapis.com people-pa.googleapis.com"

source /app/scheduler/common.sh
acquire_lock || exit 1
run_route "google" "/app/config/seeds/google.txt" 443
