#!/bin/bash
# Cloudflare 路优选：目标 cloudflare.com，候选=实时解析 + 种子兜底 IP
set -u

# 只有这一路允许「实在没有验证通过的 IP 时，降级用 TCP 结果」：
# Cloudflare 的 TCP 通基本等于能开（除了 1034/1016 那几种会被直接判死），
# 首轮降级至少让站点能动。其它路端口开着不代表认这个域名，一律不降级。
export PREF_ALLOW_DOWNGRADE=1

# 测速地址：cloudflare.com 首页是个 178 字节的跳转页，拿它算速度等于没算。
# Cloudflare 有官方测速端点，任何边缘 IP 都能服务（实测 v4/v6 都回 200，
# 一次约 270KB），直连优选出的 IP + SNI 使用该域名，测的就是这条链路。
export PREF_SPEED_URL='https://speed.cloudflare.com/__down?bytes=300000'

# 同一批边缘节点能顺带服务的域名：这些都是 Cloudflare 站点，用的是同一批
# anycast IP，跟 cloudflare.com 一起写进 hosts 没有额外成本。
#   theaudiodb.com  —— MoviePilot 音乐元数据（专辑/封面）
#   lrclib.net      —— MoviePilot 歌词源
#   anilist.co      —— 动画元数据；刮削走的是 graphql 那个域名，一起带上
# 写之前会逐个 IP 验一遍，验不过的域名这次就不映射，不会拖累主域名。
export PREF_EXTRA_DOMAINS="theaudiodb.com www.theaudiodb.com lrclib.net anilist.co graphql.anilist.co"

source /app/scheduler/common.sh
acquire_lock || exit 1
run_route "cf" "/app/config/seeds/cloudflare.txt" 443
