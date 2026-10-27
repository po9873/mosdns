#!/bin/bash
# Cloudflare 路优选：目标 cloudflare.com，候选=实时解析 + 种子兜底 IP
set -u

# 只有这一路允许「实在没有验证通过的 IP 时，降级用 TCP 结果」：
# Cloudflare 的 TCP 通基本等于能开（除了 1034/1016 那几种会被直接判死），
# 首轮降级至少让站点能动。其它路端口开着不代表认这个域名，一律不降级。
export PREF_ALLOW_DOWNGRADE=1

source /app/scheduler/common.sh
acquire_lock || exit 1
run_route "cf" "/app/config/seeds/cloudflare.txt" 443
