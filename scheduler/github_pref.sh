#!/bin/bash
# GitHub 路优选：目标 github.com
#
# 关于 v6：GitHub 公布的 v6 段（2a0a:a440::/32 这一批）从当地不可路由。
# 实测按每等份中点取 18 个地址，全部 timeout / fail；而同一台机器上
# CloudFront 的 2600:9000 段是能过校验的，所以不是机器没 v6，是这几段不通。
# 既然选不出来，就别每轮白探十几个、每个等 6 秒。哪天通了把这行删掉即可。
export PREF_NO_V6=1

set -u
source /app/scheduler/common.sh
acquire_lock || exit 1
run_route "github" "/app/config/seeds/github.txt" 443
