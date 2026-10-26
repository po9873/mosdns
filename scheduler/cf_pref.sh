#!/bin/bash
# Cloudflare 路优选：目标 cloudflare.com，候选=实时解析 + 种子兜底 IP
set -u
source /app/scheduler/common.sh
acquire_lock || exit 1
run_route "cf" "/app/config/seeds/cloudflare.txt" 443
