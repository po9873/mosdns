#!/bin/bash
# GitHub 路优选：目标 github.com
set -u
source /app/scheduler/common.sh
acquire_lock || exit 1
run_route "github" "/app/config/seeds/github.txt" 443
