#!/bin/bash
# ghcr.io 路优选：目标 ghcr.io
set -u
source /app/scheduler/common.sh
acquire_lock || exit 1
run_route "ghcr" "/app/config/seeds/ghcr.txt" 443
