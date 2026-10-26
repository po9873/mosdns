#!/bin/bash
# Google 路优选：目标 www.google.com
set -u
source /app/scheduler/common.sh
acquire_lock || exit 1
run_route "google" "/app/config/seeds/google.txt" 443
