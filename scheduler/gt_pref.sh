#!/bin/bash
# Google Translate 路优选：目标 translate.google.com
set -u
source /app/scheduler/common.sh
acquire_lock || exit 1
run_route "gt" "/app/config/seeds/ghtranslate.txt" 443
