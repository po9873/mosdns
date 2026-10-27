#!/bin/bash
# ghcr.io 路优选：目标 ghcr.io
#
# 这一路有个特殊性：docker pull 实际经两个完全不同的域名
#   1) ghcr.io                          认证 + manifest（GitHub 自己的入口，20.27.x / 20.205.x）
#   2) pkg-containers.githubusercontent.com   镜像层数据（Fastly，185.199.108~111.154）
# 只映射 ghcr.io 的话，docker pull 会卡在拉层那一步（一直转圈、最后超时）。
# 两者不是同一批节点，必须各用各的 IP，所以镜像层域名单独成组（PREF_EXTRA_LINES）。
#
# 另一个现实：ghcr.io 的证书只部署在少数节点上。实测 768 个 20.27.x 地址里
# 只有 20.27.177.117 的证书覆盖 ghcr.io，其余全是 cert/超时——所以这一路
# 常出现「只选出 1 个」。common.sh 的保底备胎就是为这种情况加的：不足 3 个时
# 从池里历史验证通过的补，别让一路只剩一个 IP 没得换。
set -u
source /app/scheduler/common.sh
acquire_lock || exit 1

export PREF_PROBE_TARGET=ghcr.io
export PREF_PROBE_PATH='/'
export PREF_EXTRA_LINES="$PREF_DIR/.ghcr.extra"
: > "$PREF_EXTRA_LINES"

PKG_DOM=pkg-containers.githubusercontent.com
pkgs=$(resolve_ips "$PKG_DOM" "" A)
if [ -n "$pkgs" ]; then
  okp=$(printf '%s\n' "$pkgs" | python3 "$SELF_DIR/lib/https_probe.py" "$PKG_DOM" 443 5 4 1 / 2>/dev/null | awk '$2=="ok"{print $1}')
  if [ -n "$okp" ]; then
    printf '%s %s\n' "$PKG_DOM" "$(printf '%s\n' "$okp" | tr '\n' ' ')" >> "$PREF_EXTRA_LINES"
    log "ghcr: 镜像层域名 $PKG_DOM -> $(printf '%s\n' "$okp" | tr '\n' ' ')"
  else
    log "ghcr: 镜像层域名 $PKG_DOM 没有 IP 通过校验，本次不写（保持上一轮）"
  fi
fi

run_route "ghcr" "/app/config/seeds/ghcr.txt" 443
