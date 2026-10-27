#!/bin/bash
# ghcr.io 路优选：目标 ghcr.io
#
# 这一路有个特殊性：docker pull 实际经两个完全不同的域名
#   1) ghcr.io                          认证 + manifest（GitHub 自己的入口）
#   2) pkg-containers.githubusercontent.com   镜像层数据（Fastly，185.199.108~111.154）
# 只映射 ghcr.io 的话，docker pull 会卡在拉层那一步（一直转圈、最后超时）。
# 两者不是同一批节点，必须各用各的 IP，所以镜像层域名单独成组（PREF_EXTRA_LINES）。
#
# 另一个现实：ghcr.io 的证书只部署在少数节点上。20.27.x 是 Azure 的网段
# （扫描 20.27.176~178 共 762 个地址，只有 20.27.177.117 认 ghcr.io）；
# GitHub 自己的 140.82.112.0/20 里也只有 .33/.34 这两个地址带 *.ghcr.io
# 证书（.3/.42 那些是 github.com）。所以候选清单很窄，种子文件里那 10 个
# 就是实测能用的全部，别指望扫描能扫出更多。common.sh 的保底备胎
# （keep_min，默认 3）就是为这种情况加的。
set -u
source /app/scheduler/common.sh
acquire_lock || exit 1

export PREF_PROBE_TARGET=ghcr.io
export PREF_PROBE_PATH='/'
export PREF_EXTRA_LINES="$PREF_DIR/.ghcr.extra"
: > "$PREF_EXTRA_LINES"

PKG_DOM=pkg-containers.githubusercontent.com
pkgs=$(resolve_ips "$PKG_DOM" "" A)
okp=""
if [ -n "$pkgs" ]; then
  okp=$(printf '%s\n' "$pkgs" | python3 "$SELF_DIR/lib/https_probe.py" "$PKG_DOM" 443 5 4 1 / 2>/dev/null | awk '$2=="ok"{print $1}')
fi
if [ -n "$okp" ]; then
  printf '%s %s\n' "$PKG_DOM" "$(printf '%s\n' "$okp" | tr '\n' ' ')" >> "$PREF_EXTRA_LINES"
  log "ghcr: 镜像层域名 $PKG_DOM -> $(printf '%s\n' "$okp" | tr '\n' ' ')"
else
  # 这一轮解析或校验没成功，别把已经能用的那行丢掉。Fastly 的这几个地址
  # 经常「这轮抽风、下轮就好」，一失败就当没有，hosts 里那行一撤，docker pull
  # 立刻卡在拉层（前面认证和 manifest 都好好的，就是层拉不下来，最难查）。
  # 所以：沿用上一轮 hosts 里已经写着的 IP，等下一轮再试新的。
  keep=$(awk -v d="$PKG_DOM" '$1==d{$1=""; sub(/^[ \t]+/,""); print; exit}' "$PREF_DIR/ghcr.hosts" 2>/dev/null)
  if [ -n "$keep" ]; then
    printf '%s %s\n' "$PKG_DOM" "$keep" >> "$PREF_EXTRA_LINES"
    log "ghcr: 镜像层域名本轮没验到新的，继续用上一轮的 $keep"
  else
    log "ghcr: 镜像层域名 $PKG_DOM 没有 IP 通过校验，本次不写（保持上一轮）"
  fi
fi

run_route "ghcr" "/app/config/seeds/ghcr.txt" 443
rc=$?

# 稳定模式（当前 IP 能开且不慢）不会重写 hosts，那样镜像层域名这一行就永远进不去，
# 结果就是「ghcr.io 能解析、docker pull 还是卡在拉层」。这里单独补一次：
# 缺就追加 + 重新合并，引擎重载交给调用方（scheduler 一轮跑完统一判断）。
if [ -s "$PREF_EXTRA_LINES" ] && [ -s "$PREF_DIR/ghcr.hosts" ]; then
  if ! grep -q "^pkg-containers" "$PREF_DIR/ghcr.hosts"; then
    awk 'NF' "$PREF_EXTRA_LINES" >> "$PREF_DIR/ghcr.hosts"
    merge_hosts
    log "ghcr: 补上镜像层域名映射（docker pull 拉镜像层要用）"
  fi
fi
exit $rc
