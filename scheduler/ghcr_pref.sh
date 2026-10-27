#!/bin/bash
# ghcr.io 路优选：目标 ghcr.io
#
# 这一路有个特殊性：docker pull 和 GitHub 的数据下载实际走另一个域族群
#   1) ghcr.io                          认证 + manifest（GitHub 自己的入口）
#   2) 185.199.108~111（Fastly）        pkg-containers / raw / objects 三个域名
# 只映射 ghcr.io 的话，docker pull 会卡在拉层那一步（一直转圈、最后超时）。
# 两者不是同一批节点，必须各用各的 IP，所以 Fastly 那组单独走 PREF_EXTRA_LINES。
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

# 这三个域名才是 GitHub 的「数据面」，都挂在 Fastly 的 185.199.108~111 段：
#   pkg-containers.githubusercontent.com  docker pull 拉镜像层
#   raw.githubusercontent.com             MoviePilot 装插件、拉站点索引
#   objects.githubusercontent.com         Release / 大文件下载
# github.com 那批（20.27.x / 172.182.x）不认这三个域名：实测 raw 直接超时，
# 140.82.112.33 回的是 *.registry.github.com 证书。所以不能靠 github 路的 IP，
# 必须各自解析、各自证书校验，通过了才写。
for dom in pkg-containers.githubusercontent.com raw.githubusercontent.com objects.githubusercontent.com \
           gist.githubusercontent.com avatars.githubusercontent.com; do
  ips=$(resolve_ips "$dom" "" A)
  ok=""
  if [ -n "$ips" ]; then
    ok=$(printf '%s\n' "$ips" | python3 "$SELF_DIR/lib/https_probe.py" "$dom" 443 5 4 1 / 2>/dev/null | awk '$2=="ok"{print $1}')
  fi
  if [ -n "$ok" ]; then
    printf '%s %s\n' "$dom" "$(printf '%s\n' "$ok" | tr '\n' ' ')" >> "$PREF_EXTRA_LINES"
    log "ghcr: $dom -> $(printf '%s\n' "$ok" | tr '\n' ' ')"
  else
    # Fastly 这几个地址经常「这轮抽风、下轮就好」，一失败就把已能用的那行撤掉，
    # docker pull 会卡在拉层、MP 会装不上插件。所以沿用上一轮 hosts 里的 IP。
    keep=$(awk -v d="$dom" '$1==d{$1=""; sub(/^[ \t]+/,""); print; exit}' "$PREF_DIR/ghcr.hosts" 2>/dev/null)
    if [ -n "$keep" ]; then
      printf '%s %s\n' "$dom" "$keep" >> "$PREF_EXTRA_LINES"
      log "ghcr: $dom 本轮没验到新的，继续用上一轮的 $keep"
    else
      log "ghcr: $dom 没有 IP 通过校验，本次不写（保持上一轮）"
    fi
  fi
done

run_route "ghcr" "/app/config/seeds/ghcr.txt" 443
rc=$?

# 稳定模式（当前 IP 能开且不慢）不会重写 hosts，那样镜像层域名这一行就永远进不去，
# 结果就是「ghcr.io 能解析、docker pull 还是卡在拉层」。这里单独补一次：
# 缺就追加 + 重新合并，引擎重载交给调用方（scheduler 一轮跑完统一判断）。
if [ -s "$PREF_EXTRA_LINES" ] && [ -s "$PREF_DIR/ghcr.hosts" ]; then
  added=""
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    d=${line%% *}
    grep -q "^$d " "$PREF_DIR/ghcr.hosts" || { printf '%s\n' "$line" >> "$PREF_DIR/ghcr.hosts"; added=1; }
  done < "$PREF_EXTRA_LINES"
  if [ -n "$added" ]; then
    merge_hosts
    log "ghcr: 补上 185.199 段的域名映射（docker pull 拉层、MP 装插件要用）"
  fi
fi
exit $rc
