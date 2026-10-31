#!/bin/bash
# ghcr.io 路优选：目标 ghcr.io
#
# 本路只管 ghcr.io（认证 + manifest）。pkg-containers/raw/objects/gist/
# avatars 这些数据面域名自 2026-10-31 起统一由 github 路的 fastly_pin_refresh
# 接管（每域名专属探测路径+判定码独立选 IP）。以前本路也映射它们，用的候选
# 段（151.101.x.217）与 github 路（151.101.x.133）不同，两路在 all.hosts 里
# 同域名竞争「IP 数多的行胜出」，老 bug 时代的坏 IP 行（20.205.243.166 等）
# 就是这么一直赢下去的。
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
# 验「Docker registry 真实能力」而不是「首页任意响应」：真 ghcr 对 /v2/ 返回
# 401 且 body 含 UNAUTHORIZED（Bearer token 缺失的标准应答）。证书对 + 这个
# 应答 = 这个 IP 确实承载 ghcr registry，docker pull 能走通。光靠 401 状态码
# 太松（任何返回 401 的站点都算过），收紧到 registry 专属报文体。
export PREF_PROBE_PATH='/v2/'
export PREF_PROBE_EXPECT='UNAUTHORIZED'
# 数据面域名已移交 github 路（fastly_pin_refresh），本路不再写 extra 行
export PREF_EXTRA_LINES="$PREF_DIR/.ghcr.extra"
: > "$PREF_EXTRA_LINES"

run_route "ghcr" "/app/config/seeds/ghcr.txt" 443
exit $?
