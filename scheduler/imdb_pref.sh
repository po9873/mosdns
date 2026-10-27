#!/bin/bash
# IMDb 路优选：目标 www.imdb.com
#
# IMDb 也在 AWS CloudFront 上（和 TMDB 同一张网），所以候选同样来自 AWS 官方
# ip-ranges.json 的 CLOUDFRONT 段。
#
# 判定为什么只看证书（expect 留空）：
#   www.imdb.com 对非浏览器 UA 回 202 + 反爬挑战页，状态码和正文都不稳定；
#   而 CloudFront 对不认识域名的请求在 TLS 阶段就用默认证书应答，我们校验证书
#   就会失败。所以「证书能过 = 这个地址确实承载 IMDb 这个 distribution」，
#   有 HTTP 响应就算可用，不用拿正文赌运气。
#
# 顺带映射 m.media-amazon.com：IMDb 的海报、头像都放在这个域名上，
# 不映射的话页面能开、图全裂。
set -u
source /app/scheduler/common.sh
acquire_lock || exit 1

export PREF_PROBE_TARGET=www.imdb.com
export PREF_PROBE_PATH='/'
export PREF_PROBE_EXPECT=''

export PREF_EXTRA_DOMAINS="m.media-amazon.com"

run_route "imdb" "/app/config/seeds/imdb.txt" 443
