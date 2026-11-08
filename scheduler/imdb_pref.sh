#!/bin/bash
# IMDb 路优选：目标 www.imdb.com
#
# IMDb 也在 AWS CloudFront 上（和 TMDB 同一张网），所以候选同样来自 AWS 官方
# ip-ranges.json 的 CLOUDFRONT 段。
#
# 判定为什么只看证书（expect 留空）：
#   www.imdb.com 对非浏览器 UA 回 202 + 反爬挑战页，状态码和正文都不稳定；
#   而 CloudFront 对不认识域名的请求在 TLS 阶段即用默认证书应答，证书校验
#   就会失败。所以「证书能过 = 这个地址确实承载 IMDb 这个 distribution」，
#   有 HTTP 响应就算可用，不用拿正文赌运气。
#
# 顺带映射 m.media-amazon.com：IMDb 的海报、头像都放在这个域名上，
# 不映射的话页面能开、图全裂。注意这个域名是**逐个 IP 单独校验**的
# （write_route 里做的）：实测有 IP 能服务 www.imdb.com 却对 m.media-amazon.com
# 回 421 Misdirected，照抄主域名的 IP 会让海报全裂。
set -u
source /app/scheduler/common.sh
acquire_lock || exit 1

# CloudflareSpeedTest：101 内按 www.imdb.com 实测排序候选；工具只挑 IP，
# 写不写 hosts 仍由 101 严格复核 + 粘滞守卫「能用不换」决定。
python3 "$SELF_DIR/lib/cfst_pref.py" imdb 2>>"${PREF_LOG:-$DATA_DIR/pref.log}" >/dev/null || true
imdb_seed="$DATA_DIR/cfst_imdb_seed.txt"
[ -s "$imdb_seed" ] || imdb_seed="/app/config/seeds/imdb.txt"

export PREF_PROBE_TARGET=www.imdb.com
export PREF_PROBE_PATH='/'
export PREF_PROBE_EXPECT=''

export PREF_EXTRA_DOMAINS="m.imdb.com s.media-imdb.com ia.media-imdb.com images-na.ssl-images-amazon.com m.media-amazon.com"

# 测速地址：www.imdb.com 只回 965 字节的反爬页，算不出带宽。
# 拿一张海报（约 270KB）测，走的是同一批 CloudFront 边缘。
export PREF_SPEED_URL='https://m.media-amazon.com/images/M/MV5BMDFkYTc0MGEtZmNhMC00ZDIzLWFmNTEtODM1ZmRlYWMwMWFmXkEyXkFqcGdeQXVyMTMxODk2OTU@._V1_.jpg'

run_route "imdb" "$imdb_seed" 443
