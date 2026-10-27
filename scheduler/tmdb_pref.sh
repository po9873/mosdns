#!/bin/bash
# TMDB 路优选：目标 www.themoviedb.org
#
# TMDB（The Movie Database）整站挂在 AWS CloudFront 上：网站、API、图片三个域名
# 背后是同一批 CloudFront 边缘节点，所以一路优选、三个域名共用一批 IP。
#
# 判定为什么「只看证书、不看正文」：
#   www.themoviedb.org 根路径回 403 + Cloudflare 挑战页（"Just a moment..."），
#   状态码看着像挂了，其实浏览器能过——不能拿 403 判死。
#   那能不能拿页面里的「TMDb」字样判？也不行：批量探测时对端会连续返回挑战页，
#   字样的出现与否全看它心情，同一批 IP 单测能过、连测就判 wrong，误杀一大片。
#   真正可靠的是证书：CloudFront 对「不认识这个域名」的请求在 TLS 阶段就用默认证书
#   （*.cloudfront.net）应答，我们校验证书就失败了；证书能过 = 这个地址确实承载
#   TMDB 这个 distribution。所以 expect 留空，只要求「证书对 + 有 HTTP 响应」。
set -u
source /app/scheduler/common.sh
acquire_lock || exit 1

export PREF_PROBE_TARGET=www.themoviedb.org
export PREF_PROBE_PATH='/'
export PREF_PROBE_EXPECT=''

# 网页 / API / 图片是同一批 CloudFront 边缘节点，三个域名都要映射，
# 否则浏览器打开站点后，海报（image.tmdb.org）和 API 请求仍然走污染解析。
export PREF_EXTRA_DOMAINS="api.tmdb.org image.tmdb.org"

# 测速地址：www.themoviedb.org 根路径只回 2.6KB 的挑战页，算不出带宽。
# 拿一张 w500 海报（约 160KB）来测，直连选中的 IP、SNI 用 image.tmdb.org，
# 测的是同一条 CloudFront 链路。这张图是 TMDB 上最经典的条目之一，
# 路径长期有效；哪天挂了也不影响优选，只是这一行没有速度数字。
export PREF_SPEED_URL='https://image.tmdb.org/t/p/w500/q6y0Go1tsGEsmtFryDOJo3dEmqu.jpg'

run_route "tmdb" "/app/config/seeds/tmdb.txt" 443
