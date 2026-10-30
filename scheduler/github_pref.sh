#!/bin/bash
# GitHub 路优选：目标 github.com
#
# 关于 v6：GitHub 公布的 v6 段（2a0a:a440::/32 这一批）从当地不可路由。
# 实测按每等份中点取 18 个地址，全部 timeout / fail；而同一台机器上
# CloudFront 的 2600:9000 段是能过校验的，所以不是机器没 v6，是这几段不通。
# 既然选不出来，就别每轮白探十几个、每个等 6 秒。哪天通了把这行删掉即可。
export PREF_NO_V6=1

# github.com 那批 IP 同时服务这些域名（实测逐个通过证书校验）：
#   www/api/codeload/collector  github 自己的主机名
#   avatars/camo/user-images   README 里的图片、头像
#   raw/objects/gist           raw 文件、Release 附件、gist
export PREF_EXTRA_DOMAINS="www.github.com api.github.com codeload.github.com collector.github.com avatars.githubusercontent.com camo.githubusercontent.com user-images.githubusercontent.com raw.githubusercontent.com objects.githubusercontent.com gist.githubusercontent.com"

# 必须「真能打开 GitHub 页面」才算可用：根路径返回的内容里必须包含 GitHub。
# 否则会出现「TCP 通、证书也对、但页面只回 OK / 空白」的假可用 IP 被写进 hosts，
# 浏览器打开 github.com 看到的就是一行 OK。expect 不合 → 判 wrong，直接剔除。
export PREF_PROBE_TARGET=github.com
export PREF_PROBE_PATH='/'
export PREF_PROBE_EXPECT='GitHub'

# 优先用社区源（GitHub520 / ineo6 这类专为受限网络挑的入口）：官方网段 / DNS 实时
# 解析出来的 IP 在某些网络里会「容器侧探测看着正常、用户那边却回 OK / 打不开」。
# 社区源更可能在用户网络里真能打开，所以选择时把它们排前面、官方/DNS 解析的排后面
# （仍作兜底）。配合上面的 expect 真验证，最终 pin 的是「社区源里确实能打开 GitHub 的 IP」。
export PREF_PREFER_THIRD=1

set -u
source /app/scheduler/common.sh
acquire_lock || exit 1
run_route "github" "/app/config/seeds/github.txt" 443
