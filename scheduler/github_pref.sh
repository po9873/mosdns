#!/bin/bash
# GitHub 路优选：目标 github.com
#
# 关于 v6：GitHub 公布的 v6 段（2a0a:a440::/32 这一批）从当地不可路由。
# 实测按每等份中点取 18 个地址，全部 timeout / fail；而同一台机器上
# CloudFront 的 2600:9000 段是能过校验的，所以不是机器没 v6，是这几段不通。
# 既然选不出来，就别每轮白探十几个、每个等 6 秒。哪天通了把这行删掉即可。
export PREF_NO_V6=1

# github 路分两类节点，绝不能混：
#   ① 网页边缘（140.82.x）——服务 github.com / www.github.com。
#      由主优选按 github.com 校验选出，PREF_EXTRA_DOMAINS 里只放这批。
#   ② Fastly 边缘（151.101.x / 185.199.x）——服务 avatars/raw/objects/gist/
#      user-images/camo/pkg-containers/codeload/collector（实测 codeload、
#      collector 也是 Fastly：网页边缘对它们连不存在的 repo 都 301 踢走）。
#      对 github.com 校验根本通不过，必须每个域名独立选 IP，
#      见下方 fastly_pin_refresh.py（每域名专属探测路径 + 判定码）。
#   ③ api.github.com——网页边缘对 API 路径回 301 踢到 github.com（App 表现为
#      429/410 报错页），由 api_pin_refresh.py 验证 GET /rate_limit=200 单独选。
# 以前把 ② 塞在 PREF_EXTRA_DOMAINS 里靠主选 IP 映射，映射得上的全是
# 「301 跳走被漏放行」的假边缘——头像/附件实际全被踢到主站。
export PREF_EXTRA_DOMAINS="www.github.com"

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

# 固定映射行（须在 source common.sh 之后，PREF_DIR 才有定义）：
# 每行「域名 ip1 ip2 ...」，每个域名配自己的那批 IP，写入 .github.extra。
# 刷新失败则沿用旧结果；连旧结果都没有才用内置兜底。
export PREF_EXTRA_LINES="$PREF_DIR/.github.extra"
api_f="$PREF_DIR/.github.api"
fastly_f="$PREF_DIR/.github.fastly"
# set -u 下引用未定义变量会直接炸掉脚本（之前 PREF_LOG 就这样把两个刷新全弄失败）
pref_log="${PREF_LOG:-$DATA_DIR/pref.log}"

# 粘滞守卫：整路先看在用 IP，能用就沿用、有坏的由 101 精确补位；
# 不再每轮白跑 api/fastly 两个全量刷新（实测单这一项要 60 秒跨境探测）。
if [ "${PREF_RESELECT:-0}" != "1" ]; then
  python3 "$SELF_DIR/lib/sticky_guard.py" github 2>>"$pref_log" >/dev/null
  log "github: 粘滞守卫已处理（全能用就沿用，有坏的由 101 精确补位），跳过 api/fastly 全量刷新"
  exit 0
fi

if python3 /app/scheduler/lib/api_pin_refresh.py "$api_f" 2>>"$pref_log" \
   && [ -s "$api_f" ]; then
  :
else
  [ -s "$api_f" ] || printf 'api.github.com 140.82.116.6\n' > "$api_f"
fi

if ! python3 /app/scheduler/lib/fastly_pin_refresh.py "$fastly_f" 2>>"$pref_log" \
   || [ ! -s "$fastly_f" ]; then
  [ -s "$fastly_f" ] || printf 'avatars.githubusercontent.com 151.101.2.217 151.101.66.217 151.101.130.217 151.101.194.217\n' > "$fastly_f"
fi

: > "$PREF_EXTRA_LINES"
cat "$api_f" "$fastly_f" >> "$PREF_EXTRA_LINES"

run_route "github" "/app/config/seeds/github.txt" 443
