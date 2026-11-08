#!/bin/sh
# mosdns 升级镜像校验 / 快路径取镜像（宿主机 38 使用）
# 仓库内权威副本：scripts/verify_image.sh，随镜像固化在 /app/scripts/。
# 宿主机那份若丢失，可从镜像取回：
#   docker run --rm --entrypoint cat po9873/mosdns:latest /app/scripts/verify_image.sh > /mnt/sda1/mosdns/verify_image.sh
# 部署仍用 po9873/mosdns:latest，不改 compose、不改栈定义。
#
# 为什么不用 ghcr 拉：Docker 的 registry-mirrors 只对 Docker Hub 生效，
# ghcr.io 走境外直连，blob 实测约 50KB/s，整镜像要 5~6 分钟；
# 内网 mirror registry.linkease.net:5443 实测约 630KB/s。
# mirror 的 latest 偶发缓存滞后，故一律按 ghcr 的 manifest digest 拉取
# （digest 拉取不受 tag 缓存影响），校验 config digest 一致后才 retag。
set -u
REPO=po9873/mosdns
MIRROR=registry.linkease.net:5443
ACC='application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json'
HDR=/tmp/mosdns_verify_hdr

TOK=$(curl -s -m 20 "https://ghcr.io/token?scope=repository:$REPO:pull&service=ghcr.io" | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])' 2>/dev/null)
curl -s -m 20 -H "Authorization: Bearer $TOK" -H "Accept: $ACC" -D "$HDR" -o /dev/null "https://ghcr.io/v2/$REPO/manifests/latest"
GH_DIGEST=$(grep -i '^docker-content-digest:' "$HDR" | tr -d '\r' | awk '{print $2}')
GH_CFG=$(curl -s -m 20 -H "Authorization: Bearer $TOK" -H "Accept: $ACC" "https://ghcr.io/v2/$REPO/manifests/latest" | python3 -c 'import sys,json;print(json.load(sys.stdin)["config"]["digest"])' 2>/dev/null)
curl -sk -m 20 -H "Accept: $ACC" -D "$HDR" -o /dev/null "https://$MIRROR/v2/$REPO/manifests/latest"
MIR_DIGEST=$(grep -i '^docker-content-digest:' "$HDR" | tr -d '\r' | awk '{print $2}')
rm -f "$HDR"
LOCAL_ID=$(docker image inspect "$REPO:latest" --format '{{.Id}}' 2>/dev/null || echo none)
echo "ghcr   latest : ${GH_DIGEST:-unknown}"
echo "mirror latest : ${MIR_DIGEST:-unknown}"
echo "ghcr   config : ${GH_CFG:-unknown}"
echo "local  latest : $LOCAL_ID"
WARN=0
if [ -n "$GH_DIGEST" ] && [ "$MIR_DIGEST" != "$GH_DIGEST" ]; then
  echo "WARN: mirror latest 缓存滞后（--fix 按 digest 拉取，不受影响）"; WARN=1
fi
if [ -n "$GH_CFG" ] && [ "$LOCAL_ID" != "$GH_CFG" ]; then
  echo "WARN: 本地 latest 不是最新，别直接 Redeploy"; WARN=1
fi
[ "$WARN" = "0" ] && echo "OK: digest 一致，可以升级"

if [ "${1:-}" = "--fix" ]; then
  if [ -z "$GH_DIGEST" ] || [ -z "$GH_CFG" ]; then
    echo "ERR: 取不到 ghcr 基准 digest，中止"; exit 1
  fi
  echo "== 走内网 mirror 按 digest 快拉（绕开 latest 缓存） =="
  OK=0
  if docker pull "$MIRROR/$REPO@$GH_DIGEST"; then
    ID=$(docker image inspect "$MIRROR/$REPO@$GH_DIGEST" --format '{{.Id}}' 2>/dev/null)
    if [ "$ID" = "$GH_CFG" ]; then OK=1; else echo "WARN: mirror 内容与 ghcr 基准不一致，回退 ghcr"; fi
  else
    echo "WARN: mirror 按 digest 拉取失败（新镜像可能还没同步），回退 ghcr"
  fi
  if [ "$OK" = "1" ]; then
    docker tag "$GH_CFG" "$REPO:latest"
    docker rmi "$MIRROR/$REPO@$GH_DIGEST" >/dev/null 2>&1 || true
    SRC=mirror
  else
    echo "== 回退 ghcr.io 直连（慢，约 5-6 分钟） =="
    docker pull "ghcr.io/$REPO:latest" || exit 1
    ID=$(docker image inspect "ghcr.io/$REPO:latest" --format '{{.Id}}')
    if [ "$ID" != "$GH_CFG" ]; then echo "ERR: ghcr 镜像与基准不一致，中止"; exit 1; fi
    docker tag "ghcr.io/$REPO:latest" "$REPO:latest"
    SRC=ghcr
  fi
  # 自动打版本锚点：从镜像内 VERSIONS 读 build_rev，在 mirror tags 里找对应 tag
  REV=$(docker run --rm --entrypoint cat "$REPO:latest" /app/VERSIONS 2>/dev/null | sed -n 's/^build_rev=//p' | head -1)
  if [ -n "$REV" ]; then
    TAG=$(curl -sk -m 20 "https://$MIRROR/v2/$REPO/tags/list" | python3 -c '
import sys, json
rev = sys.argv[1]
try:
    print(next((t for t in json.load(sys.stdin).get("tags", []) if t.endswith("-" + rev)), ""))
except Exception:
    print("")
' "$REV" 2>/dev/null)
    if [ -n "$TAG" ]; then docker tag "$GH_CFG" "$REPO:$TAG"; echo "anchor tag: $REPO:$TAG"; fi
  fi
  echo "done  source=$SRC  config=$GH_CFG  rev=${REV:-unknown}"
  echo "下一步：Portainer stack 45 Redeploy（PUT 后轮询 Status=1，不要并发 compose up）"
fi
