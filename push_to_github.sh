#!/usr/bin/env bash
# 一次性把本地仓库推到 GitHub，并可选触发镜像构建。
#
# 用法（PAT 不落盘、不进仓库）：
#   GITHUB_USER=你的用户名 GITHUB_PAT=ghp_xxx REPO=mosdns-pref ./push_to_github.sh
#
# PAT 最低权限：
#   Classic        -> 勾 repo（含 workflow）
#   Fine-grained   -> 目标仓库 Administration: R/W、Contents: R/W
# 推完去 https://github.com/settings/tokens 删掉即可。
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

USER="${GITHUB_USER:-}"
PAT="${GITHUB_PAT:-}"
REPO="${REPO:-mosdns-pref}"
BRANCH="${BRANCH:-main}"
VISIBILITY="${VISIBILITY:-public}"

if [ -z "$USER" ] || [ -z "$PAT" ]; then
  echo "缺少凭据。用法："
  echo "  GITHUB_USER=用户名 GITHUB_PAT=ghp_xxx ./push_to_github.sh"
  exit 2
fi

# 提交身份（只写本地，不改全局）
git config user.name  >/dev/null 2>&1 || git config user.name  "$USER"
git config user.email >/dev/null 2>&1 || git config user.email "${USER}@users.noreply.github.com"

# 仓库不存在就先建
echo ">> 检查仓库 ${USER}/${REPO} …"
code=$(curl -s -o /dev/null -w "%{http_code}" \
  -u "${USER}:${PAT}" "https://api.github.com/repos/${USER}/${REPO}")
if [ "$code" = "404" ]; then
  echo ">> 仓库不存在，创建（${VISIBILITY}）…"
  curl -sS -X POST -u "${USER}:${PAT}" \
    -H "Accept: application/vnd.github+json" \
    -d "{\"name\":\"${REPO}\",\"private\":$([ "$VISIBILITY" = "private" ] && echo true || echo false),\"auto_init\":false}" \
    https://api.github.com/user/repos >/dev/null
  sleep 2
elif [ "$code" != "200" ]; then
  echo "!! 访问仓库失败（HTTP $code）。检查 PAT 权限或用户名。"
  exit 3
fi

# 远端用「用户名+PAT」内嵌的形式，推完立刻改成不带凭据的地址，
# 避免明文 token 留在 .git/config
git remote remove origin 2>/dev/null || true
git remote add origin "https://${USER}:${PAT}@github.com/${USER}/${REPO}.git"

echo ">> 推送 ${BRANCH} …"
git branch -M "$BRANCH"
git push -u origin "$BRANCH"

git remote set-url origin "https://github.com/${USER}/${REPO}.git"
echo ">> 已清除本地保存的 PAT（remote 现在是 ${USER}/${REPO}.git）"

echo ">> 触发构建 …"
curl -sS -X POST -u "${USER}:${PAT}" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/${USER}/${REPO}/actions/workflows/build.yml/dispatches" \
  -d "{\"ref\":\"${BRANCH}\"}" -o /dev/null -w "dispatch HTTP %{http_code}\n"

echo
echo "完成：https://github.com/${USER}/${REPO}/actions"
echo "提醒：去 https://github.com/settings/tokens 撤销刚才那个 PAT。"
