#!/usr/bin/env bash
# 轮询 po9873/mosdns 最新一次 build 的状态，结束就打印结论。
RUN="${1:-40376076354}"
TOK="${GITHUB_PAT:-}"
HDR=(-H "Accept: application/vnd.github+json")
[ -n "$TOK" ] && HDR+=(-H "Authorization: Bearer $TOK")

for i in $(seq 1 60); do
  r=$(curl -sS "${HDR[@]}" "https://api.github.com/repos/po9873/mosdns/actions/runs/$RUN")
  st=$(printf '%s' "$r" | python3 -c "import json,sys;print(json.load(sys.stdin).get('status'))" 2>/dev/null)
  cc=$(printf '%s' "$r" | python3 -c "import json,sys;print(json.load(sys.stdin).get('conclusion'))" 2>/dev/null)
  echo "[$i] status=$st conclusion=$cc"
  if [ "$st" = "completed" ]; then
    echo "=== 最终: $cc ==="
    curl -sS "${HDR[@]}" "https://api.github.com/repos/po9873/mosdns/actions/runs/$RUN/jobs" | python3 -c "
import json,sys
d=json.load(sys.stdin)
for j in d.get('jobs',[]):
    for s in j.get('steps',[]):
        print('  %-32s %s %s' % (s.get('name'), s.get('status'), s.get('conclusion') or ''))
"
    exit 0
  fi
  sleep 30
done
echo "超过 30 分钟仍在跑，自行去 https://github.com/po9873/mosdns/actions 查看"
exit 1
