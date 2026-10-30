#!/bin/bash
# 自动治理：把「实际在访问、但慢」的域名找出来，换上更快的 IP。
#
# 前面几路（Google / GitHub / ghcr / TMDB…）都是「先知道有这条路，再去优选」。
# 日常访问里总有一堆域名根本没配优选，也从来没人去管——它们慢了就只能等用户
# 发现、再手工加进来。这一路把它反过来：从查询日志里看「你实际在访问什么」，
# 现场测速，慢的就自动找更快的 IP 换上。
#
# 三步（都在 lib/slow_scan.py + 这里完成，全程无人参与）：
#   1) slow_scan.py 按「查询次数 × 持续时长」挑出最该管的域名，现场测 TTFB/吞吐
#   2) 慢的域名：候选 IP = 现在的 + DNS 其它记录 + 同 CDN 其它网段（换段）
#   3) 实测确实更快才写进 auto.hosts，比现在快不到一倍不动（避免来回抖）
#
# 已经被其它路优选覆盖的域名不碰（各路自己有换段逻辑，这里改会打架）。
set -u
source /app/scheduler/common.sh
acquire_lock || exit 1

EVERY=${AUTO_SCAN_EVERY:-1200}      # 20 分钟扫一次
now=$(date +%s)
last=$(python3 -c "
import json,os
p='$PREF_DIR/.auto_scan.json'
try: print(json.load(open(p)).get('t',0))
except Exception: print(0)
" 2>/dev/null || echo 0)
if [ "${AUTO_FORCE:-0}" != "1" ] && [ "${last:-0}" -gt 0 ] && [ $(( now - last )) -lt "$EVERY" ]; then
  log "auto: 距上次体检 $(( (now - last) / 60 )) 分钟（<$(( EVERY / 60 ))），本轮跳过"
  exit 0
fi
python3 -c "
import json
json.dump({'t': $now}, open('$PREF_DIR/.auto_scan.json','w'))" 2>/dev/null

log "auto: 开始体检——从查询日志里找「在访问但慢」的域名"
python3 "$SELF_DIR/lib/slow_scan.py" "$PREF_DIR" 2>/dev/null | sed 's/^/auto: /' | while read -r l; do log "$l"; done

# 慢域名清单转成 shell 好处理的行：域名|当前IP|延时|速度
SLOW_FILE="$PREF_DIR/.slow.json"
[ -s "$SLOW_FILE" ] || { log "auto: 没有慢的域名，收工"; exit 0; }

rows=$(python3 - "$SLOW_FILE" <<'PYEOF'
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    sys.exit(0)
for x in d.get("slow", []):
    print("%s|%s|%s|%s|%s" % (x["domain"], x.get("ip", ""),
          int(x.get("latency") or 0), int(x.get("speed") or 0), x.get("why", "")))
PYEOF
)
[ -n "$rows" ] || { log "auto: 没有慢的域名，收工"; exit 0; }

: > "$PREF_DIR/auto.hosts.tmp"
changed=0
IFS=$'\n'
for row in $rows; do
  dom=${row%%|*}; rest=${row#*|}
  cur_ip=${rest%%|*}; rest=${rest#*|}
  cur_lat=${rest%%|*}; rest=${rest#*|}
  cur_sp=${rest%%|*}; why=${rest#*|}

  # 已被其它路优选覆盖的交给各路自己处理，这里不插手
  if grep -q "^$dom " "$PREF_DIR/all.hosts" 2>/dev/null; then
    log "auto: $dom 已有优选路在管（$why），跳过"
    continue
  fi

  # 候选：现在的 IP + DNS 其它记录 + 同 CDN 其它网段
  cand=$(resolve_ips "$dom" "" A | tr '\n' ' ')
  cand="$cur_ip $cand"
  exp=$(printf '%s\n' "$cand" | tr ' ' '\n' | awk 'NF' | cdn_expand_ips "$dom" 443 / "" 200 3 | awk '{print $1}')
  cand=$(printf '%s %s\n' "$cand" "$exp" | tr ' ' '\n' | awk '!seen[$0]++ && NF')

  # 现场验：能开（TLS+HTTP）且比现在快
  best=$(printf '%s\n' "$cand" | python3 "$SELF_DIR/lib/https_probe.py" "$dom" 443 5 4 1 / "" "" 2>/dev/null \
         | awk -v cl="${cur_lat:-99999}" -v cs="${cur_sp:-0}" '$2=="ok"{
             lat=$3+0; sp=(($4=="-"||$4=="")?0:$4+0);
             # 比现在快：延时更低，或吞吐明显更高（至少快一倍）
             if (lat < cl*0.85 || sp > cs*1.3) printf "%s %s %s %s\n", $1, lat, sp, $4 }' \
         | sort -k2 -n | head -1)
  [ -n "$best" ] || { log "auto: $dom 没找到更快的 IP（$why），保持原样"; continue; }

  b_ip=$(echo "$best" | awk '{print $1}')
  b_lat=$(echo "$best" | awk '{print $2}')
  b_sp=$(echo "$best" | awk '{print $3}')
  printf '%s %s\n' "$dom" "$b_ip" >> "$PREF_DIR/auto.hosts.tmp"
  changed=$(( changed + 1 ))
  # 改动清单：面板「自动治理」那格要能原样列出「动了哪些、从哪个换到哪个、
  # 为什么动」，不能只让用户看到 hosts 变了。
  python3 - "$PREF_DIR/auto_changes.json" "$dom" "$cur_ip" "$b_ip" "$why" "$b_lat" "$b_sp" <<'PYEOF'
import json, sys, time
p, dom, old_ip, new_ip, why, lat, sp = sys.argv[1:8]
try:
    ch = json.load(open(p, encoding="utf-8"))
except Exception:
    ch = []
ch.append({"t": int(time.time()), "domain": dom, "old_ip": old_ip, "new_ip": new_ip,
           "why": why, "latency": lat, "speed": sp})
json.dump(ch[-50:], open(p, "w", encoding="utf-8"))
PYEOF
  log "auto: $dom 慢（$why）→ 换 $b_ip（${b_lat}ms / ${b_sp}KB/s），原 ${cur_ip}"
done
unset IFS

if [ "$changed" -gt 0 ]; then
  mv "$PREF_DIR/auto.hosts.tmp" "$PREF_DIR/auto.hosts"
  before=$(file_sig "$PREF_DIR/all.hosts")
  merge_hosts
  reload_if_changed "$before"
  log "auto: 本轮换掉 $changed 个慢域名"
else
  rm -f "$PREF_DIR/auto.hosts.tmp"
  log "auto: 体检完毕，没有需要换 IP 的域名"
fi
exit 0
