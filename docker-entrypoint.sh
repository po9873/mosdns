#!/bin/bash
# ============================================================
# 容器入口：渲染配置 / 种入账号 / 自动线程 / 拉起三进程
# 三进程：mosdns（supervisor 守护）、scheduler（后台）、UI（前台）
# 全部由环境变量驱动，零硬编码；运行数据只写 /data。
# ============================================================
set -u

source /app/scheduler/common.sh

DATA_DIR="${PREF_DATA_DIR:-/data}"
DNS_PORT="${PREF_DNS_PORT:-53}"
API_PORT="${PREF_API_PORT:-9099}"
UI_PORT="${PREF_UI_PORT:-80}"
FOREIGN_DOH="${PREF_FOREIGN_DOH:-https://1.1.1.1/dns-query}"
FOREIGN_DOH_BACKUP="${PREF_FOREIGN_DOH_BACKUP:-https://8.8.8.8/dns-query}"
DOMESTIC_DOH="${PREF_DOMESTIC_DOH:-https://223.5.5.5/dns-query}"
THREADS="${PREF_THREADS:-}"
CACHE_SIZE="${PREF_CACHE_SIZE:-8192}"

elog() { echo "[entrypoint] $*"; }

mkdir -p "$DATA_DIR/prefs"

# ---------- 初始化运行数据（只在不存在时创建，绝不覆盖用户数据）----------
[ -f "$DATA_DIR/prefs/all.hosts" ] || : > "$DATA_DIR/prefs/all.hosts"
# 清单：缺失时从镜像补齐（镜像里是构建时固化的完整版），并写入来源元数据
python3 /app/scheduler/lib/lists.py init >/dev/null 2>&1 || true
# 兜底（python 异常时也能保证文件存在）
[ -f "$DATA_DIR/cn_domains.txt" ] || cp /app/config/cn_domains.txt "$DATA_DIR/cn_domains.txt" 2>/dev/null || : > "$DATA_DIR/cn_domains.txt"
[ -f "$DATA_DIR/gfw_domains.txt" ] || cp /app/config/gfw_domains.txt "$DATA_DIR/gfw_domains.txt" 2>/dev/null || : > "$DATA_DIR/gfw_domains.txt"
[ -f "$DATA_DIR/china_ip.txt" ] || cp /app/config/china_ip.txt "$DATA_DIR/china_ip.txt" 2>/dev/null || : > "$DATA_DIR/china_ip.txt"
elog "分流清单: $(wc -l < "$DATA_DIR/china_ip.txt" 2>/dev/null || echo 0) 条国内 IP 段"
# IP 源与候选池：首次启动写入内置源（官方 + 第三方 + 镜像）
python3 /app/scheduler/lib/subs.py init >/dev/null 2>&1 || true

# ---------- 自动线程 ----------
if [ -z "$THREADS" ] || [ "$THREADS" = "auto" ]; then
  THREADS=$(detect_threads)
fi
elog "优选并发线程: $THREADS"

# ---------- 账号密码：固定初始 admin/admin，不再读环境变量 ----------
# 规则：① 已存在 /data/auth.json → 沿用（控制台改过的密码，重启不会被冲掉）
#       ② 不存在 → 写入 admin/admin；首次登录强制改密（前端不给进，接口也拦）
if [ ! -f "$DATA_DIR/auth.json" ]; then
  python3 - "$DATA_DIR/auth.json" <<'PY'
import json, os, sys
p = sys.argv[1]
tmp = p + ".tmp"
with open(tmp, "w") as f:
    json.dump({"user": "admin", "pass": "admin", "default": True}, f, ensure_ascii=False)
os.replace(tmp, p)
PY
  elog "初始登录账号: admin / admin（首次登录会强制修改密码）"
else
  elog "沿用已保存的登录账号（首次登录若仍是 admin/admin 会被强制改密）"
fi

# ---------- 默认设置 ----------
if [ ! -f "$DATA_DIR/settings.json" ]; then
  cat > "$DATA_DIR/settings.json" <<EOF
{"interval_min":60,"threads":$THREADS,"auto_reload":true,"list_auto_update":true,"list_update_hours":24,"top_n":3,"ipv6":true,"verify_https":true,"bad_ttl_hours":${PREF_BAD_TTL_HOURS:-6},"watchdog_sec":${PREF_WATCHDOG_SEC:-180},"sub_ttl_days":${PREF_SUB_TTL_DAYS:-14},"pool_max":${PREF_POOL_MAX:-4000},"push":{"enabled":false,"url":"","events":"round,warn,login"},"routes":{"cf":true,"google":true,"gt":true,"github":true,"ghcr":true}}
EOF
fi

# ---------- 渲染 mosdns 配置 ----------
esc() { printf '%s' "$1" | sed 's/[&|\\]/\\&/g'; }
sed \
  -e "s|__DNS_PORT__|$(esc "$DNS_PORT")|g" \
  -e "s|__API_PORT__|$(esc "$API_PORT")|g" \
  -e "s|__CACHE_SIZE__|$(esc "$CACHE_SIZE")|g" \
  -e "s|__DOMESTIC_DOH__|$(esc "$DOMESTIC_DOH")|g" \
  -e "s|__FOREIGN_DOH__|$(esc "$FOREIGN_DOH")|g" \
  -e "s|__FOREIGN_DOH_BACKUP__|$(esc "$FOREIGN_DOH_BACKUP")|g" \
  /app/config/config.yaml > "$DATA_DIR/config.yaml"
elog "配置已渲染: $DATA_DIR/config.yaml (DNS:$DNS_PORT API:$API_PORT UI:$UI_PORT)"

# ---------- mosdns supervisor ----------
start_mosdns() {
  /usr/local/bin/mosdns start -c "$DATA_DIR/config.yaml" -d "$DATA_DIR" >>"$DATA_DIR/mosdns.out" 2>&1 &
  echo $! > "$DATA_DIR/mosdns.pid"
}

mosdns_loop() {
  while true; do
    pid=""
    [ -f "$DATA_DIR/mosdns.pid" ] && pid=$(cat "$DATA_DIR/mosdns.pid" 2>/dev/null)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      sleep 1
      continue
    fi
    start_mosdns
    sleep 1
    pid=$(cat "$DATA_DIR/mosdns.pid" 2>/dev/null)
    if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
      elog "mosdns 启动失败，5 秒后重试（详见 $DATA_DIR/mosdns.out）"
      sleep 5
    else
      elog "mosdns 已启动 (pid $pid)"
      sleep 2
    fi
  done
}
mosdns_loop &

# ---------- scheduler（等 mosdns 就绪后再起）----------
( sleep 6; exec /app/scheduler/scheduler.sh daemon ) &

# ---------- watchdog（盯住 1034，一出现就换 IP）----------
export PREF_WATCHDOG_SEC="${PREF_WATCHDOG_SEC:-180}"
export PREF_DATA_DIR="$DATA_DIR"
( sleep 20; exec python3 /app/scheduler/lib/watchdog.py ) &

# ---------- UI（前台，容器主进程）----------
export PREF_UI_PORT="$UI_PORT"
export PREF_DATA_DIR="$DATA_DIR"
export PREF_DNS_PORT="$DNS_PORT"
export PREF_API_PORT="$API_PORT"
exec python3 /app/ui/server.py
