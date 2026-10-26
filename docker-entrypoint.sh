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
AUTH_USER="${PREF_AUTH_USER:-admin}"
AUTH_PASS="${PREF_AUTH_PASS:-}"
THREADS="${PREF_THREADS:-}"

elog() { echo "[entrypoint] $*"; }

mkdir -p "$DATA_DIR/prefs"

# ---------- 初始化运行数据（只在不存在时创建，绝不覆盖用户数据）----------
[ -f "$DATA_DIR/prefs/all.hosts" ] || : > "$DATA_DIR/prefs/all.hosts"
if [ ! -f "$DATA_DIR/cn_domains.txt" ]; then
  cp /app/config/cn_domains.txt "$DATA_DIR/cn_domains.txt" 2>/dev/null || : > "$DATA_DIR/cn_domains.txt"
fi
if [ ! -f "$DATA_DIR/gfw_domains.txt" ]; then
  cp /app/config/gfw_domains.txt "$DATA_DIR/gfw_domains.txt" 2>/dev/null || : > "$DATA_DIR/gfw_domains.txt"
fi
if [ ! -f "$DATA_DIR/china_ip.txt" ]; then
  cp /app/config/china_ip.txt "$DATA_DIR/china_ip.txt" 2>/dev/null || : > "$DATA_DIR/china_ip.txt"
fi

# ---------- 自动线程 ----------
if [ -z "$THREADS" ] || [ "$THREADS" = "auto" ]; then
  THREADS=$(detect_threads)
fi
elog "优选并发线程: $THREADS"

# ---------- 账号密码（空则随机生成，仅打印到日志，不落镜像）----------
if [ -z "$AUTH_PASS" ]; then
  AUTH_PASS=$(head -c 64 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 18)
  elog "未设置 PREF_AUTH_PASS，已随机生成登录密码: $AUTH_PASS"
fi
cat > "$DATA_DIR/auth.json" <<EOF
{"user":"$AUTH_USER","pass":"$AUTH_PASS"}
EOF
elog "登录账号: $AUTH_USER"

# ---------- 默认设置 ----------
if [ ! -f "$DATA_DIR/settings.json" ]; then
  cat > "$DATA_DIR/settings.json" <<EOF
{"interval_min":60,"threads":$THREADS,"routes":{"cf":true,"google":true,"gt":true,"github":true,"ghcr":true}}
EOF
fi

# ---------- 渲染 mosdns 配置 ----------
esc() { printf '%s' "$1" | sed 's/[&|\\]/\\&/g'; }
sed \
  -e "s|__DNS_PORT__|$(esc "$DNS_PORT")|g" \
  -e "s|__API_PORT__|$(esc "$API_PORT")|g" \
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
      sleep 3
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

# ---------- UI（前台，容器主进程）----------
export PREF_UI_PORT="$UI_PORT"
export PREF_DATA_DIR="$DATA_DIR"
export PREF_DNS_PORT="$DNS_PORT"
export PREF_API_PORT="$API_PORT"
exec python3 /app/ui/server.py
