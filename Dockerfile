# syntax=docker/dockerfile:1
#
# MosDNS 优选镜像 —— 原版核心 + 自建层（零第三方黑盒）
# 运行时不下载任何东西：工具/种子都固化在镜像里，优选只做 DNS 查询 + TCP 测延迟。
#
# 所有版本都可通过 --build-arg 覆盖（由 CI 的 versions.env 注入）
ARG GOLANG_IMAGE=golang:1.24-alpine
ARG ALPINE_IMAGE=alpine:3.20
ARG MOSDNS_VERSION=v5.3.4
ARG CFT_VERSION=v2.3.5
ARG GT_VERSION=latest

# ---------- 阶段 1：从官方源码编译 mosdns ----------
FROM ${GOLANG_IMAGE} AS builder
ARG MOSDNS_VERSION
ENV GOPROXY=https://proxy.golang.org,direct
RUN apk add --no-cache git ca-certificates
WORKDIR /build
# 不能用 go install pkg@version：mosdns 的 go.mod 含 replace 指令，Go 不允许
# 以「非主模块」方式安装这类包。改为克隆源码、以主模块身份 go build，replace 才生效。
RUN git clone --depth 1 --branch ${MOSDNS_VERSION} https://github.com/IrineSistiana/mosdns.git /build/mosdns \
    && cd /build/mosdns \
    && go build -trimpath -o /go/bin/mosdns .

# ---------- 阶段 2：可选测速工具（失败不阻断，脚本会自动回退纯脚本探测）----------
FROM ${ALPINE_IMAGE} AS tools
ARG CFT_VERSION
RUN apk add --no-cache curl tar
# 资产名是 cfst_linux_amd64.tar.gz（不是 CloudflareSpeedTest_linux_amd64.tar.gz），
# 之前按项目名拼 URL 一直 404，于是镜像里从来没有这个工具。
# GoogleTranslateIpCheck 自 1.9 起只发 Windows 包，1.8 之后没有 linux 构建，
# 不再固化；gt 路本来就用它的社区 IP 清单，不依赖二进制。
RUN mkdir -p /opt/cft && \
    ( curl -fsSL "https://github.com/XIU2/CloudflareSpeedTest/releases/download/${CFT_VERSION}/cfst_linux_amd64.tar.gz" -o /tmp/cft.tgz \
      && tar -xzf /tmp/cft.tgz -C /opt/cft \
      && (chmod +x /opt/cft/cfst 2>/dev/null || chmod +x /opt/cft/CloudflareSpeedTest 2>/dev/null) \
      && (test -x /opt/cft/cfst || ln -sf CloudflareSpeedTest /opt/cft/cfst) ) \
    || echo "warn: CloudflareSpeedTest 未固化，将使用纯脚本探测"
RUN touch /opt/cft/.keep
# 中国 IP 段完整列表（构建时下载并固化；多源兜底 + 条目数校验，失败则用仓库内置精简种子）
RUN mkdir -p /opt/seed && \
    ok=0; \
    for u in \
      "https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt" \
      "https://ispip.clang.cn/all_cn.txt" \
      "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china.txt" ; do \
      if curl -fsSL --retry 2 --max-time 90 "$u" -o /tmp/cip.txt; then \
        n=$(grep -cE '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$' /tmp/cip.txt || true); \
        if [ "${n:-0}" -ge 500 ]; then \
          mv /tmp/cip.txt /opt/seed/china_ip.txt; ok=1; echo "china_ip 固化成功: ${n} 条 <- $u"; break; \
        fi; \
      fi; \
    done; \
    [ "$ok" = "1" ] || echo "warn: china_ip 完整列表未下载，使用内置精简种子"; \
    touch /opt/seed/china_ip.txt
# CDN 网段库（诊断用）：构建时按官方发布的源合并固化，运行时仍可在线更新
RUN { : > /opt/seed/cdn_ranges.txt; \
      for src in "Cloudflare|https://www.cloudflare.com/ips-v4" \
                 "Cloudflare|https://www.cloudflare.com/ips-v6" \
                 "Fastly|https://api.fastly.com/public-ip-list"; do \
        name="${src%%|*}"; url="${src#*|}"; \
        if curl -fsSL --retry 2 --max-time 60 "$url" -o /tmp/cdn.txt; then \
          case "$url" in \
            *public-ip-list*) \
              python3 -c "import json,sys;d=json.load(open('/tmp/cdn.txt'));[print('$name',c) for c in (d.get('addresses') or [])+(d.get('ipv6_addresses') or [])]" >> /opt/seed/cdn_ranges.txt 2>/dev/null ;; \
            *) \
              awk -v n="$name" '/^[0-9a-fA-F:.]+\/[0-9]+$/{print n" "$0}' /tmp/cdn.txt >> /opt/seed/cdn_ranges.txt ;; \
          esac; \
        fi; \
      done; \
      if curl -fsSL --retry 2 --max-time 60 "https://www.gstatic.com/ipranges/goog.txt" -o /tmp/goog.txt 2>/dev/null; then \
        awk -F, '/^(ipv4|ipv6),/{gsub(/ /,"",$2); if ($2 ~ /\//) print "Google "$2}' /tmp/goog.txt >> /opt/seed/cdn_ranges.txt; \
      fi; \
      n=$(wc -l < /opt/seed/cdn_ranges.txt 2>/dev/null || echo 0); \
      echo "cdn_ranges 固化: ${n} 条"; \
      [ "${n:-0}" -ge 20 ] || : > /opt/seed/cdn_ranges.txt; }

# ---------- 阶段 3：运行时镜像 ----------
FROM ${ALPINE_IMAGE}
ARG MOSDNS_VERSION=v5.3.4
ARG CFT_VERSION=v2.3.5
ARG GT_VERSION=latest
ARG BUILD_REV=dev
ARG BUILD_DATE=""
LABEL org.opencontainers.image.description="MosDNS 优选镜像：原版核心 + 七路优选 + 单登录 UI"
LABEL org.opencontainers.image.title="mosdns-pref"

RUN apk add --no-cache ca-certificates curl bash python3 tzdata \
    && rm -rf /var/cache/apk/*

COPY --from=builder /go/bin/mosdns /usr/local/bin/mosdns
COPY --from=tools /opt/cft /app/bin/cft

# 构建信息落盘：控制台「工具与版本」读这个文件，
# 显示的就是镜像里实际装进去的版本，不是 versions.env 里「想要」的版本。
# gt 只记录版本号：上游 1.9 起不再发 linux 包，1.8 的 linux-x64 是 .NET
# 自包含构建，Alpine（musl）跑不起来；gt 路用的是它的社区 IP 清单，
# 清单跟随上游 master，所以这里照样记下 CI 探测到的最新 release 标签。
RUN mkdir -p /app && printf 'mosdns=%s\ncft=%s\ngt=%s\nbuild_rev=%s\nbuild_date=%s\n' \
      "$MOSDNS_VERSION" "$CFT_VERSION" "$GT_VERSION" "$BUILD_REV" "$BUILD_DATE" > /app/VERSIONS

WORKDIR /app
COPY config/      /app/config/
# 若构建时成功下载了完整 china_ip 列表，则覆盖内置精简种子
COPY --from=tools /opt/seed/china_ip.txt /tmp/china_ip_full.txt
COPY --from=tools /opt/seed/cdn_ranges.txt /tmp/cdn_ranges_full.txt
RUN if [ -s /tmp/china_ip_full.txt ]; then cp /tmp/china_ip_full.txt /app/config/china_ip.txt; fi \
    && if [ -s /tmp/cdn_ranges_full.txt ]; then cp /tmp/cdn_ranges_full.txt /app/config/cdn_ranges.txt; fi \
    && rm -f /tmp/china_ip_full.txt /tmp/cdn_ranges_full.txt
COPY scheduler/   /app/scheduler/
COPY ui/          /app/ui/
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh \
    && chmod +x /app/scheduler/*.sh 2>/dev/null || true

# ---------- 环境变量（全部可在 run 时覆盖，均不写死）----------
# DoH 上游刻意用 IP 形式：避免 mosdns 启动时解析上游域名造成"自己解析自己"的循环。
ENV PREF_UI_PORT=80 \
    PREF_BIND=0.0.0.0 \
    PREF_DNS_PORT=53 \
    PREF_API_PORT=9099 \
    PREF_FOREIGN_DOH=https://1.1.1.1/dns-query \
    PREF_FOREIGN_DOH_BACKUP=https://8.8.8.8/dns-query \
    PREF_DOMESTIC_DOH=https://223.5.5.5/dns-query \
    PREF_THREADS="" \
    PREF_DATA_DIR=/data

VOLUME ["/data"]
EXPOSE 53/tcp 53/udp 80/tcp 9099/tcp

ENTRYPOINT ["/app/docker-entrypoint.sh"]
