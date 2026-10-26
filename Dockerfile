# syntax=docker/dockerfile:1
#
# MosDNS 优选镜像 —— 原版核心 + 自建层（零第三方黑盒）
# 运行时不下载任何东西：工具/种子都固化在镜像里，优选只做 DNS 查询 + TCP 测延迟。
#
# 所有版本都可通过 --build-arg 覆盖（由 CI 的 versions.env 注入）
ARG GOLANG_IMAGE=golang:1.22-alpine
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
RUN go install github.com/IrineSistiana/mosdns/v5@${MOSDNS_VERSION}

# ---------- 阶段 2：可选测速工具（失败不阻断，脚本会自动回退纯脚本探测）----------
FROM ${ALPINE_IMAGE} AS tools
ARG CFT_VERSION
ARG GT_VERSION
RUN apk add --no-cache curl tar
RUN mkdir -p /opt/cft && \
    ( curl -fsSL "https://github.com/XIU2/CloudflareSpeedTest/releases/download/${CFT_VERSION}/CloudflareSpeedTest_linux_amd64.tar.gz" -o /tmp/cft.tgz \
      && tar -xzf /tmp/cft.tgz -C /opt/cft CloudflareSpeedTest \
      && chmod +x /opt/cft/CloudflareSpeedTest ) \
    || echo "warn: CloudflareSpeedTest 未固化，将使用纯脚本探测"
RUN mkdir -p /opt/gt && \
    ( curl -fsSL "https://github.com/Ponderfly/GoogleTranslateIpCheck/releases/download/${GT_VERSION}/GoogleTranslateIpCheck-linux-x64.tar.gz" -o /tmp/gt.tgz \
      && tar -xzf /tmp/gt.tgz -C /opt/gt \
      && chmod +x /opt/gt/* 2>/dev/null ) \
    || echo "warn: GoogleTranslateIpCheck 未固化，将使用纯脚本探测"
RUN touch /opt/cft/.keep /opt/gt/.keep
# 中国 IP 段完整列表（构建时下载并固化；失败则用仓库内置精简种子兜底）
RUN mkdir -p /opt/seed && \
    ( curl -fsSL --retry 3 "https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt" -o /opt/seed/china_ip.txt \
      && [ -s /opt/seed/china_ip.txt ] ) \
    || echo "warn: china_ip 完整列表未下载，将使用内置精简种子"
RUN touch /opt/seed/china_ip.txt

# ---------- 阶段 3：运行时镜像 ----------
FROM ${ALPINE_IMAGE}
LABEL org.opencontainers.image.description="MosDNS 优选镜像：原版核心 + 五路优选 + 单登录 UI"
LABEL org.opencontainers.image.title="mosdns-pref"

RUN apk add --no-cache ca-certificates curl bash python3 tzdata \
    && rm -rf /var/cache/apk/*

COPY --from=builder /go/bin/mosdns /usr/local/bin/mosdns
COPY --from=tools /opt/cft /app/bin/cft
COPY --from=tools /opt/gt /app/bin/gt

WORKDIR /app
COPY config/      /app/config/
# 若构建时成功下载了完整 china_ip 列表，则覆盖内置精简种子
COPY --from=tools /opt/seed/china_ip.txt /tmp/china_ip_full.txt
RUN if [ -s /tmp/china_ip_full.txt ]; then cp /tmp/china_ip_full.txt /app/config/china_ip.txt; fi \
    && rm -f /tmp/china_ip_full.txt
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
    PREF_AUTH_USER=admin \
    PREF_AUTH_PASS="" \
    PREF_THREADS="" \
    PREF_DATA_DIR=/data

VOLUME ["/data"]
EXPOSE 53/tcp 53/udp 80/tcp 9099/tcp

ENTRYPOINT ["/app/docker-entrypoint.sh"]
