# MosDNS 优选一体机

原版 [mosdns](https://github.com/IrineSistiana/mosdns) 源码构建 + 五路优选 + 单登录控制台。
零第三方黑盒；运行时不下载任何东西；所有版本可由 `versions.env` 锁定。

## 特性

- **原版核心**：从官方 v5 源码 `go build`，零第三方打包。
- **五路优选**：Cloudflare / Google / Google 翻译 / GitHub / ghcr.io，串行执行（全局锁，CPU 弱也不怕）。
- **多 IP + IPv6**：每路按延迟保留前 N 个 IP（IPv4 / IPv6 各自排序），一次写入 hosts，某个 IP 失效可自动切换。
- **HTTPS 校验（排除 1034）**：TCP 通不等于可用。对候选逐个发起真实 TLS 握手 + `Host` 请求，**Cloudflare 1034 / 1010 / 1020、证书不符、5xx 一律剔除**，避免优选到一个打开就报错的 IP。
- **自包含**：候选 IP 靠运行时向本机 mosdns 实时解析，延迟靠 TCP 直连探测；工具与种子固化在镜像内，**不存在"拉不下来"**。
- **默认国内优先**：未知域名先走国内 DoH，超时/失败才走国外；GFW 清单强制走国外。
- **IP 归属校验**：国内返回的 IP 必须落在国内网段才采用，被污染则丢弃转国外。
- **诊断页**：IP 查询（境内/境外、CDN 厂商、PTR）、端口连通检测（ICMP + TCP + UDP）、域名查询（A/AAAA + 逐 IP 归属与延迟），**每次都是现查，点「重新查询」即刷新**。
- **消息推送**：企业微信 / 钉钉 / 飞书 机器人 Webhook，可按事件（每轮完成 / 失败或降级 / 登录提醒）推送，只推事件不推明细。
- **清单自更新**：国内 IP 段、CDN 网段库（Cloudflare / Google / Fastly 官方源）都可每日自动更新 / 手动更新，UI 里能看到条目数、更新时间、来源，并支持预览。
- **单登录 UI**：概况 / 结果 / 诊断 / 日志 / 配置 / 源；实时解析域名；亮/暗/系统三态；移动端底栏。
- **数据隔离**：个人运行数据只写 `/data` 卷，镜像与仓库不含任何个人数据。

## 构建（GitHub Actions）

推送到 `main` 即触发；也可在 Actions 页手动 Run workflow：

| 输入 | 作用 |
|---|---|
| `auto_update` | 自动探测所有上游最新版（含 golang/alpine 大版本） |
| `mosdns_version` | 指定 mosdns 版本 |
| `push_latest` | 是否更新 `latest` 标签 |

构建流程：解析版本 → 构建 → **自检门禁**（UI 健康检查 / mosdns 可执行 / 配置生成）→ 通过才推 → 失败自动回退 `known-good.env` 并报警。

产物：
- `ghcr.io/<你的用户名>/mosdns`
- `docker.io/<你的 Docker Hub 用户名>/mosdns`（需配置 Secrets：`DOCKERHUB_USERNAME`、`DOCKERHUB_TOKEN`）

## 部署

1. 复制 `docker-compose.yml`，把 `CHANGE_ME` 改成你的用户名。
2. 首次启动的初始账号是 **`admin` / `admin`**（不设置也能直接用）。
3. 浏览器打开 `http://<服务器IP>/` 登录，登录后在 **配置 → 账号与密码** 里改成自己的（可改可不改，不强制）。

```bash
docker compose up -d
docker logs -f mosdns-pref
```

## 分流清单（国内 IP 段会变）

`china_ip.txt` 是「国内 IP 归属检测」的依据，随 APNIC 分配每月都在变，所以做了三层：

| 层 | 做法 |
|---|---|
| 构建时 | CI 从多个公开源下载完整清单固化进镜像（失败则用仓库内置种子） |
| 运行时 | 默认每 24 小时检查一次，过期才下载；多源依次尝试，任一成功即原子替换 |
| 兜底 | 全部源失败 → **保留旧清单**，只在 UI 标记「更新失败」，绝不会把清单弄空 |

列表来源（依次尝试）：`17mon/china_ip_list` → `ispip.clang.cn` → `china-operator-ip` → APNIC 官方委派记录（自动把 `1.0.1.0/256` 转成 `1.0.1.0/24`）。

**在哪里看**：控制台「源」页 → 分流清单表（条目数 / 大小 / 更新时间 / 来源 / 状态），点「预览」看前 40 行，点「更新」立即拉取。概况页顶部也有一条 `国内 IP 段 7,456 条 · 2 小时前`。

**什么时候生效**：mosdns 不监听清单文件变化，所以更新后需要重载进程（约 1 秒）。程序会自动做，也可以点「重载引擎」。

## 关于重启（重要）

mosdns 没有热重载接口，改 hosts / 清单只能重启进程。为了不打扰使用：

- **一轮五路跑完只判断一次**，绝不「每路重启一次」；
- 本轮结果与上轮**完全一致时直接跳过重启**（IP 通常几天不变，所以大多数轮次是 0 次重启）；
- 清单更新与优选结果合并到同一次重载，不会连着重启两次；
- 重启由 supervisor 接管，中断约 1 秒；
- 不想自动重启可在「配置」页关掉「结果变化后自动重载引擎」，改为手动点「重载引擎」。

## 更新

- 上游自动探测：每周一（可在 workflow 改 cron）。
- 服务器升级：`docker compose pull && docker compose up -d`。
- 回退：`docker pull ghcr.io/<user>/mosdns:<旧tag>` 后改 compose 的 image 即可。

## 配置项（环境变量）

| 变量 | 默认 | 说明 |
|---|---|---|
| `PREF_AUTH_USER` | `admin` | 初始登录账号 |
| `PREF_AUTH_PASS` | `admin` | 初始登录密码；两个都填了环境变量才会覆盖 `/data/auth.json`（可用来重置） |
| `PREF_UI_PORT` | `80` | 控制台端口 |
| `PREF_DNS_PORT` | `53` | DNS 端口 |
| `PREF_DOMESTIC_DOH` | `https://223.5.5.5/dns-query` | 国内上游 |
| `PREF_FOREIGN_DOH` | `https://1.1.1.1/dns-query` | 国外上游 |
| `PREF_FOREIGN_DOH_BACKUP` | `https://8.8.8.8/dns-query` | 国外备援 |
| `PREF_THREADS` | 空 | 优选并发；空=自动（CPU/虚拟化自适应） |
| `PREF_CACHE_SIZE` | `8192` | DNS 缓存条数上限（LRU 淘汰，超出自动丢最旧的） |

> 上游 DoH 用 IP 形式，是为了避免 mosdns 启动时解析上游域名造成"自己解析自己"的循环。

## 缓存与日志（不会无限增长）

- **DNS 缓存**：`cache` 插件按条数上限做 LRU 淘汰（默认 8192 条，`PREF_CACHE_SIZE` 可调），
  不会因为长期运行而无限变大；缓存同时落盘到 `/data/cache.dump`，重启可复用。
- **一键清空**：控制台「概况 → 缓存与日志」里可看到当前条数 / 上限 / 占比 / 累计命中 / 落盘体积 / 日志体积，
  点「清空 DNS 缓存」立即释放（同时删掉落盘副本，避免重启又被加载回来）。
- **实时解析域名**：读取 mosdns `query_summary` 日志（时间/域名/类型/命中缓存/用时/状态/客户端），
  每 5 秒自动刷新，可在同一张卡里手动输入域名现查。
- **查询日志**：超过 32MB 自动只保留尾部 8MB，也可在控制台手动清空。

## 目录

```
config/       mosdns 配置模板 + 公开种子（cn/gfw 清单、五路候选种子）
scheduler/    调度 + 五路优选 + 公共函数 + DNS/探测/清单库（lib/lists.py）
ui/           控制台后端(server.py) + 前端(static/index.html)
versions.env  上游版本锁定
known-good.env 最后一份通过自检的组合
docker-entrypoint.sh  渲染配置 / 种入账号 / 拉起三进程
```

## 隐私

仓库只含通用代码、配置模板与公开种子；优选结果、域名数据、账号密码全部只在你的 `/data` 卷，永不进镜像或 GitHub。
