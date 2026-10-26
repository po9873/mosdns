# MosDNS 优选一体机

原版 [mosdns](https://github.com/IrineSistiana/mosdns) 源码构建 + 五路优选 + 单登录控制台。
零第三方黑盒；运行时不下载任何东西；所有版本可由 `versions.env` 锁定。

## 特性

- **原版核心**：从官方 v5 源码 `go build`，零第三方打包。
- **五路优选**：Cloudflare / Google / Google 翻译 / GitHub / ghcr.io，串行执行（全局锁，CPU 弱也不怕）。
- **自包含**：候选 IP 靠运行时向本机 mosdns 实时解析，延迟靠 TCP 直连探测；工具与种子固化在镜像内，**不存在"拉不下来"**。
- **默认国内优先**：未知域名先走国内 DoH，超时/失败才走国外；GFW 清单强制走国外。
- **IP 归属校验**：国内返回的 IP 必须落在国内网段才采用，被污染则丢弃转国外。
- **清单自更新**：国内 IP 段随 APNIC 分配变化，可每日自动更新 / 手动更新，UI 里能看到条目数、更新时间、来源，并支持预览。
- **单登录 UI**：概况 / 结果 / 日志 / 配置 / 源；实时解析域名；亮/暗/系统三态；移动端底栏。
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
2. 首次启动会打印随机登录密码（`docker logs mosdns-pref | grep 密码`），或用 `PREF_AUTH_PASS` 指定。
3. 浏览器打开 `http://<服务器IP>/` 登录。

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
| `PREF_AUTH_USER` | `admin` | 登录账号 |
| `PREF_AUTH_PASS` | 空 | 登录密码；空则随机生成并打印 |
| `PREF_UI_PORT` | `80` | 控制台端口 |
| `PREF_DNS_PORT` | `53` | DNS 端口 |
| `PREF_DOMESTIC_DOH` | `https://223.5.5.5/dns-query` | 国内上游 |
| `PREF_FOREIGN_DOH` | `https://1.1.1.1/dns-query` | 国外上游 |
| `PREF_FOREIGN_DOH_BACKUP` | `https://8.8.8.8/dns-query` | 国外备援 |
| `PREF_THREADS` | 空 | 优选并发；空=自动（CPU/虚拟化自适应） |

> 上游 DoH 用 IP 形式，是为了避免 mosdns 启动时解析上游域名造成"自己解析自己"的循环。

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
