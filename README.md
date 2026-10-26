# MosDNS 优选一体机

原版 [mosdns](https://github.com/IrineSistiana/mosdns) 源码构建 + 五路优选 + 单登录控制台。
零第三方黑盒；运行时不下载任何东西；所有版本可由 `versions.env` 锁定。

## 特性

- **原版核心**：从官方 v5 源码 `go build`，零第三方打包。
- **五路优选**：Cloudflare / Google / Google 翻译 / GitHub / ghcr.io，串行执行（全局锁，CPU 弱也不怕）。
- **自包含**：候选 IP 靠运行时向本机 mosdns 实时解析，延迟靠 TCP 直连探测；工具与种子固化在镜像内，**不存在"拉不下来"**。
- **默认国内优先**：未知域名先走国内 DoH，超时/失败才走国外；GFW 清单强制走国外。
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
scheduler/    调度 + 五路优选 + 公共函数 + DNS/探测库
ui/           控制台后端(server.py) + 前端(static/index.html)
versions.env  上游版本锁定
known-good.env 最后一份通过自检的组合
docker-entrypoint.sh  渲染配置 / 种入账号 / 拉起三进程
```

## 隐私

仓库只含通用代码、配置模板与公开种子；优选结果、域名数据、账号密码全部只在你的 `/data` 卷，永不进镜像或 GitHub。
