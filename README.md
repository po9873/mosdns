# MosDNS 优选一体机

基于 [mosdns](https://github.com/IrineSistiana/mosdns) v5 源码构建，集成 IP 优选与单账号 Web 控制台。
镜像内无第三方黑盒，运行时不下载可执行文件，所有上游版本由 `versions.env` 锁定。

## 特性

- **原版核心**：官方 v5 源码 `go build`，不修改解析逻辑，不引入闭源组件。
- **七路优选**：Cloudflare / Google 搜索 / Google 翻译 / GitHub / ghcr / TMDB / IMDb，串行调度，低配 CPU 亦可运行。
- **可用性校验**：不依赖 TCP 连通性，逐个执行 TLS 握手 + HTTPS 请求，按状态码、1034/1010/1020、证书、5xx 判定。
- **双栈**：IPv4 与 IPv6 分别排序后共同写入 hosts，单条失效自动切换。
- **分流**：国内 DoH 优先，失败转国外；国内应答须落在国内网段；GFW 清单强制走国外。
- **动态上游**：国内/国外 DoH 候选池定时扫描，连续不可用自动剔除，控制台可手动增删并即时测速。
- **控制台**：概况 / 监测 / 日志 / 配置 / 源五个页面，亮色、暗色、跟随系统三种主题，适配移动端。
- **清单自更新**：国内 IP 段、Cloudflare / Google / Fastly 官方网段每日更新，界面显示条目数与来源。
- **诊断**：IP 归属查询、端口连通性（ICMP + TCP + UDP）、域名解析实测；支持企业微信 / 钉钉 / 飞书机器人通知。
- **数据隔离**：运行时只写 `/data`，镜像与仓库不含账号、密钥或运行数据。

## 快速开始

### 前置条件

| 项 | 要求 |
|---|---|
| 系统 | Linux x86_64 / arm64（群晖、Unraid、PVE、OpenWrt-x86 均可）；Windows / macOS 使用 Docker Desktop |
| Docker | 20.10 及以上，含 Compose v2（`docker compose version` 有输出） |
| 端口 | `53/udp`、`53/tcp`（DNS）与 `80/tcp`（控制台）空闲 |
| 目录 | 一个持久化目录挂载至 `/data`，容器只写该目录 |

53 端口被占用是最常见的启动失败原因。确认命令：

```bash
sudo ss -lunpt | grep :53
```

Ubuntu / Debian 默认由 `systemd-resolved` 占用，处理方式见「常见问题」。

### 方式一：docker run

```bash
docker run -d --name mosdns --restart unless-stopped \
  -p 53:53/udp -p 53:53/tcp -p 80:80 \
  -v /opt/mosdns:/data \
  -e TZ=Asia/Shanghai \
  po9873/mosdns:latest
```

### 方式二：docker compose（推荐）

```bash
mkdir -p /opt/mosdns && cd /opt/mosdns
cat > docker-compose.yml <<'YAML'
services:
  mosdns:
    image: po9873/mosdns:latest
    container_name: mosdns
    restart: unless-stopped
    ports:
      - "53:53/udp"      # DNS
      - "53:53/tcp"      # DNS
      - "80:80"          # 控制台
    volumes:
      - ./data:/data
    environment:
      TZ: Asia/Shanghai
      # PREF_UI_PORT: "80"     # 控制台端口，默认 80
      # PREF_DNS_PORT: "53"    # DNS 端口，默认 53
YAML
docker compose up -d
docker compose logs -f
```

### 端口

| 端口 | 协议 | 用途 | 必需 |
|---|---|---|---|
| 53 | UDP + TCP | DNS 服务 | 是 |
| 80 | TCP | 控制台（`PREF_UI_PORT` 可改） | 是 |
| 9099 | TCP | 内部 API，仅监听 `127.0.0.1`，不映射 | 否 |

镜像默认具备 `NET_RAW`（诊断页 ICMP 探测所需）。若编排配置了 `cap_drop: ALL`，或 NAS 限制了容器能力，
需补 `cap_add: [NET_ADMIN, NET_RAW]`。

### 数据目录

首次启动自动生成全部文件，无需预先准备：

```
/data
├── config.yaml                # 渲染后的 mosdns 配置（自动生成，不建议手工修改）
├── prefs/                     # 控制台写入的配置，重渲染以此为准
├── doh_local_candidates.txt   # 国内 DoH 候选池
├── doh_remote_candidates.txt  # 国外 DoH 候选池
├── china_ip.txt               # 国内 IP 段（可自动更新）
├── auth.json                  # 控制台账号
├── mosdns.log / pref.log      # 日志（自动轮转）
└── …                          # 其余为候选池、缓存、黑名单等运行时状态
```

备份与迁移均以该目录为单位；重置方式为停止容器、清空目录、重新启动，账号回到 `admin/admin`。

### 验证

```bash
curl -I http://127.0.0.1/                  # 期望 200
nslookup www.qq.com 127.0.0.1              # 期望返回国内 IP
nslookup github.com 127.0.0.1              # 期望返回 GitHub IP
docker logs mosdns | tail -20              # 应出现 UI listening on 0.0.0.0:80
```

宿主机启用系统代理时，`curl 127.0.0.1` 可能被代理接管并返回 502，可加 `--noproxy '*'` 复测。

### 首次登录

浏览器访问 `http://<服务器IP>/`，初始账号密码为 `admin` / `admin`，登录后强制修改。

未完成改密前，后端除登录、改密、状态查询外的接口一律返回 `403`。

忘记密码：停止容器，删除 `/data/auth.json`，重新启动，账号恢复为 `admin` / `admin`。

## 升级与回退

`latest` 标签仅在推送代码或手动触发构建时更新，与上游项目发版无关，因此 `pull` 不会引入未验证的版本。

```bash
docker compose pull && docker compose up -d
```

生产环境建议固定到不可变标签，格式为 `<mosdns版本>-<日期>-<commit>`，取值见对应 Actions 构建记录：

```yaml
    image: po9873/mosdns:v5.3.4-20260101-abc1234
```

回退方式为将标签改回上一版本后重新 `up -d`。`known-good.env` 记录上一份通过自检的上游版本组合。

## 配置项

| 变量 | 默认 | 说明 |
|---|---|---|
| `PREF_UI_PORT` | `80` | 控制台端口 |
| `PREF_DNS_PORT` | `53` | DNS 端口 |
| `PREF_STABLE_HOURS` | `6` | 优选稳定窗口（小时）：窗口内现有 IP 可用且不慢时跳过全量重探；`0` 表示每轮全量重扫 |
| `PREF_STABLE_TTFB_MS` | `1200` | 判定变慢的响应时间阈值（ms），超过则重新优选 |
| `PREF_STABLE_SPEED_KBPS` | `200` | 吞吐下限（KB/s），低于该值视为变慢；`0` 表示不参考吞吐 |
| `PREF_THREADS` | 空 | 优选并发数；留空按 CPU 与虚拟化环境自适应 |
| `PREF_CACHE_SIZE` | `8192` | DNS 缓存条数上限，超出按 LRU 淘汰 |
| `PREF_WATCHDOG_SEC` | `180` | 换 IP 巡检间隔初始值，登录后可在「配置 → 定时任务」修改，立即生效 |
| `PREF_BAD_TTL_HOURS` | `6` | 坏 IP 冷却时长（小时） |
| `PREF_POOL_MAX` | `4000` | 候选池上限 |
| `PREF_SUB_TTL_DAYS` | `14` | 候选 IP 多少天未再出现即清理 |
| `PREF_CIDR_SAMPLE` | `6` | 每个官方 CIDR 的采样数量 |
| `PREF_SRC_DISABLE_AFTER` | `1` | 非官方源连续失败多少次后处理 |
| `PREF_SRC_AUTO_DELETE` | `1` | 达到阈值直接删除源；`0` 表示仅停用保留 |

## 定时任务

全部位于「配置 → 定时任务」，保存即生效，无需重启。

| 任务 | 默认 | 说明 |
|---|---|---|
| 优选 | 每 60 分钟 | 一轮结束后的等待时间，可整体暂停 |
| 国内 IP 段更新 | 每 24 小时 | 拉取最新网段，失败保留旧清单 |
| 源定时拉取 | 每 6 小时 | 拉取启用中的源，补充候选池 |
| 源定时体检 | 每天 05:00 | 复检所有源可用性，非官方源连续失败到阈值即删除 |
| 源自动发现 | 关闭 / 每天 04:00 | 搜索新的公开源并试测 |
| 上游 DoH 扫描 | 每 60 分钟 | 全量测速候选池，新可用项收编，在用项失效则替换（手动模式下仅提示） |
| 生效 IP 巡检 | 每 180 秒 | 在用 IP 触发 1034 / 证书错误 / 5xx 时立即撤下并替换 |

间隔单位、周期（1~12 小时 / 每天 / 每周）与执行时点（0~23 点）均可调整，每行显示上次与下次执行时间。
仅缓存上限与日志轮转属于引擎启动参数，需修改环境变量后重启。

## 控制台

| 页面 | 内容 |
|---|---|
| 概况 | 各路当前 IP、延迟与吞吐，上游 DNS 及厂商，缓存与日志用量，分流清单状态 |
| 监测 | 上游逐条测速（国内 / 国外分列），域名解析与实际打开验证，实时解析域名列表 |
| 日志 | 引擎日志与调度日志，可筛选与清空 |
| 配置 | 上游 DNS、定时任务、每路保留数量、稳定模式参数、自动重载开关 |
| 源 | IP 源管理、候选池明细与来源计数、分流清单、换 IP 记录、源订阅 |

### 实时解析域名

读取 mosdns `query_summary` 日志，按域名去重后完整列出当前在解析的域名，每 5 秒刷新，框内滚动、表头吸顶。
每行包含时间、域名、记录类型、应答 IP、线路、响应耗时、状态与客户端。面板自身发起的环回查询不计入统计。

「来源」一栏说明这个答案是谁给的：

| 显示 | 含义 |
|---|---|
| `Cloudflare` / `Google 搜索` / `Google 翻译` / `GitHub` / `ghcr` / `TMDB` / `IMDb` | 由该路优选写入 hosts，不经过上游 DNS |
| `国内 · 阿里 DNS` | 由国内上游链解析，名称为该链当前在用的服务 |
| `国外 · ControlD` | 由国外上游链解析（GFW 清单命中的域名走这条） |
| `国内优先 · 阿里 DNS` | 不在两份域名清单中，先走国内、失败转国外 |

判断顺序与 `config.yaml` 中的 `main_sequence` 一致。后面的浅色小字为应答 IP 的归属
（按 `/data/cdn_ranges.txt` 与镜像内置网段库合并判定），用于判断实际落地位置。

## 优选机制

### 七路与对应域名

| 路 | 写入 hosts 的域名 |
|---|---|
| Cloudflare | `cloudflare.com`、`theaudiodb.com`、`www.theaudiodb.com`、`lrclib.net`、`anilist.co`、`graphql.anilist.co` |
| Google 搜索 | `google.com`、`www.google.com`、`www.gstatic.com`、`ssl.gstatic.com` 及 Gmail / Drive / Docs 等 Google 服务域名 |
| Google 翻译 | `translate.google.com`、`translate.googleapis.com` |
| GitHub | `github.com` |
| ghcr | `ghcr.io`、`pkg-containers.githubusercontent.com`、`raw.githubusercontent.com`、`objects.githubusercontent.com` |
| TMDB | `www.themoviedb.org`、`api.tmdb.org`、`api.themoviedb.org`、`image.tmdb.org` |
| IMDb | `www.imdb.com`、`m.media-amazon.com`、`m.imdb.com`、`s.media-imdb.com`、`ia.media-imdb.com` 等 |

同一路内的域名共用同一批边缘节点才会合并（Cloudflare、CloudFront 的任意域名可互用）。
分属不同服务的不共用：`github.com` 与 `raw.githubusercontent.com` 分属两路，各用各自 IP。
附加域名写入前逐 IP 校验，未通过者本次不映射。

### 判定标准

每个候选均发送真实 HTTPS 请求（SNI 与 Host 均为目标域名），记录两项指标：

- **响应时间**：连接建立至收到首字节的耗时（TTFB，含 TCP、TLS、请求与后端处理）
- **吞吐**：读取响应体估算下载速度（KB/s），响应体小于 4KB 时不显示

各路判定条件按路配置（`scheduler/*_pref.sh` 中的 `PREF_PROBE_*`）：

| 路 | 请求 | 判定 |
|---|---|---|
| Cloudflare / GitHub / ghcr | `GET /` | 状态码正常，无 1034 / 证书错误 / 5xx |
| Google 搜索 | `GET /`（`www.google.com`） | 正文含 `<title>Google` |
| Google 翻译 | `GET /`（`translate.google.com`） | 正文含 `translate`（该页为纯 JS 壳，无 `<title>`） |
| TMDB / IMDb | `GET /` | 证书与目标域名匹配且有响应；两个站点对未识别请求返回 403 / 202，不按正文判定 |

仅凭状态码不足以判定：Google 前端对未知路径返回 404 或空白 200，Cloudflare 对源站故障返回 1034，
均表现为握手成功但页面不可用。

### 失败原因

| 标记 | 含义 |
|---|---|
| `CF 1034` | Cloudflare 无法解析源站，该 IP 不可用 |
| `CF 1016` / `1020` / `1015` / `1023` | 源站 DNS 不存在 / 被防火墙拒绝 / 限速 / 主机不可达 |
| `CF 10xx`（其他） | Cloudflare 节点侧其他错误，同样视为不可用 |
| `证书错` | 证书不匹配或已过期：被劫持，或 SNI 与 IP 不属于同一站点 |
| `HTTP 5xx` | 源站或中间层故障（500 / 502 / 503 / 504） |
| `超时` | 连接或响应超时，允许降级使用并标记「未校验」 |
| `连不上` | 连接重置或 TLS 握手失败 |

明确不可用（1034 / 证书 / 5xx）的 IP 立即拉黑并替换，冷却期内不再使用；
仅超时的 IP 可降级使用并标记「未校验」；候选全部不可用时撤下该路 hosts，域名回退上游解析，不写入已知坏 IP。

### 每路保留数量

1. **取最快的一批**：以该路最快 IP 的响应时间为基准，不超过其 1.5 倍者入选，最多保留 N 个（默认 3）。
2. **不足则补备胎**：入选数量低于「最少保留」（默认 3）时，从历史验证通过的候选池补齐，标记为「备胎」。
   备胎本轮不复测，主力失效时由守护进程接替。

ghcr、GitHub 等路径的可用地址天然稀少：Azure `20.27.176~178` 共 762 个地址中仅 `20.27.177.117` 持有该域名证书，
`140.82.112.0/20` 中仅每个 /24 的第 33、34 号地址带 `*.ghcr.io` 证书。单轮常只选出 1~2 个，
保留备胎可将失效切换时间从数分钟降至秒级。这类入口的准确清单维护在 `config/seeds/ghcr.txt`，
种子 IP 无条件进入校验环节，不因排序靠后而丢弃。

### 稳定模式

`stable_hours` 默认 6 小时。每轮先复检当前在用 IP：

1. 对每个在用 IP 发送两次真实 HTTPS 请求，取较优结果；
2. 全部不可用（1034 / 证书 / 5xx / 超时）→ 先由守护进程换 IP，连续两轮均不可用才全量重探；
3. 可访问但响应超过 `PREF_STABLE_TTFB_MS`，或可信吞吐样本低于 `PREF_STABLE_SPEED_KBPS` → 全量重探；
4. 可用且不慢 → 本轮结束，窗口内不再全量扫描。

每项测两次是因为单次吞吐抖动明显（同一 IP 实测可出现 158 / 289 / 532 KB/s），单次结果不足以判定变慢。
响应体不足 32KB 的估算吞吐（界面显示为 `≈158 KB/s`）仅作参考，不参与判定。

### 失败退避

整层不可达的路径（特定网络至某批地址完全不通）全量探测耗时 2~3 分钟且结果恒为失败，域名走上游解析仍可正常使用。

- 连续失败按 **1h → 2h → 4h → 6h** 退避，期间跳过探测，日志记录「暂停优选」
- 一旦选出结果，退避立即清零
- 「立即测试」等价于 `PREF_FORCE=1`，忽略退避立即执行
- 界面显示「已暂停优选」并说明原因

### 1034 处理

| 层 | 触发时机 | 行为 |
|---|---|---|
| 优选时校验 | 每轮优选 | 真实 TLS + Host 请求，命中 1034 / 证书 / 5xx 立即从当前 hosts 摘除并重载，不等本轮结束 |
| 巡检看门狗 | 默认每 180 秒 | 对生效中的 IP 复检，发现 1034 即替换，并从候选池补入通过校验的 IP |

被拒绝的 IP 记入黑名单，冷却 `PREF_BAD_TTL_HOURS`（默认 6 小时）。
每次替换均记录原因、原 IP 与新 IP，可在「源 → 换 IP 记录」查看。
`/api/results` 输出前再次过滤，`cf1034` / `cert` / `http5xx` 一律剔除并在卡片注明剔除数量。

## 分流

`china_ip.txt` 是判断国内 IP 归属的依据，随 APNIC 分配每月变化，采用三层保障：

| 层 | 做法 |
|---|---|
| 构建时 | CI 从多个公开源下载完整清单固化进镜像，失败则使用仓库内置种子 |
| 运行时 | 默认每 24 小时检查一次，过期才下载；多源依次尝试，任一成功即原子替换 |
| 兜底 | 全部源失败时保留旧清单，仅在界面标记更新失败，不会清空 |

清单来源依次为：`17mon/china_ip_list` → `ispip.clang.cn` → `china-operator-ip` → APNIC 官方委派记录
（自动将 `1.0.1.0/256` 规范化为 `1.0.1.0/24`）。

mosdns 不监听清单文件变化，更新后需重载进程（约 1 秒）。程序自动执行，也可在控制台点击「重载引擎」。

## 上游 DoH

国内与国外上游均来自可编辑的候选清单，镜像仅在文件缺失时补齐默认版本，不覆盖已修改内容：

| 文件 | 用途 |
|---|---|
| `/data/doh_remote_candidates.txt` | 国外 DoH 候选（强制走国外解析时使用） |
| `/data/doh_local_candidates.txt` | 国内 DoH 候选（国内域名解析） |
| `/data/doh_watchlist.txt` | 观察名单：想试的新上游丢这里，探测可用后自动收编 |

每行格式为 `<DoH地址> [连接 IP]`，`#` 开头为注释：

```
https://dns.controld.com/dns-query 76.76.2.2
https://dns.nextdns.io/dns-query 45.90.28.1
```

- `连接 IP` 可选：TLS 的 SNI 仍使用域名，实际连接指定 IP（mosdns `dial_addr`），避免解析上游域名造成自循环；指定后跳过证书校验。
- 探测与运行时使用同一方式（POST + `application/dns-message`），要求返回 `rcode=0` 且有答案。
- 新增自定义上游：将地址写入对应文件并重启容器，启动探测会自动纳入。
- 网络环境存在 SNI 嗅探时，已知 DoH 主机名会被拦截，需改用不在黑名单中的地址。

### 观察名单（自动收编新上游）

候选清单是固定的，扫描只在这些条目里挑。想试一个清单外的新 DoH 服务，
把地址写进 `/data/doh_watchlist.txt` 即可，无需重启：

```
@remote https://dns.example.com/dns-query
https://dns.adguard-dns.com/dns-query 94.140.14.14
```

- 行首 `@local` / `@remote` 强制指定测试侧（国内/国外）；不写则按探测连接 IP 的归属自动分侧
  （落在国内 IP 段库的进国内池，其余进国外池——DoH 会应答任何域名，靠「哪侧通」分不出来）。
- 定时扫描每轮顺带探测名单，**连续 2 轮可用**的自动写入对应候选池、从名单移除，
  并与其它候选一起参与自动选用；一直不通的留在名单里，不影响任何东西。
- 收编动作记录在扫描日志（`/data/pref.log`）与扫描结果的 `watch` 字段中。

### 控制台配置上游

「配置 → 上游 DNS」中填写的每一条在保存前均实测一次（TLS 握手 + 实际 DNS 查询，校验 `rcode=0` 且有答案）。
不通过的条目不写入配置，并逐条列出原因（连不上 / 超时 / HTTP 非 200 / REFUSED / 查不到记录），
强制写入需二次确认。「仅测试」只测不存；「扫描候选池」立即执行一轮扫描，手动模式下新增项以「补入 N 条」呈现，确认后写入。

候选池明细列出每一条的状态：绿点为在用，橙点为探测通过但未启用（可一键加入，仍需「测试并保存」），
红点为不可用并附实际错误。表头汇总「在用 N 条 · 可用未启用 N 条 · 不通 N 条」。

### 扫描策略

候选池每 `doh_scan_min`（默认 60 分钟）全量测速：

| 模式 | 扫描结果 | 行为 |
|---|---|---|
| 自动（未手动配置） | 在用项失效或有更快项 | 自动切换至最快可用项并热重载，保留 `doh_keep`（默认 3）条 |
| 手动（控制台保存过配置） | 出现新可用项 | 配置不变，界面提示，点击「补入」后写入 |

- 候选池为 `/data` 用户清单与镜像内置清单的并集，升级引入的新候选自动并入，按整行去重（同一服务的多个 anycast 入口分别保留）。
- 选路分两轮：先保证不同服务各取最快一条，不足 `doh_keep` 条时再以同服务其他入口补齐。
- 在用项参与探测，仍可用则原样保留（含 `dial_addr`），不因单次扫描失败清空上游。
- 扫描器带文件锁与限频，运行于常驻线程，不占用优选主循环。
- 池内只包含实际提供 DoH 的地址。百度 DNS（`180.76.76.76`）、OneDNS（`117.50.10.10`）仅提供 UDP / DoT；
  `dns.pub` 的 DoH 位于 `120.53.53.53` / `1.12.12.21`，填写其普通 DNS 地址会持续无响应。
  旧版本 `/data` 中的此类错址由 `doh_config.py pool-fix` 在启动时统一修正。

## IP 源

候选 IP 由源清单与候选池共同提供：

| 类型 | 内容 | 说明 |
|---|---|---|
| 官方 | Cloudflare 官方 v4/v6 网段、Google 官方网段（`gstatic/ipranges/goog.json`）、GitHub 官方网段（`api.github.com/meta`） | 权威定义，仅提供网段，按固定步长采样后探测 |
| 第三方 | IPDB 精选 v4 / v6、IPDB 接口、IPDB 反代优选 | 社区维护，更新快、数量少 |
| 镜像 | jsDelivr、ghproxy | 与官方同源，用于 `raw.githubusercontent.com` 直连失败时兜底 |
| 自定义 | v4 / v6 清单地址；直接粘贴 IP 清单 | 提供地址则定时拉取，粘贴清单则直接入池 |

| 路 | 官方源 | 其他源 | 网段数 |
|---|---|---|---|
| Cloudflare | `cloudflare.com/ips-v4` + `ips-v6` | IPDB 精选 / IPDB 接口 / IPDB 反代优选 / jsDelivr / ghproxy | v4 15 段 / v6 7 段 |
| Google 搜索 | `gstatic.com/ipranges/goog.json` | GitHub 网段镜像、jsDelivr、Ponderfly 社区实测 IP 清单 | v4 132 段 / v6 16 段 + 8819 个实测 IP |
| Google 翻译 | 同上 | 同上 | 同上 |
| GitHub | `api.github.com/meta` | GitHub520、ineo6 hosts、jsDelivr | v4 254 段 / v6 6 段 |
| ghcr | `api.github.com/meta`（默认关闭，随机采样命中率约 0.8%） | `config/seeds/ghcr.txt`（10 个经 TLS 与 `GET /v2/` 验证的入口） | v4 254 段 / v6 6 段 |
| TMDB / IMDb | `ip-ranges.amazonaws.com/ip-ranges.json`，仅取 `service=CLOUDFRONT` | 无 | v4 214 段 / v6 34 段 |

官方源提供全量网段，社区清单提供当前可用的前端 IP，两者互补。官方网段采样后能连通的占比很低
（GitHub 实测 60 个候选仅 1 个可用），社区清单可直接补位。

### 社区清单的收录规则

社区 hosts 源为 `IP 域名` 格式，按域名白名单收录：仅保留本路使用的域名对应行，其余行整行跳过。
未按域名过滤时，候选池会混入其他站点地址（GitHub 池曾混入 Facebook 与微软地址），
导致优选抽到大量「TCP 可连但该域名不识别」的候选。纯 IP 行不受此限制。

### 手动添加源

「源」页右上角「+ 添加」支持两种方式：

1. 填写 v4 / v6 清单地址，选择归属路径，添加后立即拉取并显示条目数。
2. 选择「直接粘贴 IP 清单」，支持纯 IP、CIDR（`1.2.3.0/24`）与 hosts 格式（`1.2.3.4 github.com`），保存即入池。

两种方式均需选择归属路径，IP 只进入对应候选池。

候选池除订阅源外，还会回填每轮优选中的 DNS 实时解析结果、种子兜底 IP 与通过校验的 IP。
每张池子卡片下方按来源逐项列出名称与数量。

### 源体检

| 项 | 说明 |
|---|---|
| 频率 | 默认每天 05:00（「源」页可开关，也可立即执行） |
| 范围 | 所有源，含已停用的第三方源，仅检查是否可获取 IP，不写入池 |
| 官方源失败 | 仅标红，不自动停用 |
| 第三方 / 镜像失败 | 达到 `PREF_SRC_DISABLE_AFTER`（默认 1 次）即删除，并移除其带来的未验证 IP（验证通过者保留） |
| 恢复 | 已删除的内置源可通过「恢复内置源」补回；关闭「失效自动删除」则改为仅停用 |
| 通知 | 源失效时推送 `warn` 级别消息（企微 / 钉钉 / 飞书） |

定时拉取、源体检、源发现为三项独立任务：前者增量补充候选，中者复检连通性，后者仅试测未测过或上次失败的源。

### 源订阅

一行一个清单地址，同步引入的源默认不启用。支持两种格式：

```
[{ "name": "某社区镜像", "url_v4": "https://.../v4.txt", "url_v6": "https://.../v6.txt" }]
```
```
某社区镜像 | https://.../v4.txt | https://.../v6.txt
```

`GitHub 加速前缀` 可将 `raw.githubusercontent.com` 地址改写为加速地址（如 `https://ghfast.top`）。

## 重载与重启

mosdns 没有热重载接口，hosts 与清单变更需要通过重载进程生效。为减少中断：

- 一轮优选结束只判断一次，不按路逐个重启；
- 本轮结果与上轮完全一致时跳过重载（IP 通常数天不变，多数轮次不会触发）；
- 清单更新与优选结果合并为同一次重载；
- 重载由 supervisor 接管，中断约 1 秒；
- 可在「配置」页关闭「结果变化后自动重载引擎」，改为手动点击「重载引擎」。

## 缓存与日志

- **DNS 缓存**：按条数上限 LRU 淘汰（默认 8192 条），同时落盘至 `/data/cache.dump`，重启可复用。
- **一键清空**：「概况 → 缓存与日志」显示条数、上限、占比、累计命中、落盘体积与日志体积，可清空缓存并删除落盘副本。
- **查询日志**：超过 32MB 时仅保留尾部 8MB，也可手动清空。

## 常见问题

| 现象 | 处理 |
|---|---|
| 启动即退出，日志 `address already in use` | 53 端口被占用。用 `sudo ss -lunpt \| grep :53` 定位；`systemd-resolved` 可 `sudo systemctl disable --now systemd-resolved`，并将 `/etc/resolv.conf` 指向实际 DNS |
| 容器运行中，局域网设备无法解析 | 确认设备 DNS 指向本机，且宿主机防火墙放行 53/udp |
| 控制台打不开或返回 502 | 确认 80 端口已映射；宿主机启用代理时用 `curl --noproxy '*'` 验证；反向代理需透传 WebSocket |
| 使用 macvlan 时宿主机无法访问控制台 | 二层隔离的正常现象，局域网其他设备不受影响；宿主机访问需增加 macvlan 子接口或静态路由 |
| 国外上游全部失败、延迟很高 | 境外 443 受限，属网络环境问题；可仅保留国内上游 |
| 控制台页面空白 | 强制刷新；镜像版本过旧时执行 `docker compose pull` |

## 目录结构

```
config/               mosdns 配置模板、公开种子（cn/gfw 清单、优选候选种子）
scheduler/            调度、优选、公共函数、DNS 与探测库（lib/lists.py）
ui/                   控制台后端（server.py）与前端（static/index.html）
versions.env          项目版本与上游版本锁定
known-good.env        上一份通过自检的版本组合（回退参考）
docker-entrypoint.sh  渲染配置、初始化账号、启动进程
```

## 构建镜像

构建不依赖定时任务，也不探测上游发版。触发条件为：

- 推送至 `main` 且改动涉及 `scheduler/`、`ui/`、`config/`、`Dockerfile`、`docker-entrypoint.sh`、`versions.env`；
- 在 Actions 页面手动执行 Run workflow。

| 输入 | 作用 |
|---|---|
| `mosdns_version` | 仅本次构建使用的 mosdns 版本（留空取 `versions.env`，不写回仓库） |
| `push_latest` | 是否更新 `latest` 标签（默认更新；关闭则仅生成不可变标签） |

流程：读取 `versions.env` → 构建 → 自检门禁（控制台健康检查、mosdns 可执行、配置生成）。
自检未通过时不推送任何镜像，线上版本保持不变，避免出现标签为新版、内容为旧版的镜像。

`versions.env` 固定内置版本，更换时改该文件并推送即可，部署端再执行 `docker compose pull`。
自检只验证容器可启动，不保证跨版本的行为兼容，建议先跑不可变标签确认无异常。

产物：`ghcr.io/<用户名>/mosdns` 与 `docker.io/<用户名>/mosdns`，需配置 Secrets `DOCKERHUB_USERNAME`、`DOCKERHUB_TOKEN`。
每次构建同时生成不可变标签 `<mosdns版本>-<日期>-<commit>`。

## 版本

- `APP_VERSION`（`versions.env`）为项目自身版本，控制台侧栏「版本」显示此值，附构建日期与 commit
- 侧栏「引擎」单独显示内置 mosdns 版本，与项目版本区分
- `known-good.env` 记录上一份通过自检的上游组合

## 许可证

GPL-3.0。DNS 引擎为 [mosdns](https://github.com/IrineSistiana/mosdns)（GPL-3.0），本项目在其基础上构建，
完整条款见 `LICENSE`。

## 隐私

仓库仅包含通用代码、配置模板与公开种子。优选结果、域名数据、账号密码只存在于 `/data` 卷，不进入镜像或 GitHub。
