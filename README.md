# CFAutoTest

批量筛选 Cloudflare 优选 IP 中「延迟低、下载快」的节点，结果输出为 `result.txt` / `result.csv`，并自动上传到 GitHub Release。

## 工作原理

```
下载节点列表  →  解析去重  →  TLS 握手探测(带 SNI)  →  延迟筛选
    →  逐国下载测速  →  写 txt/csv  →  上传 GitHub Release
```

关键点：

- **延迟阶段就做完整 TLS 握手**（携带 `server_hostname`），而不是裸 TCP 连接。这样能提前淘汰「端口通但不认这个域名」的假节点，实测约 36% 的候选在这一步就失败。
- **测速阶段带提前终止**：样本 25MB，若在 `25 ÷ 阈值 × 1.05` 秒内没下完，说明不可能达标，立即放弃，不必等满。
- **低速兜底**：某国全部候选测完后仍凑不满配额，就从 `[低速阈值, 主阈值)` 区间按速度降序补齐。
- **结果校验**：全部测完后若入选总数少于 `MIN_TOTAL`（默认 7），视为本轮结果不可信，**不覆盖 Release**，直接报错退出，保留上一轮的有效结果。

## 输出

### result.txt

每行一个节点，按速度降序：

```
103.238.129.171:443#JP 103.238.129.171 9.71
152.175.1.189:443#HK 152.175.1.189 9.21
```

格式：`ip:port#国家码 ip 速度(MB/s)`

### result.csv

| 列 | 说明 |
|---|---|
| ip / port / tag | 节点信息 |
| ping_ms | TLS 握手耗时（毫秒） |
| speed_MBps | 下载速度（MB/s） |
| bytes_MB | 实际下载量 |
| status | 见下表 |
| qualified | `Y` 主阈值达标 / `L` 低速兜底 / `N` 未入选 |

`status` 取值：

| 值 | 含义 |
|---|---|
| `ok` | 下完 25MB 样本 |
| `early_stop` | 超过提前终止时间，已放弃 |
| `partial` | 连接提前断开，只下了一部分 |
| `ttfb_timeout` | 握手成功但等不到响应头 |
| `ping_fail` | TLS 握手失败 |
| `latency_skip` | 握手成功但超过延迟阈值 |
| `country_quota` | 该国配额已满，未测 |

## 配置

脚本顶部的「可配置参数」区：

| 参数 | 默认值 | 说明 |
|---|---|---|
| `COUNTRIES` | `["JP","HK","SG","TW"]` | 参与筛选的国家码 |
| `PORT` | `443` | 只测这个端口的节点 |
| `LATENCY_MAX_MS` | `800` | TLS 握手耗时上限。**注意这是 TLS 不是 TCP**，比纯 RTT 大 3–5 倍 |
| `PING_TIMEOUT_MS` | `2000` | 单次握手超时 |
| `PING_ATTEMPTS` | `3` | 每个 IP 试几次，取最小值 |
| `PING_CONCURRENCY` | `50` | 握手并发。太高会让测量值虚高（弱 CPU 排队） |
| `SPEED_MIN_MBPS` | `7.0` | 主阈值 |
| `LOW_SPEED_MIN_MBPS` | `5.0` | 低速兜底阈值 |
| `MAX_PER_COUNTRY` | `5` | 每国凑够几个就切下一个 |
| `MIN_TOTAL` | `7` | 总数低于该值视为本轮失败：不上传 Release，直接报错退出 |
| `SPEED_MAX_BYTES` | `25 MB` | 单次测速样本大小 |
| `VERIFY_TLS` | `True` | 是否校验证书 |

## 环境变量

| 名称 | 必填 | 说明 |
|---|---|---|
| `GITHUB_REPO` | 否 | `owner/repo`，如 `4evergr8/CFAutoTest`。不填则跳过上传 |
| `GITHUB_TOKEN` | 否 | 有仓库 Contents 读写权限的 PAT |
| `RELEASE_TAG` | 否 | Release 标签，默认 `latest` |
| `RELEASE_NAME` | 否 | Release 标题 |
| `PROXY` | 否 | 下载列表和上传 API 的代理，格式 `192.168.123.100:7890` |

**代理行为**：先走代理，失败再直连，各尝试一次，都不行就报错退出。

**Token 权限**：经典 PAT 勾 `repo`（私有）或 `public_repo`（公开）；Fine-grained PAT 把 `Contents` 设为 Read and write。

上传使用固定 tag，所以下载地址永久不变，内容每次覆盖：

```
https://github.com/4evergr8/CFAutoTest/releases/download/latest/result.txt
```

## 本地运行

```bash
python node_speedtest.py                  # 全量
python node_speedtest.py --limit 20       # 只测前 20 个，用于试跑
```

只依赖 Python 标准库，Python 3.8+ 均可，无需安装任何第三方包。

## 青龙部署

1. 脚本上传到 `/ql/data/scripts/`，与青龙的 `notify.py` 同目录
2. 环境变量里加上 `GITHUB_REPO`、`GITHUB_TOKEN`（可选 `PROXY`）
3. 新建任务，命令 `task node_speedtest.py`
4. 定时规则 `0 2,7,12,17,22 * * *`（每 5 小时一次，避开 05、06 点）

脚本头部已按青龙规范写好：

```
cron: 0 2,7,12,17,22 * * *
new Env('CF 节点测速')
```

用「订阅」方式添加仓库时会自动建任务，前提是面板里开了 `AutoAddCron`。

## 通知

整个流程包在一个 `try` 里，**只有出错时才推送**，成功不打扰。

推送走青龙的 `notify.py`（`from notify import send`），渠道在 `/ql/data/config/config.sh` 里配。注意这跟面板的「通知设置」是两套东西：

- 面板「通知设置」→ 青龙任务结束时的系统通知
- `config.sh` 里的变量 → 脚本主动调 `notify.py` 时用

脚本出错会 `sys.exit(1)`，青龙会判定任务失败，所以即使不配 `config.sh`，也能收到「任务失败」的系统通知。

## 已知限制

- 节点列表每次都会轮换，反代 IP 存活周期短，不能缓存结果
- 列表源站速度不稳定，偶尔会下载失败（脚本会先代理后直连各试一次）
- 单国候选数量差异大（JP/SG 各 400+，TW 只有 20 左右），小池子可能凑不满配额
