# GitLab Feishu Relay

一个零第三方依赖的单文件 Go Webhook 中转服务，将 GitLab 项目与群组事件转换为清晰的飞书消息卡片。支持 GitLab 19.1 事件、飞书签名、可选 Token 校验、重试、去重、健康检查与调试日志。

A dependency-free, single-file Go webhook relay that turns GitLab project and group events into readable Feishu cards. Supports GitLab 19.1 events, Feishu signing, optional token validation, retries, deduplication, health checks, and debug logs.

## Features

- 独立解析 GitLab 19.1 各类 Webhook Payload，避免不同事件的同名字段类型冲突。
- 为 Push、Merge Request、Pipeline、Job、Note、Deployment 等事件生成专属飞书卡片。
- 支持项目与群组 Webhook，包括 Issue、Wiki、Release、Milestone、Token 到期和漏洞事件。
- 支持飞书 HMAC-SHA256 签名及可选的 GitLab Secret Token 校验。
- 提供有限重试、事件 UUID 内存去重、请求体限制和优雅退出。
- 仅使用 Go 标准库，全部服务代码位于一个 `main.go` 文件中。

## Requirements

- Go 1.22 或更高版本（使用新版 `http.ServeMux` 路由语法）。
- 一个飞书群自定义机器人 Webhook。
- 一个可配置 Webhook 的 GitLab 项目或群组。

## Build

```bash
go build -o gitlab-feishu-relay main.go
```

## Run

最小配置：

```bash
FEISHU_WEBHOOK='https://open.feishu.cn/open-apis/bot/v2/hook/xxx' \
./gitlab-feishu-relay
```

推荐的生产配置：

```bash
ADDR='0.0.0.0:8080' \
GITLAB_TOKEN='replace-with-a-random-secret' \
FEISHU_WEBHOOK='https://open.feishu.cn/open-apis/bot/v2/hook/xxx' \
FEISHU_SECRET='replace-with-the-feishu-signing-secret' \
MAX_COMMITS=5 \
RETRIES=2 \
./gitlab-feishu-relay
```

## Configuration

| Environment variable | Required | Default | Description |
| --- | --- | --- | --- |
| `FEISHU_WEBHOOK` | Yes | — | 飞书自定义机器人的 Webhook 地址。 |
| `FEISHU_SECRET` | No | — | 飞书机器人签名密钥；设置后自动附加时间戳和签名。 |
| `GITLAB_TOKEN` | No | — | GitLab Secret Token；设置后校验 `X-Gitlab-Token`。 |
| `ADDR` | No | `:8080` | HTTP 监听地址，例如 `127.0.0.1:9000`。 |
| `MAX_COMMITS` | No | `5` | Push 卡片展示的最大提交数，范围为 0–20。 |
| `RETRIES` | No | `2` | 飞书投递失败后的重试次数，范围为 0–5。 |
| `DEBUG` | No | `false` | 设置为 `1`、`true`、`yes` 或 `on` 时记录 400 请求正文和解析错误。 |
| `SELF_TEST` | No | `false` | 设置为 `1` 时运行内置事件解析与卡片测试后退出。 |

`DEBUG` 会记录无效请求的正文，可能包含项目内部信息，仅建议在排障期间短暂启用。它不会记录请求头或 GitLab Token。

## GitLab Setup

在项目或群组的 Webhook 设置中填写：

```text
URL: http(s)://relay.example.com/webhooks/gitlab
Secret token: 与 GITLAB_TOKEN 相同；未使用时留空
Custom webhook template: 留空
```

按需启用事件，然后使用 GitLab 的 Test 功能验证投递。中转服务需要接收 GitLab 原始完整 Payload，因此不要配置 Custom webhook template。

## Feishu Setup

1. 在目标飞书群中添加自定义机器人。
2. 将机器人 Webhook 地址设置为 `FEISHU_WEBHOOK`。
3. 如果机器人启用了签名校验，将签名密钥设置为 `FEISHU_SECRET`。
4. 如果启用了关键词校验，建议添加 `GitLab` 关键词。

飞书自定义机器人限制单次请求体不超过 20 KB。服务会限制提交展示数量，并在内置测试中检查卡片大小。

## Endpoints

| Method | Path | Success response | Purpose |
| --- | --- | --- | --- |
| `POST` | `/webhooks/gitlab` | `204 No Content` | 接收 GitLab Webhook 并投递飞书卡片。 |
| `GET` | `/healthz` | `204 No Content` | 健康检查。 |

## Supported Events

- Push and tag push
- Issues and work items
- Comments/notes on commits, merge requests, issues, and snippets
- Merge requests
- Wiki pages
- Pipelines and jobs
- Deployments
- Feature flags
- Releases and milestones
- Emoji awards
- Project/group access token and deploy token expiry
- Vulnerabilities
- Group member, project, and subgroup lifecycle events

事件会先根据 `object_kind`、`event_name` 和 `event_type` 识别，再使用对应的独立结构二次解析。卡片会根据动作、状态或严重等级选择颜色，并提供相关 GitLab 页面链接。

## Self-test

```bash
SELF_TEST=1 go run main.go
```

静态检查与编译：

```bash
gofmt -w main.go
go vet main.go
go build -o gitlab-feishu-relay main.go
```

## Security

- 推荐同时配置 `GITLAB_TOKEN` 和 `FEISHU_SECRET`。
- 未配置 `GITLAB_TOKEN` 时，应通过内网、防火墙、IP 白名单、mTLS 或反向代理保护入口。
- 不要把飞书 Webhook、签名密钥或 GitLab Token 提交到代码仓库。
- 内存去重不跨进程或重启持久化；多实例部署需要外部共享存储才能实现全局去重。

## License

MIT License. See [`LICENSE`](LICENSE).
