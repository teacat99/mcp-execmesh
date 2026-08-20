# Remote Executor MCP (`mcp-execmesh`)

[![CI](https://github.com/teacat99/mcp-execmesh/actions/workflows/ci.yml/badge.svg)](https://github.com/teacat99/mcp-execmesh/actions/workflows/ci.yml)
[![Docker](https://github.com/teacat99/mcp-execmesh/actions/workflows/docker.yml/badge.svg)](https://github.com/teacat99/mcp-execmesh/actions/workflows/docker.yml)

Remote Executor MCP 是一个轻量级、低内存占用、高安全性的 AI 远程执行网关（MCP Server）。它采用 **控制面（MCP Gateway）与数据面（Remote Target）分离** 的架构，允许 AI 客户端（如 ChatGPT Developer Mode、Cursor 等）通过标准 MCP Streamable HTTP 协议安全地控制配置的目标主机，执行命令、流式传输文件并管理异步长任务。

---

## 核心设计与特性

1. **极致轻量与低内存优化**：
   - 面向 **128MB RAM** VPS 与轻量容器环境深度设计；
   - 彻底禁止 `io.ReadAll` 与无界 `bytes.Buffer`；
   - 同步命令输出与文件传输均受严格的定长缓冲（默认 64KiB）与流式中继保护，常驻内存小于 15MB RSS。
2. **凭据隔离与 Target 路由**：
   - AI 模型只能通过预设的 `target` ID 访问主机，禁止动态传入任意 IP 或 SSH 凭据；
   - 密钥与密码通过独立的 Secret 文件加载，绝不在 Tool 参数、返回值或审计日志中泄露。
3. **严格主机安全校验**：
   - 默认开启 SSH `known_hosts` 强校验，有效防御中间人（MITM）攻击。
4. **标准 MCP 协议支持**：
   - 基于官方 Go SDK (`github.com/modelcontextprotocol/go-sdk`) 实现；
   - 暴露标准 Streamable HTTP `/mcp` 端点及 `/healthz`、`/readyz` 健康检查。
5. **完善审计日志**：
   - 结构化记录每条指令的执行人、目标、命令 SHA256、耗时、退出码与返回状态。

---

## 架构概览

```text
ChatGPT / Cursor / MCP Client
            │
            │ MCP Streamable HTTP (JSON-RPC)
            ▼
┌───────────────────────────────────────────────┐
│       Remote Executor MCP (mcp-execmesh)      │
│                                               │
│  Target Registry       SSH Connection Pool    │
│  Limited Output Buffer Auth / Policy / Audit  │
└───────────────────────┬───────────────────────┘
                        │
                 SSH / SFTP (Stream)
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
     test-01         build-01        prod-01
```

---

## 支持的 MCP 工具集

| 工具名称 | 功能描述 | Read-Only | Destructive | 阶段 |
|---|---|---|---|---|
| `targets_list` | 获取所有已配置且允许操作的 Target 列表及能力概览 | Yes | No | M1 |
| `target_info` | 查询指定 Target 的详细能力、限制与运行环境配置 | Yes | No | M1 |
| `exec` | 在指定的 Target 上同步执行短命令（含超时与有界截断） | No | Yes | M1 |
| `exec_start` | 在远程 Target 启动后台异步任务（返回有序 `job_id`） | No | Yes | M2 |
| `job_status` | 查询异步任务执行状态、PID、退出码及输出统计 | Yes | No | M2 |
| `job_output` | 分页分段流式读取任务的 stdout 或 stderr 日志 | Yes | No | M2 |
| `job_cancel` | 安全终止指定的远程后台任务进程（SIGTERM / SIGKILL） | No | Yes | M2 |
| `file_push` | 兼容 OpenAI fileParams，从 URL 流式下载并直写 SFTP（支持 SHA256 校验与原子重命名） | No | Yes | M3 |
| `file_stat` | 查询远程文件/目录状态（大小、类型、权限、修改时间） | Yes | No | M3 |
| `file_hash` | 计算远程文件的密码学哈希（SHA256, SHA1, MD5） | Yes | No | M5 |
| `file_pull_prepare` | 生成单次有效下载 Ticket，返回公网 HTTPS `download_url`（非 Token 字段） | Yes | No | M5 |
| `target_add` | **Admin**：新增 Target 配置 | No | Yes | Admin |
| `target_update` | **Admin**：更新 Target 配置 | No | Yes | Admin |
| `target_enable` | **Admin**：启用 Target | No | No | Admin |
| `target_disable` | **Admin**：禁用 Target | No | No | Admin |
| `target_remove` | **Admin**：移除 Target | No | Yes | Admin |
| `target_test` | **Admin**：测试 Target SSH 连通性 | Yes | No | Admin |
| `credentials_list` | **Admin**：列出凭据引用（不含明文） | Yes | No | Admin |
| `known_host_info` | **Admin**：查询 known_hosts 条目 | Yes | No | Admin |
| `known_host_add` | **Admin**：添加 SSH 主机公钥 | No | Yes | Admin |
| `known_host_remove` | **Admin**：移除 SSH 主机公钥 | No | Yes | Admin |
| `config_reload` | **Admin**：热重载配置文件 | No | No | Admin |

> **Admin 工具**仅对具备 Admin Principal 的身份可用（Bearer Admin Token 或带 Admin scope 的 Capability URL）。普通 ChatGPT/Cursor 执行 Principal 无法调用。

---

## 快速上手

### 1. 编译构建

```bash
# 本地编译
go build -ldflags="-s -w" -o bin/remote-mcp ./cmd/remote-mcp

# 校验配置文件
./bin/remote-mcp -config configs/config.example.yaml -validate-only
```

### ChatGPT Capability URL

```bash
./bin/remote-mcp auth capability create \
  --config /etc/remote-mcp/config.yaml \
  --id chatgpt-main \
  --scope targets:read --scope exec:run \
  --scope jobs:read --scope jobs:write \
  --scope files:read --scope files:write \
  --target '*'
```

将打印一次的 URL 填入 ChatGPT Developer Mode，身份验证选择 **No Authentication**。Cursor 继续使用 `https://host/mcp` + Bearer。

Capability URL 必须当作密码，切勿提交到 Git 或写入日志。

### 2. 使用 Docker 运行

**拉取公开镜像（GitHub Container Registry）：**

```bash
docker pull ghcr.io/teacat99/mcp-execmesh:latest
docker pull ghcr.io/teacat99/mcp-execmesh:1.0.0

docker run --rm -p 8080:8080 \
  -v "$(pwd)/configs/config.example.yaml:/etc/remote-mcp/config.yaml:ro" \
  -v "$(pwd)/configs/known_hosts.example:/etc/remote-mcp/known_hosts:ro" \
  ghcr.io/teacat99/mcp-execmesh:latest
```

**本地 compose 构建：**

```bash
docker compose up -d
```

### 3. 健康检查

```bash
curl http://127.0.0.1:8080/healthz
# {"status":"ok"}

curl http://127.0.0.1:8080/readyz
# {"status":"ok","targets_count":1}
```

### 4. 文件下载（`file_pull_prepare`）

远程 MCP Client（如 ChatGPT）通过 `file_pull_prepare` 获取 **一次性 HTTPS 下载链接**，从 Target 拉取文件。须正确配置公网地址：

```yaml
server:
  public_base_url: "https://mcp.example.com"   # 必须是 Client 可达的 HTTPS 地址，不能用 127.0.0.1
```

**要点：**

- Tool 返回 `download_url`（形如 `https://mcp.example.com/files/{ticket}`），**不**再返回独立 `token` 字段
- Ticket 单次有效、有 TTL（默认 900s，见 `runtime.default_download_ticket_ttl`）
- 反向代理须对 `/files/` 关闭 buffering，并配置 access log 脱敏（见 [deploy/README.md — §4 反向代理](deploy/README.md)）
- 生产环境完整配置见 **[生产部署指南](deploy/README.md)**（HTTPS、Nginx、`public_base_url`、安全清单）

---

## 生产部署

请参阅 **[deploy/README.md](deploy/README.md)**：Docker Compose、目录权限、Nginx HTTPS、Systemd、监控探针与维护者发版流程。

---

## 发布与镜像（维护者）

公开 Docker 镜像 **仅由 public 仓库**（[`teacat99/mcp-execmesh`](https://github.com/teacat99/mcp-execmesh)）的 GitHub Actions 自动构建并推送到 GHCR。私有开发仓用于日常开发与本地镜像测试，不自动发布。

| 镜像 | 说明 |
|---|---|
| `ghcr.io/teacat99/mcp-execmesh:latest` | `main` 分支最新构建 |
| `ghcr.io/teacat99/mcp-execmesh:1.0.0` | semver tag 发版（示例） |

**Private → Public 同步发版：**

```bash
# 1. 在 private 仓 master 完成开发与测试
go test ./...

# 2. （可选）打 semver tag
git tag v1.0.0

# 3. 同步到 public 仓（排除 .cursor/ 等）
./scripts/sync-public.sh

# 或显式指定 tag（不必先在 private 打 tag）
# PUBLIC_TAG=v1.0.0 ./scripts/sync-public.sh

# 预览 sync 与 tag 操作（不 push）
# DRY_RUN=1 ./scripts/sync-public.sh
```

同步后 public 仓 `main` push（及 `v*` tag push）会自动触发 Docker workflow。本地手动测试镜像：

```bash
docker build -f deploy/Dockerfile.standalone -t mcp-execmesh:dev .
docker run --rm mcp-execmesh:dev -version
```

版本变更见 [CHANGELOG.md](CHANGELOG.md)。

---

## 许可证与安全

本项目采用 [MIT License](LICENSE)。

请参阅 [SECURITY.md](SECURITY.md) 了解详细安全规范与配置要求。
