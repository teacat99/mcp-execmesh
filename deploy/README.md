# Remote Executor MCP (`mcp-execmesh`) 生产部署指南

本文档提供 `mcp-execmesh` 在生产环境（Linux VPS、Docker、Kubernetes、Systemd + 反向代理）中的标准部署配置与最佳实践。

---

## 目录
1. [Docker Compose 快速部署（推荐）](#1-docker-compose-快速部署推荐)
2. [生产环境目录与权限结构](#2-生产环境目录与权限结构)
3. [生产级安全配置清单](#3-生产级安全配置清单)
4. [反向代理与 HTTPS 配置 (Nginx)](#4-反向代理与-https-配置-nginx)
5. [Systemd 服务化部署](#5-systemd-服务化部署)
6. [监控与健康检查](#6-监控与健康检查)

---

## 1. Docker Compose 快速部署（推荐）

### 1.1 镜像构建
提供两种 Dockerfile 方式：
- **方式 A（根目录 `Dockerfile`，推荐 CI/CD）**：先在宿主机快速交叉编译静态二进制文件 `bin/remote-mcp`，秒级打出极简 Alpine 运行镜像。
  ```bash
  CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o bin/remote-mcp ./cmd/remote-mcp
  docker build -t mcp-execmesh:latest .
  ```
- **方式 B（`deploy/Dockerfile.standalone`）**：纯容器内两阶段构建，无需宿主机 Go 环境。
  ```bash
  docker build -f deploy/Dockerfile.standalone -t mcp-execmesh:latest .
  ```

### 1.2 启动服务
```bash
docker compose up -d
docker compose logs -f
```

---

## 2. 生产环境目录与权限结构

容器以非 root 用户 `mcpuser` (UID: `10001`, GID: `10001`) 运行，请确保挂载卷权限正确：

```
/opt/remote-mcp/
├── config.yaml          # 只读挂载 (:ro)，所有者 root:root，权限 0640
├── known_hosts          # 只读挂载 (:ro)，所有者 root:root，权限 0640
│                            # 须包含目标主机实际协商会用到的全部 Host Key 类型（rsa/ecdsa/ed25519）
│                            # 以及连接地址对应的所有名字：hostname、解析后的 IP、Docker extra_hosts 名
│                            # 单文件 bind-mount 禁止 mv/rename 替换（inode 会脱钩）；应原地写入后重启容器
├── secrets/             # 只读挂载 (:ro)，所有者 root:root 或 10001:10001，权限 0600
│   ├── node-01_ed25519
│   └── api_token.txt
└── data/                # 读写挂载，所有者 10001:10001，权限 0700 (用于持久化状态与临时中继)
```

---

## 3. 生产级安全配置清单

生产环境请务必检查以下安全配置项：

| 配置项 | 推荐值 | 说明 |
| :--- | :--- | :--- |
| `server.auth.type` | `bearer` 或 `api_key` | **严禁在公网暴露 `none`**，必须配置 Bearer Token 或 API Key |
| `security.require_known_hosts` | `true` | 强制开启严格 Host Key 检查，防止 SSH 中间人劫持 |
| `security.allow_inline_secrets` | `false` | 禁止在配置文件中内联明文密码/密钥，强制使用独立密钥文件或环境变量 |
| `security.block_private_download_addresses` | `true` | 强制开启 SSRF 拦截（阻断私有/回环/保留 IP 与元数据服务） |
| `security.allowed_file_download_schemes` | `["https"]` | 文件拉取仅允许 HTTPS 加密连接 |
| `security.mask_sensitive_commands` | `true` | 在审计日志中对包含密码、密钥、Token 的敏感命令参数自动掩码 |
| `runtime.max_concurrent_requests` | `8` ~ `32` | 限制并发请求，防止小内存 VPS 资源耗尽 |
| `runtime.max_concurrent_transfers` | `1` ~ `4` | 控制大文件流式传输并发数 |

---

## 4. 反向代理与 HTTPS 配置 (Nginx)

将 Nginx 配置作为 TLS 终止代理，并启用流式传输支持（禁止缓冲）：

参考文件：`deploy/nginx.example.conf`

关键参数：
- `proxy_buffering off;`：支持 MCP Streamable HTTP 流式长连接与大文件流式拉取。
- `proxy_read_timeout 300s;`：适应长耗时同步命令与流式上传。
- `client_max_body_size 0;`：允许任意大小流式传输（受 `mcp-execmesh` 内部限额保护）。

---

## 5. Systemd 服务化部署

直接部署在裸机 Linux（如 Debian/CentOS/Alpine）时，参考 `deploy/remote-mcp.service`：

```bash
# 复制二进制与服务配置
sudo cp bin/remote-mcp /usr/local/bin/remote-mcp
sudo cp deploy/remote-mcp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now remote-mcp
```

---

## 6. 监控与健康检查

- **存活探针 (Liveness Probe)**：`GET /healthz` -> 返回 `200 OK`
- **就绪探针 (Readiness Probe)**：`GET /readyz` -> 返回 `200 OK`，若 Target 校验或依赖故障返回 `503 Service Unavailable`
- **单次安全下载**：`GET /files/{token}` -> 流式下载远程 Target 文件
