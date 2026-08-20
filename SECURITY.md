# 安全设计与规范 (Security Policy)

Remote Executor MCP 专为面向外部 AI Agent 和自动化系统的远程控制而设计，遵循以下安全基准与防御原则：

## 1. 凭据隔离与权限最小化
- **禁止动态凭据**：MCP Tool 绝不接收 `host`、`username`、`password`、`private_key` 作为入参，所有连接凭据必须预先配置在服务器端。
- **文件权限规范**：
  - 配置文件权限建议设为 `0640`；
  - 密钥和密码文件权限建议设为 `0600`，目录设为 `0700`。
- **凭据防泄露**：
  - Tool 返回值中严禁携带私钥、密码、私钥路径及内部 Secret 路径；
  - 审计日志中自动屏蔽敏感密码，记录命令 SHA256 哈希。

## 2. 主机密钥验证 (Host Key Verification)
- 默认启用严格的 `known_hosts` 校验 (`strict: true`)；
- 当目标主机的指纹与 `known_hosts` 不匹配时，直接拒绝建立 SSH 连接，防止中间人拦截。

## 3. 内存保护与抗拒绝服务 (DoS Protection)
- **有界输出缓冲**：所有通过 `exec` 调用的命令 stdout 和 stderr 均受到 `max_stdout_bytes` / `max_stderr_bytes` 约束（默认 64KiB），超出部分安全截断并设置 `stdout_truncated` 标志，杜绝内存耗尽（OOM）。
- **禁止无界读写**：全项目严禁 `io.ReadAll` 读取大流，大传输统一使用定长 64KiB 缓冲区进行流式中继。

## 4. 路径限制与逃逸防护
- 支持配置 `allowed_paths`；
- 所有工作目录和文件路径均进行路径规范化 (`filepath.Clean`) 和前缀边界校验，防止 `../` 目录遍历攻击。

## 5. SSRF 防御与安全文件流式中继
- **协议白名单**：默认仅允许 `https://` 下载链接；
- **私有与保留网络拦截**：严格拦截指向私有网段（`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`）、回环地址（`127.0.0.0/8`, `::1`）、链路本地（`169.254.0.0/16`, `fe80::/10`）及保留广播地址的请求；
- **DNS 解析与重定向防护**：在建立 TCP 连接底层实施 IP 过滤，并在 HTTP 重定向（最多 3 次）过程中逐次执行合法性验证，防御 DNS Rebinding 攻击；
- **单次有效签名 Token**：通过 `file_pull_prepare` 生成的下载链接使用 256 位加密随机 Token，严格绑定 Target 与路径，限制单次有效并自动过期。

## 6. 传输层安全与认证
- 生产环境必须前置 HTTPS 反向代理。
- **Dual Authentication**：
  - Cursor / Claude / CLI：`POST /mcp` + `Authorization: Bearer`；
  - ChatGPT Developer Mode：`https://host/mcp/cap_v1_<opaque>`，身份验证选择 **No Authentication**。
- Capability URL **必须当作密码**：禁止写入 README、Issue、截图、Git、CI 日志。
- 服务器只保存 SHA-256 digest（`capabilities.yaml` 权限 0600），明文仅在 `remote-mcp auth capability create|rotate` 时显示一次。
- 每个 HTTP GET/POST/DELETE 都重新验证 Capability；MCP-Session-Id 不能替代认证。
- 无效 Capability 统一返回 404，不区分过期/撤销/不存在。
- MCP Tool 只根据 Principal + Scope + Target ACL 授权，不感知 Capability / Bearer。
- 应用日志对 `/mcp/cap_v1_...` 脱敏为 `/mcp/[CAPABILITY]`；反代 access log 必须同样脱敏。

Capability URL MUST be treated as a password.

