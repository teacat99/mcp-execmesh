# Changelog

本文件记录 `mcp-execmesh` 各版本的 notable 变更。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [1.0.0] - 2026-08-20

### Added
- Remote Executor MCP 核心网关：Target Registry、同步/异步执行、文件传输、Job 管理
- Dual Authentication：Capability URL + Bearer 统一 Principal
- 动态 Target 管理（Admin 工具集）
- 文件下载链路：`public_base_url` + 单次有效 Ticket（SHA-256 存储、TTL、防重放）
- 公开镜像自动发布至 `ghcr.io/teacat99/mcp-execmesh`（仅 public 仓库触发）
- `scripts/sync-public.sh` 支持向 public 仓库传播 `v*` semver tag

### Changed
- Docker 构建注入 `version` / `gitCommit` / `buildDate`（`remote-mcp -version` 与 MCP Server 版本一致）
- 公开镜像与私有开发仓分离：private 手动构建测试，public 自动 CI/CD

### Security
- 凭据隔离与 Target ID 间接路由；严格 known_hosts 校验
- 下载 Ticket 不进入应用日志；无效/过期/已用 Ticket 统一返回 404

[1.0.0]: https://github.com/teacat99/mcp-execmesh/releases/tag/v1.0.0
