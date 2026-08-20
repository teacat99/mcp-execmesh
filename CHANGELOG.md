# Changelog

本文件记录 `mcp-execmesh` 各版本的 notable 变更。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Added
- Dual Authentication：Capability URL + Bearer 统一 Principal
- 动态 Target 管理（`target_add` / `update` / `enable` / `disable` / `remove` 等 Admin 工具）
- 文件下载链路：`public_base_url` + 单次有效 Ticket（SHA-256 存储、TTL、防重放）
- 公开镜像自动发布至 `ghcr.io/teacat99/mcp-execmesh`（仅 public 仓库触发）
- `scripts/sync-public.sh` 支持向 public 仓库传播 `v*` semver tag

### Changed
- Docker 构建注入 `version` / `gitCommit` / `buildDate`（`remote-mcp -version` 可观测）
- 公开镜像与私有开发仓分离：private 手动构建测试，public 自动 CI/CD

### Security
- 下载 Ticket 不进入应用日志；无效/过期/已用 Ticket 统一返回 404
