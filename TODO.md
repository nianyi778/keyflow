# KeyFlow TODO

> Last updated: 2026-03-06

## P0 — Core (Done)

- [x] 修改密码 — `keyflow passwd`
- [x] 数据备份/恢复 — `keyflow backup` / `keyflow restore`
- [x] import 覆盖策略 — `--on-conflict overwrite|skip|rename`
- [x] Key Group — `key_group` 字段 + `keyflow group list/show/export`
- [x] 模板系统 — `keyflow template list/use`，14 个预设模板

## P0.5 — AI-Native (Done)

- [x] MCP Action Tools — `deploy_secret`、`deploy_project_secrets`、`add_key`、`get_env_snippet`、`check_project_readiness`
- [x] `kf setup` — 一键配置 9 种 AI 工具（Claude/Cursor/Windsurf/Gemini/OpenCode/Codex/Zed/Cline/Roo）
- [x] Deploy 安全修复 — 所有目标通过 stdin pipe 或环境变量传值，不暴露在 `ps`

## P1 — 体验提升

- [x] Shell 补全 — `keyflow completions zsh/bash/fish`
- [x] 本地 Web Dashboard — `keyflow dashboard` 暗色主题可视化管理
- [x] Onboarding 闭环 — `kf init` 完成后引导 `kf add` → `kf setup`
- [ ] **真实 API 健康检查** — reqwest 实际调 API 验证 key 有效性（Google/GitHub/CF）
- [ ] **过期提醒通知** — cron + macOS 系统通知 / webhook

## P2 — 产品化

- [ ] **GitHub Actions CI** — 自动构建 macOS/Linux/Windows 二进制，Release 发布
- [ ] **Homebrew 发布** — `brew install keyflow`
- [ ] **多设备同步** — 加密导出后同步到 iCloud/Dropbox/Git
- [ ] **1Password/Bitwarden 导入** — 从密码管理器批量迁入

## P3 — 团队 & 商业化

- [ ] **后端服务** — 用户认证、团队管理、API
- [ ] **前端面板** — Web SaaS 版管理界面
- [ ] **团队共享** — 密钥分享 + RBAC 权限控制
- [ ] **审计日志** — 谁在什么时候访问了什么 key
- [ ] **官网 Landing Page** — 产品介绍、文档站

## Done

- [x] v0.1.0: CLI 全功能 + AES-256-GCM + MCP Server + 17 providers
- [x] v0.2.0: P0 (passwd/backup/restore/groups/templates) + P1 (completions/dashboard)
- [x] v0.3.0: AI-Native (5 MCP action tools + kf setup + deploy security fix + onboarding)
