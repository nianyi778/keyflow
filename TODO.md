# KeyFlow TODO

> Last updated: 2026-03-06

## P0 — Core (自用必备)

- [ ] **修改密码** — `keyflow passwd`，重新加密所有数据，不丢失
- [ ] **数据备份/恢复** — `keyflow backup` / `keyflow restore`，导出加密包
- [ ] **import 覆盖策略** — 导入 .env 遇到同名 key 可选 覆盖/跳过/重命名
- [ ] **Key Group** — 一组关联密钥（如 Google OAuth: client_id + secret + redirect_uri），一次添加/导出
- [ ] **模板系统** — `keyflow template google-oauth` 预设标准字段，减少手动输入

## P1 — 体验提升

- [ ] **Shell 补全** — `keyflow completions zsh/bash/fish`（clap 内置支持）
- [ ] **本地 Web Dashboard** — `keyflow dashboard` 启动本地 HTTP server，浏览器可视化管理
- [ ] **真实 API 健康检查** — reqwest 实际调 API 验证 key 有效性（Google/GitHub/CF）
- [ ] **过期提醒通知** — cron + macOS 系统通知 / webhook
- [ ] **自动检测项目** — 进入目录时读 package.json / Cargo.toml 自动关联项目标签

## P2 — 产品化

- [ ] **Homebrew 发布** — `brew install keyflow`
- [ ] **GitHub Actions CI** — 自动构建 macOS/Linux/Windows 二进制，Release 发布
- [ ] **多设备同步** — 加密导出后同步到 iCloud/Dropbox/Git
- [ ] **1Password/Bitwarden 导入** — 从密码管理器批量迁入
- [ ] **VS Code 扩展** — 编辑器侧边栏查看/搜索 key

## P3 — 团队 & 商业化

- [ ] **后端服务** — 用户认证、团队管理、API
- [ ] **前端面板** — Web SaaS 版管理界面
- [ ] **团队共享** — 密钥分享 + RBAC 权限控制
- [ ] **审计日志** — 谁在什么时候访问了什么 key
- [ ] **官网 Landing Page** — 产品介绍、文档站

## Done

- [x] CLI 全功能 (add/list/get/search/update/remove/import/export/run/health)
- [x] AES-256-GCM 加密 + Argon2 密钥派生
- [x] MCP Server (Claude Code / Cursor 集成)
- [x] 17 个 provider 预设 URL
- [x] 交互式 + 非交互式双模式
- [x] GitHub 仓库创建 + 推送
- [x] MCP 全局配置 (~/.claude/.mcp.json)
