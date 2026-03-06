# KeyFlow TODO

> 最后更新：2026-03-06
> 当前产品主线：开发者密钥资产库
> 当前主入口：CLI + Web
> 当前 AI 定位：增强层，不是主入口

## 当前状态

这轮迭代之后，KeyFlow 已经从“AI-first secret ops”开始收口到“开发者密钥沉淀与复用”方向。

当前已经具备的核心能力：
- 本地加密 vault
- `add / list / get / search / update / remove`
- `import / export / run / backup / restore`
- key group / template
- 本地 Web 控制台
- 可选 MCP / AI 集成
- 资产健康检查
- 显式 `verify`
- 候选扫描 `scan`

当前重要边界：
- 不会因为 AI 对话里出现 token 就自动入库
- `scan` 默认只预览，只有 `--apply` 或交互确认才会导入
- `kf setup` 不再把主密码写进 AI 工具配置，改为依赖本地 `~/.keyflow/.session`

## 本轮已完成

### 产品定位与文档

- [x] README 改成中文，并明确产品定义、AI 边界、自动保存边界、提醒边界
- [x] `docs/product-architecture.md` 改成中文
- [x] `docs/product-roadmap.md` 改成中文
- [x] CLI / README / 路线图统一为 `CLI + Web` 主线，TUI 降级为实验性入口

### 数据模型与资产元数据

- [x] `SecretEntry` 增加 `account_name`
- [x] `SecretEntry` 增加 `source`
- [x] `SecretEntry` 增加 `last_verified_at`
- [x] DB migration 支持 `account_name` / `source` / `last_verified_at`
- [x] 搜索支持按 `account_name` / `source` 命中

### Provider 与模板

- [x] 增加 `resend` provider 推断和默认管理地址
- [x] 增加 `resend` 模板

### 导入与沉淀

- [x] `kf import` 从“单文件导入”升级为“文件或目录导入”
- [x] 目录导入支持扫描 `.env` / `.env.*`
- [x] 目录导入支持从 `package.json` / `Cargo.toml` 推断项目名
- [x] 导入条目自动写入 `source=import:<path>`
- [x] 增加 `kf scan <path>`
- [x] `kf scan` 默认只展示候选项，不自动入库
- [x] 增加 `kf scan <path> --apply`

### 健康检查

- [x] `health` 从“过期检查”扩展为“资产质量检查”
- [x] 增加 `metadata_review`
- [x] 当前 review 规则覆盖：
  - `account` 缺失
  - `source` 缺失或过弱
  - `project` 缺失
  - `expiry` 缺失
  - `verification` 过旧
- [x] Web health API 返回 `metadata_review`
- [x] MCP `check_health` 返回 `metadata_review`

### 验证与确认

- [x] 增加 `kf verify <name>`
- [x] 增加 `kf verify --all`
- [x] CLI `list/get/search` 已显示 `verified`

### Web / TUI / MCP

- [x] Web 列表显示 `account` / `source`
- [x] Web health 面板增加 `metadata_review`
- [x] TUI 详情显示 `verified`
- [x] MCP metadata 增加 `account_name` / `source` / `last_verified_at` / `metadata_gaps`

### 安全模型

- [x] `kf setup` 不再把 `KEYFLOW_PASSPHRASE` 写入 AI 工具配置
- [x] `init` / `passwd` 会更新本地 session
- [x] setup 测试已切换为 session 模型

### 测试

- [x] CLI 主链路集成测试
- [x] backup/restore passphrase rotation 回归测试
- [x] legacy backup 兼容测试
- [x] setup 幂等测试
- [x] 目录导入测试
- [x] asset metadata / resend 测试
- [x] metadata review 测试
- [x] verify 测试
- [x] scan preview/apply 测试

## 当前优先级

### P0 — 继续收紧“开发者密钥资产库”主线

- [x] Web 增加显式 Verify 动作，而不只是展示 `verified`
- [x] Web 增加 “最近验证 / 待补信息 / 长期未使用” 过滤视图
- [x] CLI `update` 支持显式更新 `last_verified_at`
- [x] README 增加一段“推荐日常工作流”

### P1 — 健康检查继续变强

- [x] 增加“疑似重复 / 重叠 key”检查
- [x] 增加“同 provider 多把旧 key”提示
- [x] 增加“source 质量分层”，区分 `manual`、`import:path`、`template:*`、`mcp:add_key`
- [x] 增加“未验证超过 N 天”更明确的分类输出
- [x] 增加真实 provider 校验能力设计，但不要默认联网执行

### P1 — 被动发现，但保持用户确认

- [x] `scan` 支持递归扫描模式
- [x] `scan` 支持只看新增候选项
- [x] `scan` 支持跳过常见无意义变量
- [x] `scan` 支持导出候选清单，而不是立即导入
- [x] 设计“AI 发现候选 key -> 用户确认 -> add_key”的交互

### P1 — Web 主界面继续加强

- [x] Web 增加重复 key / review item 数量卡片
- [x] Web 增加单条详情抽屉或侧栏
- [x] Web 增加按 `account` / `source` 过滤
- [x] Web 增加 verify / mark inactive 等轻操作

### P2 — 安全与 setup 继续收口

- [x] README 补一段“session 模型怎么工作”
- [x] `kf lock` 后，AI MCP 调用失败时返回更明确提示
- [x] setup 后输出更明确的安全说明和恢复说明
- [x] 评估 session 过期/自动失效机制

### P2 — Provider 与资产模型

- [x] 补 `environment` 字段（prod/staging/dev）
- [x] 补 `permission_profile` / `scope_profile`
- [x] 补 `account/org` 更细化字段设计
- [x] 补更高频 provider 深度模板（Google/GitHub/Cloudflare/Resend/OpenAI/Stripe）

## 暂缓

- [ ] 团队版 / RBAC / 审计日志
- [ ] 托管版 SaaS
- [ ] 大规模 provider rotation automation
- [ ] 把 KeyFlow 做成通用部署控制平面
- [ ] TUI 大量新功能投入

## 提交前检查

这次提交前，建议至少确认：

- [x] `cargo test`
- [x] `cargo clippy --all-targets --all-features -- -D warnings`
- [x] README 与命令行为一致
- [x] `TODO.md` 无过时产品叙事

## 下次继续时的建议入口

如果下次继续开发，建议直接从下面三项开始，优先级从高到低：

1. Web 增加 `Verify` 动作
2. 健康检查增加“重复 / 重叠 key”规则
3. `scan` 增加递归扫描和候选筛选

## 最近关键变更摘要

这几轮的关键方向性变更：

- 从 AI-first 文案切回开发者密钥资产库
- 把 `commands.rs` 拆模块
- 统一 bin 入口
- backup/restore salt 兼容修复
- 增加 asset metadata：`account_name` / `source`
- 增加 `last_verified_at`
- 增加 `resend`
- import 支持目录
- 新增 `scan`
- 新增 `verify`
- `health` 升级为资产质量检查
- `setup` 改为 session 模型，不再把主密码写进配置
