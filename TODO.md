# KeyFlow TODO

> 最后更新：2026-03-16
> 当前产品主线：本地加密的开发者密钥资产库
> 当前主入口：CLI + MCP
> 当前原则：不保留历史包袱，不为未上线版本做兼容设计

## 当前核心

KeyFlow 现在只专注四件事：

- 安全存：把已有密钥加密保存到本地 vault
- 快速找：按 provider / project / account / source / env_var 搜索
- 稳定复用：通过 `run / export / import / scan` 进入真实项目工作流
- 安全暴露给 AI：通过 MCP 提供元数据和轻量工作流能力

## 已完成

- [x] 删除 Web 控制台
- [x] 删除 TUI
- [x] 删除 group 能力
- [x] 删除 template 能力
- [x] 删除 MCP deploy 编排能力
- [x] 删除 `key_group` 数据模型
- [x] 删除模板常量和相关文档资源
- [x] MCP 重构为协议层 / 服务层 / 工具注册层
- [x] 收敛为 `CLI + MCP` 产品形态
- [x] 删除旧备份 restore 兼容逻辑
- [x] 删除数据库补迁移逻辑

## Now

- [x] 重写 CLI 服务层
  目标：把 secrets.rs 里的业务逻辑继续抽离，CLI 只保留参数解析和输出。
  完成：SecretService 成为唯一业务层，VaultService 降级为 JSON 包装。

- [x] 重做 MCP 工具契约
  目标：统一工具命名、输入 schema、输出 schema、错误格式，按 `discover / inspect / reuse / maintain` 分层。
  完成：10 个工具按四层重命名，outputSchema 全覆盖，错误格式统一。

- [x] 标准化 `structuredContent`
  目标：所有 MCP 工具返回稳定结构，不再主要依赖文本里的 JSON dump。
  完成：所有工具同时返回 content（text 回退）和 structuredContent（typed JSON）。

- [x] 重写 README
  目标：删掉历史演进痕迹，只讲当前核心链路、数据模型、CLI 工作流和 MCP 能力。
  完成：MCP 工具说明更新为四层分组，旧工具名引用全部替换。

## Next

- [ ] 执行人工 smoke 检查
  目标：基于 `docs/release-rehearsal-2026-03-07.md` 完成真实 vault、`kf serve`、HTTP transport、`kf setup` 的人工走查。

- [ ] 精简 `SecretEntry`
  检查 `org_name / permission_profile / apply_url / scopes / environment` 哪些真是核心，哪些应该进一步删减。

- [ ] 提升搜索质量
  增加更好的排序和字段优先级，让精确命中优先于模糊命中。

- [ ] 升级项目识别
  不只识别 `package.json / Cargo.toml`，补 workspace / monorepo 场景。

- [ ] 强化 readiness 检查
  让 `maintain_project_readiness` 提供更明确的状态分级、缺失原因和建议动作。

- [ ] 重构 import / scan 流水线
  把扫描、预览、去重、冲突处理整理成更清晰的统一流程。

- [ ] 增加 MCP 专项测试
  直接测协议层和工具层，而不是主要靠 CLI 集成测试间接覆盖。

## Later

- [ ] 考虑进一步精简 backup 格式
  在不牺牲可恢复性的前提下，继续降低复杂度。

- [ ] 评估是否把 CLI 也彻底切到 service-first 架构
  如果命令继续增长，就把展示层和业务层彻底解耦。

- [ ] 考虑加入更强的项目上下文发现
  例如从 `.env.example` 或项目配置中推断候选 env var，但默认仍然只读。

## 不做

- [ ] Web UI
- [ ] TUI
- [ ] group / bundle 模型
- [ ] template 系统
- [ ] 大而全的 provider 编排
- [ ] deploy control plane
- [ ] 团队版 / RBAC / 托管 SaaS
- [ ] 为历史版本保留兼容层

## 验收线

每次继续改造，至少确认：

- [x] `cargo test`
- [x] 文档与当前产品边界一致
- [x] 不新增历史兼容代码
- [x] 不把非核心能力重新塞回产品面
