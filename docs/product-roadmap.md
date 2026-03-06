# 产品路线图

## 必须做

这些能力决定了产品是否成立：

- 让密钥沉淀更容易：
  支持从 `.env`、项目目录、剪贴板、模板等入口吸收已有 key，并提供更好的默认元数据
- 让复用更直接：
  更强的搜索、基于项目的复用、更好的 `kf run`、更好的 `kf export`
- 让回忆更可信：
  provider、account、project、purpose、expiration、status 应该一眼能看懂
- 让健康检查更可执行：
  已过期、即将过期、inactive、长期未使用、信息不完整的 key 都应该能引导清理决策
- 对外表达保持一致：
  明确 KeyFlow 首先是开发者密钥资产库，其次才是 AI 增强工具
- 提升高频 provider 覆盖：
  重点围绕 Google、GitHub、Cloudflare、Resend、OpenAI、Stripe

如果这些能力弱，用户还是会继续重复申请密钥，而不是复用已有资产。

## 应该做

这些能力会在核心工作流稳定后进一步增强产品：

- 被动候选发现：
  扫描本地 `.env` 文件、记录复用痕迹、减少手动 `kf add`
- 更完整的元数据模型：
  account/org、environment、permission profile、source、last verified time
- 更强的 AI 辅助：
  更好的 MCP 只读工具、项目 readiness 检查、env var 推荐
- 更安全的 setup 体验：
  降低明文主密码写入配置的风险，给用户更清晰的边界和提示
- 公有云交付能力：
  改善对云平台 CLI 和项目目标的密钥交付
- 私有化部署能力：
  Docker、Compose 和自部署路径，适合用户自己托管

## 暂缓做

这些方向有价值，但现在不该主导开发节奏：

- 全 AI 驱动的部署编排
- 面向大量 provider 的轮换自动化
- 在单用户工作流还不够锋利前就做多租户托管版
- 复杂企业权限系统
- 把 KeyFlow 做成通用 DevOps 控制平面

## 版本矩阵

### Local Edition

- CLI、本地 Web 控制台、可选实验性 TUI
- 本地加密 vault
- import、search、export、run、backup、restore
- 可选 AI 集成

### Hosted Edition

- 你提供的托管服务
- 更顺滑的 onboarding 和同步
- Web-first 体验
- 托管发布和集成能力

### Self-Hosted Edition

- 用户自己部署
- 自己控制数据和运行环境
- 适合 homelab、内部团队、受监管场景

## 决策规则

如果一个功能能更快帮助用户做到以下任意一点，优先：
- 存下一把 key
- 找回一把 key
- 更信任一把 key
- 复用一把 key
- 安全把一把 key 交付到运行环境

如果一个功能主要带来这些问题，要谨慎：
- provider 维护负担明显增加
- AI-only 工作流，但非 AI 价值很弱
- 部署复杂度增加，但对复用没帮助
- 因为秘密暴露路径增多而增加新风险
