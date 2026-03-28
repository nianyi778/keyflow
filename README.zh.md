<div align="center">

# KeyFlow

**开发者密钥资产库 — 存一次，搜得到，复用快，AI 也能查**

[![Rust](https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=white)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-Compatible-8A2BE2)](#ai-集成)
[![Website](https://img.shields.io/badge/Site-keyflow.divinations.top-22C55E)](https://keyflow.divinations.top)

**[English](README.md)**

</div>

## 安装

```bash
brew tap nianyi778/keyflow && brew install keyflow
# 或
cargo install --git https://github.com/nianyi778/keyflow
```

## 30 秒上手

```bash
kf init                                              # 创建加密 vault
kf add OPENAI_API_KEY sk-xxx --provider openai       # 存 key
kf search resend                                     # 搜 key
kf run --project myapp -- npm start                  # 注入环境变量运行
kf export --project myapp -o .env                    # 导出 .env
kf import ./myapp                                    # 吸收项目里的 .env
kf health                                            # 看哪些 key 需要清理
```

### 跨项目同名 Key

同一个环境变量，不同项目可以存不同的值：

```bash
kf add DATABASE_URL postgres://dev:5432 --projects dev-app
kf add DATABASE_URL postgres://prod:5432 --projects prod-app
kf get database-url                                  # 交互选择
kf get database-url --project dev-app                # 直接拿
kf run --project dev-app -- npm start                # 只注入 dev-app 的密钥
```

> `kf` 是 `keyflow` 的短命令，两者等价。

## 截图

<table>
<tr>
<td width="50%">

**`kf list`**

<img src="docs/cli-list.png" alt="kf list" width="480" />
</td>
<td width="50%">

**`kf search`**

<img src="docs/cli-search.png" alt="kf search" width="480" />
</td>
</tr>
<tr>
<td width="50%">

**`kf health`**

<img src="docs/cli-health.png" alt="kf health" width="480" />
</td>
</tr>
</table>

## AI 集成

自带 MCP server，一行接入 AI 编码工具：

```bash
kf setup claude    # 或 cursor / windsurf / gemini / opencode / codex / zed / cline / roo
```

AI 只能看到元数据（名称、provider、项目、状态），看不到密钥值。10 个工具按 discover / inspect / reuse / maintain 分层，详见 [MCP 契约](docs/mcp-contract.md)。

手动配置：

```json
{ "mcpServers": { "keyflow": { "command": "kf", "args": ["serve"] } } }
```

## 云同步

端到端加密同步，服务端永远看不到明文：

```bash
kf sync init       # 注册并绑定云端
kf sync push       # 推送本地变更
kf sync pull       # 拉取远端变更
kf sync run        # 双向同步（先拉后推）
kf sync status     # 查看同步状态
```

## 命令速查

| 命令 | 说明 |
|------|------|
| `kf init` | 初始化 vault |
| `kf add` | 新增密钥 |
| `kf list` | 列出密钥 |
| `kf get <name> [--project X]` | 读取密钥值 |
| `kf search <query>` | 搜索 |
| `kf scan <path>` | 扫描 .env 候选项 |
| `kf update <name> [--project-filter X]` | 更新元数据 |
| `kf verify <name> [--project X]` | 标记 key 仍有效 |
| `kf remove <name> [--project X]` | 删除 |
| `kf run -- <cmd>` | 注入环境变量运行 |
| `kf import <path>` | 导入 .env |
| `kf export` | 导出 .env |
| `kf health` | 健康检查 |
| `kf setup` | 配置 AI 集成 |
| `kf serve` | 启动 MCP server |
| `kf sync` | 云同步 |
| `kf backup` / `kf restore` | 备份 / 恢复 |
| `kf passwd` | 改主密码 |
| `kf lock` | 锁定 vault |
| `kf completions <shell>` | 生成 shell 补全脚本 |

## 安全

- **AES-256-GCM** 加密，**Argon2** 密钥派生
- 本地存储：macOS `~/Library/Application Support/keyflow/`，Linux `~/.local/share/keyflow/`
- MCP 只暴露元数据，不暴露密钥值
- `.passphrase` 文件权限 `0600`，`kf lock` 一键清除
- `kf run` 运行时注入，明文不落盘
- 支持 20+ provider 自动推断（Google、GitHub、Cloudflare、AWS、OpenAI 等）

## License

[MIT](LICENSE) - Copyright (c) 2026 nianyi778
