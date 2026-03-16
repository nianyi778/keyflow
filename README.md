<div align="center">

# KeyFlow

**Developer key vault — store once, search fast, reuse everywhere, AI-safe**

**开发者密钥资产库 — 存一次，搜得到，复用快，AI 也能查**

[![Rust](https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=white)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-Compatible-8A2BE2)](#ai-integration)
[![Website](https://img.shields.io/badge/Site-keyflow.divinations.top-22C55E)](https://keyflow.divinations.top)

</div>

## Install / 安装

```bash
brew tap nianyi778/keyflow && brew install keyflow
# or / 或
cargo install --git https://github.com/nianyi778/keyflow
```

## Quickstart / 快速上手

```bash
kf init                                              # Create vault / 创建加密 vault
kf add OPENAI_API_KEY sk-xxx --provider openai       # Store a key / 存 key
kf search resend                                     # Find a key / 搜 key
kf run --project myapp -- npm start                  # Inject & run / 注入环境变量运行
kf export --project myapp -o .env                    # Export .env / 导出 .env
kf import ./myapp                                    # Import .env / 吸收项目 .env
kf health                                            # Check hygiene / 健康检查
```

> `kf` is shorthand for `keyflow`. Both work. / `kf` 是 `keyflow` 的短命令，两者等价。

## Screenshots / 截图

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

## AI Integration / AI 集成

Built-in MCP server. One command to connect any AI coding tool:

自带 MCP server，一行接入 AI 编码工具：

```bash
kf setup claude    # or cursor / windsurf / gemini / opencode / codex / zed / cline / roo
```

AI sees metadata only — never the secret value. 10 tools organized by discover / inspect / reuse / maintain. See [MCP contract](docs/mcp-contract.md).

AI 只能看到元数据，看不到密钥值。10 个工具按 discover / inspect / reuse / maintain 分层，详见 [MCP 契约](docs/mcp-contract.md)。

Manual config / 手动配置：

```json
{ "mcpServers": { "keyflow": { "command": "kf", "args": ["serve"] } } }
```

## Cloud Sync / 云同步

End-to-end encrypted. The server never sees plaintext.

端到端加密，服务端永远看不到明文。

```bash
kf sync init       # Register / 注册并绑定云端
kf sync run        # Push & pull / 推拉同步
```

## Commands / 命令速查

| Command | Description / 说明 |
|---------|-------------|
| `kf init` | Initialize vault / 初始化 |
| `kf add` | Add secret / 新增密钥 |
| `kf list` | List secrets / 列出密钥 |
| `kf get <name>` | Retrieve value / 读取密钥值 |
| `kf search <query>` | Search / 搜索 |
| `kf scan <path>` | Scan .env candidates / 扫描候选项 |
| `kf update <name>` | Update metadata / 更新元数据 |
| `kf verify <name>` | Mark as valid / 标记仍有效 |
| `kf remove <name>` | Delete / 删除 |
| `kf run -- <cmd>` | Inject & run / 注入运行 |
| `kf import <path>` | Import .env / 导入 |
| `kf export` | Export .env / 导出 |
| `kf health` | Health check / 健康检查 |
| `kf setup` | AI integration / 配置 AI |
| `kf sync` | Cloud sync / 云同步 |
| `kf backup` / `kf restore` | Backup / 备份恢复 |
| `kf passwd` | Change password / 改主密码 |
| `kf lock` | Lock vault / 锁定 |

## Security / 安全

- **AES-256-GCM** encryption, **Argon2** key derivation / AES-256-GCM 加密，Argon2 密钥派生
- Local storage / 本地存储：macOS `~/Library/Application Support/keyflow/`, Linux `~/.local/share/keyflow/`
- MCP exposes metadata only / MCP 只暴露元数据
- `.passphrase` permission `0600`, `kf lock` clears instantly / `.passphrase` 权限 0600，`kf lock` 一键清除
- `kf run` injects at runtime — plaintext never hits disk / 运行时注入，明文不落盘
- 20+ providers auto-detected / 20+ provider 自动推断 (Google, GitHub, Cloudflare, AWS, OpenAI...)

## License

[MIT](LICENSE) - Copyright (c) 2026 nianyi778
