# Provider 校验能力设计

> 状态：设计阶段，暂不实现联网校验

## 目标

为高频 provider 提供可选的密钥有效性校验能力，帮助用户确认 key 是否仍然可用。

## 设计原则

1. **不默认联网执行** — 校验必须由用户显式触发（`kf verify <name> --check`）
2. **只做最小请求** — 使用最轻量的 API 调用确认身份，不执行任何写操作
3. **失败不改状态** — 网络超时或服务不可达不应改变 key 的状态
4. **渐进覆盖** — 从最常用的 provider 开始，逐步增加

## 校验策略

| Provider | 校验方法 | 端点 |
|----------|----------|------|
| OpenAI | GET /v1/models (header: Authorization) | api.openai.com |
| Anthropic | GET /v1/models | api.anthropic.com |
| GitHub | GET /user | api.github.com |
| Cloudflare | GET /client/v4/user/tokens/verify | api.cloudflare.com |
| Stripe | GET /v1/balance | api.stripe.com |
| Vercel | GET /v2/user | api.vercel.com |
| Resend | GET /domains | api.resend.com |
| SendGrid | GET /v3/user/profile | api.sendgrid.com |
| Supabase | 无通用端点，跳过 | - |
| AWS | sts:GetCallerIdentity | sts.amazonaws.com |

## 接口设计

```rust
pub trait ProviderValidator {
    fn can_validate(&self, provider: &str) -> bool;
    fn validate(&self, provider: &str, env_var: &str, value: &str) -> ValidateResult;
}

pub enum ValidateResult {
    Valid,
    Invalid(String),    // 明确无效 + 原因
    Unknown(String),    // 无法判断（网络错误等）
    Unsupported,        // 该 provider 暂不支持校验
}
```

## CLI 交互

```bash
# 只更新 last_verified_at（当前行为）
kf verify openai-api-key

# 实际联网校验（未来）
kf verify openai-api-key --check

# 批量联网校验
kf verify --all --check
```

## 安全考量

- 校验请求通过 HTTPS 直连 provider API，不经过任何中间服务
- key 值只在内存中存在，不会写入日志或 CLI 输出
- 超时默认 10 秒，避免长时间阻塞
