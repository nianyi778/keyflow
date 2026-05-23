# Worker deployment

The sync backend is a single Cloudflare Worker (`src/index.ts`) backed by a D1
database and a KV namespace.

## Prerequisites

- **Node ≥ 22.** Older Node versions hit `EBADENGINE` warnings with `wrangler`
  and may fail at `wrangler dev` / `wrangler deploy`. The package `engines`
  field enforces this.
- A Cloudflare account with D1 + KV enabled.
- `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` / `JWT_SECRET` set as Worker
  secrets (`wrangler secret put …`).

## First-time install

```bash
cd worker
npm install
npm run db:init           # local D1 schema (development)
npm run db:init:remote    # remote D1 schema (production)
npm run typecheck         # tsc --noEmit, must be clean
npm test                  # vitest suite (currently 27 tests)
```

## Schema migrations

The base schema lives in `schema.sql` (used for fresh installs).

Migrations are numbered files under `migrations/`. Each one is idempotent on a
fresh database (covered by `schema.sql`) and must be applied to existing
remote databases in order:

| File | What it does |
| ---- | ------------ |
| `001_google_auth.sql` | Initial users / OAuth state tables. |
| `002_token_version.sql` | Adds `users.token_version` for JWT revocation. |

Apply a migration to the remote DB:

```bash
wrangler d1 execute keyflow-sync --remote --file=./migrations/002_token_version.sql
```

## Deploy

```bash
npm run deploy   # wrangler deploy
```

After deploy:

1. Verify `/healthz`-equivalent paths return 200.
2. Re-run the device flow from a CLI to confirm `/api/device/start` ↔ `/api/device/poll`
   (PKCE) round-trips and writes a fresh token to `~/.local/share/keyflow/sync.json`.

## Breaking change: 1-year tokens are rejected

Tokens minted before the security-hardening pass have a 365-day TTL and **lack
the `tv` (token_version) claim**. After deploy these tokens fail verification
and the CLI will report `unauthorized`. This is intentional — the user must
re-run `kf sync init` to obtain a fresh, revocable, 7-day token.

If you need to roll back this behavior in an emergency, revert
`worker/src/index.ts` to the prior commit on `master`; the schema change is
additive and does not need to be reverted.

## Rate-limit `namespace_id`

`wrangler.jsonc` declares two Cloudflare-native rate-limit buckets with
`namespace_id: "1001"` (API per user) and `"1002"` (auth per IP). These are
developer-chosen integers — they need not match any external CF ID. If you
fork the Worker into another deployment under the same account, pick distinct
`namespace_id` values so the buckets count independently.
