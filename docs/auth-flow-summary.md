## KeyFlow Cloud Auth Summary

1. **Deploy requirements**  
   - Worker secrets: `JWT_SECRET`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`.  
   - GitHub OAuth App callback: `/auth/github/callback` on whichever domain (`https://keyflow.divinations.top` or self-hosted).  
   - Wrangler config notes include callback URL reminder and the secret list.

2. **CLI auth commands**  
   - `kf auth login`: device flow → opens `/login?user_code=…` → GitHub OAuth → `/me` + CLI session token.  
   - `kf auth login --user-id <id>`: manual fallback.  
   - `kf auth status` / `kf auth logout` manage saved login state.

3. **Cloud sync flow**  
   - `kf sync init` now reuses any local login, avoiding extra registration.  
   - `kf sync run/push/pull` continue to encrypt blobs and respect remote empty state.

4. **Worker pages/APIs**  
   - `/`: tri-language Vault Ledger landing page.  
   - `/login`: device login UI with GitHub CTA and current-browser reuse.  
   - `/me`: identity dashboard with GitHub profile, sync stats, session list, revoke buttons (with tri-language copy).  
   - `/auth/github/start`, `/auth/github/callback`: OAuth flow stores GitHub profile, creates sessions, approves device flows.  
   - `/api/device/*`, `/api/me`, `/api/logout`, `/api/sessions/:id` handle device flow, session listing, revocation.

5. **Session handling**
   - JWTs now include `session_id` and sessions are persisted in KV for status updates/revocation.  
   - CLI sessions vs web sessions distinguished (type/label/user agent).  
   - `/me` renders current session badge and shows device list; revoking clears KV entry.

6. **Next steps captured**
   - GitHub OAuth config note already in README.  
   - Consider adding session naming + CLI session list/revoke commands later.

