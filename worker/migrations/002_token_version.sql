-- Migration 002: per-user token_version for global token revocation.
--
-- token_version is included as a claim in every issued JWT. On each
-- authenticated request the worker compares the claim against the value
-- stored here; a mismatch rejects the token. Bumping this column (see the
-- /api/revoke endpoint) therefore invalidates every previously issued token
-- for that user without needing a token blacklist.

ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0;
