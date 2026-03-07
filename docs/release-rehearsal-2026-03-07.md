# KeyFlow Release Rehearsal

> Date: 2026-03-07
> Scope: automatic pre-release verification for the current core-only KeyFlow
> Operator: Codex

## Result

Automatic verification passed. The current build is ready for manual smoke checks.

## Commands Run

The following commands completed successfully:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo run --quiet --bin kf -- help
```

## Verified Automatically

- code formatting is clean
- clippy reports no warnings under `-D warnings`
- test suite passes
- CLI binary starts and shows help output
- current docs set exists for:
  - `README.md`
  - `docs/mcp-contract.md`
  - `docs/release-checklist.md`

## Manual Smoke Checks Still Required

These items were intentionally not executed during this rehearsal to avoid mutating a real local vault or user config:

- `kf init` against a fresh vault path
- `kf add`, `kf get`, `kf update`, `kf remove` against a throwaway vault
- `kf import`, `kf export`, `kf scan`, `kf run` against a sample project
- `kf backup` and `kf restore` with current backup format
- `kf setup` writing real MCP config files for target AI clients
- `kf serve` against a real unlocked vault
- `kf serve --transport http --host 127.0.0.1 --port 8765`
- `GET /healthz` and `POST /mcp` against the running HTTP transport
- explicit rejection check for non-loopback bind without `KEYFLOW_ALLOW_REMOTE_HTTP=1`

## Release Checklist Status

- product boundary: no regression found in automatic verification
- CLI build health: pass
- MCP build health: pass
- HTTP transport compile/test coverage: pass
- docs baseline: present
- release decision: not blocked by automated checks

## Conclusion

KeyFlow is in a clean automated-release state. Proceed to manual smoke validation before tagging a release.
