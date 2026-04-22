# Contributing to KeyFlow

Thanks for your interest in contributing! KeyFlow is a local-first developer tool — contributions that keep it fast, secure, and focused are especially welcome.

## Quick Start

```bash
git clone https://github.com/nianyi778/keyflow
cd keyflow
cargo build
cargo test
```

Requires Rust stable (1.75+). No external dependencies beyond what's in `Cargo.toml`.

## Ways to Contribute

- **Bug reports** — open an issue with the bug report template
- **Feature requests** — open an issue with the feature request template
- **Pull requests** — see the PR guidelines below
- **Documentation** — fix typos, improve examples, clarify behavior

## PR Guidelines

1. **One concern per PR.** A rename feature and a refactor should be separate PRs.
2. **Tests required for new behavior.** Add or update tests in `tests/` or inline `#[cfg(test)]` blocks.
3. **No new dependencies without discussion.** KeyFlow stays lean by design.
4. **Run before pushing:**

```bash
cargo fmt
cargo clippy -- -D warnings
cargo test
```

5. **Commit messages** use the conventional format: `feat:`, `fix:`, `refactor:`, `docs:`, `chore:`, `test:`.

## Architecture Overview

```
src/
  cli.rs           # Clap argument definitions
  lib.rs           # Command dispatch (cli args → command functions)
  commands/
    secrets.rs     # CLI commands: add, get, update, remove, search, …
    sync.rs        # Cloud sync pull/push logic
    auth.rs        # Vault open / passphrase helpers
  services/
    secrets.rs     # Business logic — the only layer that talks to db.rs
  db.rs            # SQLite persistence (rusqlite)
  crypto.rs        # AES-256-GCM encryption, Argon2 key derivation
  mcp/             # MCP server (protocol, tools, service)
  models.rs        # Shared data types
```

The rule: **CLI → service → DB**. Commands call service methods; service methods call db methods. Never call `db` directly from commands.

## Security

If you find a vulnerability, please report it privately via [SECURITY.md](SECURITY.md) rather than opening a public issue.

## License

By contributing, you agree your contributions are licensed under the [MIT License](LICENSE).
