# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.9.x   | ✅ |
| < 0.9   | ❌ |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

KeyFlow handles encrypted secrets — any vulnerability that could expose vault contents, weaken encryption, or allow unauthorized access is treated as critical.

### How to Report

Open a [GitHub Security Advisory](https://github.com/nianyi778/keyflow/security/advisories/new) (private, only visible to maintainers).

Include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fix (optional)

### What to Expect

- **Acknowledgement** within 48 hours
- **Status update** within 7 days
- **Fix timeline** communicated once the issue is triaged
- Credit in the release notes (if desired)

## Scope

In scope:
- Vault encryption / key derivation weaknesses
- MCP server exposing secret values instead of metadata
- `kf run` leaking plaintext secrets outside the child process
- Cloud sync exposing plaintext to the server
- Path traversal or injection in `kf import` / `kf scan`

Out of scope:
- Issues in dependencies (report upstream; we will update promptly)
- Theoretical attacks requiring physical access to the machine
- Social engineering

## Security Design Notes

- Vault is encrypted with **AES-256-GCM**, key derived with **Argon2id**
- The sync server never receives plaintext — all encryption/decryption is local
- `kf get` masks values by default; `--raw` is required to reveal
- MCP tools expose only metadata (name, provider, project, status) — never secret values
