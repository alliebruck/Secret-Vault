# Threat Model

## Scope

Developer Secret Vault is a local portfolio application for storing developer secrets by project and environment. This threat model covers the current React, Express, SQLite, and Node.js CLI implementation.

This project is not production secrets infrastructure. The goal is to demonstrate secure design decisions, identify realistic risks, and document future hardening work.

## Assets

- User master passwords
- Password hashes
- Vault encryption keys
- API keys, database passwords, OAuth secrets, JWT secrets, SSH keys, and other stored secrets
- Encrypted secret version history
- Browser session tokens
- CLI bearer tokens
- Audit logs
- Local SQLite database

## Trust Boundaries

- Browser to Express API over HTTP in local development
- CLI to Express API over HTTP in local development
- Express API to SQLite database
- CLI to local filesystem at `~/.vaultx/config.json`
- User-entered master password to server-side vault-key unwrap logic

## Assumptions

- The app is run locally for demo and development.
- Users choose a strong master password.
- The local machine is not fully compromised.
- The database may be copied or leaked, so plaintext secret values should not be present in SQLite.
- The server process is trusted while running.

## Threats Considered

### Database Disclosure

An attacker obtains `data/vault.db`.

Impact:

- Secret metadata such as names, environments, project names, notes, timestamps, and audit logs may be exposed.
- Secret values should remain encrypted.
- Password hashes may be exposed and could be attacked offline.

Controls:

- Secret values are encrypted with AES-256-GCM before storage.
- Previous secret versions are also encrypted.
- Passwords are hashed with Argon2id.
- Vault keys are encrypted with a key derived from the user's master password.

### Password Guessing

An attacker attempts to guess a user's login password.

Controls:

- Passwords are hashed with Argon2id.
- Login attempts are rate limited.
- Master-password re-entry is required before sensitive secret actions.

Current gaps:

- MFA is not implemented.
- Account lockout and suspicious login alerts are not implemented.

### Unauthorized Secret Access

An authenticated user or attacker attempts to access secrets they do not own.

Controls:

- Secret, project, version, and audit queries are scoped by authenticated user id.
- Sensitive API routes require authentication.
- Reveal and restore operations require master-password verification.

Current gaps:

- Team sharing and RBAC are not implemented yet.
- There are no workspace-level access policies.

### Session Theft

An attacker steals a browser session token or CLI session token.

Controls:

- Browser sessions use HTTP-only cookies.
- CLI commands that decrypt secret values still require the master password.
- CLI does not store the master password.

Current gaps:

- CLI token logout and rotation are not implemented yet.
- Session timeout controls are basic.
- Local development uses HTTP, not HTTPS.

### Secret Misuse or Accidental Exposure

A user accidentally reveals, copies, edits, deletes, or restores a secret.

Controls:

- Sensitive actions are audit logged.
- Secret values are hidden by default.
- Reveal/copy/edit/restore require master-password re-entry.
- Version history allows restoring previous encrypted versions.

Current gaps:

- No approval workflow for destructive changes.
- No alerting for unusual access patterns.

### CLI Config Exposure

An attacker reads `~/.vaultx/config.json`.

Impact:

- The attacker may obtain the CLI session token.
- The token alone should not decrypt secrets because `get` and `run` require the master password.

Controls:

- CLI config is written with restrictive file permissions where supported.
- Master password is never stored by the CLI.

Current gaps:

- CLI logout is not implemented.
- Token expiration and rotation are not exposed through the CLI.

## Security Controls

- Argon2id password hashing
- AES-256-GCM secret encryption
- Per-user random vault key
- Vault key wrapping with a password-derived key
- HTTP-only browser sessions
- Bearer-token CLI sessions
- Master-password re-entry for sensitive operations
- Audit logging for reveal, copy, create, edit, delete, version reveal, and restore actions
- Login rate limiting
- User-scoped database queries

## Known Limitations

- Not production hardened
- No MFA/TOTP yet
- No team sharing or RBAC yet
- No hosted HTTPS deployment
- SQLite local storage only
- Uses Node's experimental `node:sqlite` module
- Metadata is not encrypted
- CLI session token management is minimal
- No automated security tests yet

## Future Hardening

- Add TOTP MFA and recovery codes
- Add CLI logout and token rotation
- Add team workspaces and RBAC
- Add secret access policies
- Add PostgreSQL support
- Add Docker Compose deployment
- Add HTTPS production deployment guidance
- Encrypt more metadata where practical
- Add automated tests for authorization boundaries
- Add suspicious activity alerts
- Add backup and recovery design
