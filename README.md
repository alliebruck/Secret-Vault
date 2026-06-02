# Developer Secret Vault

A resume-focused full-stack security project for managing developer secrets.

## Current MVP

- User registration and login
- Argon2id password hashing
- HTTP-only cookie sessions
- SQLite local database
- Project folders and environments
- AES-256-GCM encrypted secret values
- Password re-entry before creating or revealing a secret
- Copy/reveal audit logging
- Search/filter UI
- Strong secret generator

## Run Locally

```bash
npm install
npm run dev
```

The API runs on `http://localhost:4000` and the web app runs on the Vite URL shown in the terminal.

## Security Notes

This project is designed as a portfolio-grade demo, not production security software. The core pattern is intentionally defensible:

- User passwords are hashed with Argon2id.
- Each user receives a random vault key.
- The vault key is encrypted with a key derived from the user's master password.
- Secret values are encrypted with AES-256-GCM before they are written to the database.
- Sensitive reads and writes require password re-entry and create audit events.

Good next additions: TOTP MFA, team sharing/RBAC, a CLI, and secret version history.
