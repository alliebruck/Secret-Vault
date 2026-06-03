import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";

const __dirname = dirname(fileURLToPath(import.meta.url));
const dataDir = join(__dirname, "..", "data");
mkdirSync(dataDir, { recursive: true });

export const db = new DatabaseSync(join(dataDir, "vault.db"));

db.exec(`
  PRAGMA foreign_keys = ON;

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    vault_key_salt TEXT NOT NULL,
    encrypted_vault_key TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, name)
  );

  CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    environment TEXT NOT NULL,
    encrypted_value TEXT NOT NULL,
    notes TEXT NOT NULL DEFAULT '',
    expires_at TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(project_id, name, environment)
  );

  CREATE TABLE IF NOT EXISTS secret_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    secret_id INTEGER NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    version_number INTEGER NOT NULL,
    name TEXT NOT NULL,
    environment TEXT NOT NULL,
    encrypted_value TEXT NOT NULL,
    notes TEXT NOT NULL DEFAULT '',
    expires_at TEXT,
    reason TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(secret_id, version_number)
  );

  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id INTEGER,
    metadata TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

export function getSessionUser(tokenHash) {
  return db
    .prepare(`
      SELECT users.id, users.email
      FROM sessions
      JOIN users ON users.id = sessions.user_id
      WHERE sessions.token_hash = ? AND sessions.expires_at > datetime('now')
    `)
    .get(tokenHash);
}

export function logAudit(userId, action, entityType, entityId = null, metadata = {}) {
  db.prepare(`
    INSERT INTO audit_logs (user_id, action, entity_type, entity_id, metadata)
    VALUES (?, ?, ?, ?, ?)
  `).run(userId, action, entityType, entityId, JSON.stringify(metadata));
}
