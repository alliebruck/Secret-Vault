import argon2 from "argon2";
import cookieParser from "cookie-parser";
import cors from "cors";
import express from "express";
import rateLimit from "express-rate-limit";
import { db, getSessionUser, logAudit } from "./db.js";
import {
  decryptJson,
  encryptJson,
  hashToken,
  makeVaultKeyEnvelope,
  randomToken,
  unwrapVaultKey
} from "./crypto.js";

const app = express();
const PORT = process.env.PORT || 4000;
const SESSION_DAYS = 7;

app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());
app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true
  })
);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 12,
  standardHeaders: true,
  legacyHeaders: false
});

function sessionCookieOptions() {
  return {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: SESSION_DAYS * 24 * 60 * 60 * 1000
  };
}

function requireAuth(req, res, next) {
  const token = req.cookies.session;
  if (!token) return res.status(401).json({ error: "Authentication required" });

  const user = getSessionUser(hashToken(token));
  if (!user) return res.status(401).json({ error: "Authentication required" });

  req.user = user;
  next();
}

async function verifyPasswordAndGetVaultKey(userId, password) {
  const user = db
    .prepare("SELECT * FROM users WHERE id = ?")
    .get(userId);

  if (!user || !(await argon2.verify(user.password_hash, password))) {
    throw new Error("Invalid password");
  }

  return unwrapVaultKey(password, user.vault_key_salt, user.encrypted_vault_key);
}

function createSession(userId, res) {
  const token = randomToken();
  const tokenHash = hashToken(token);
  const expiresAt = new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000).toISOString();

  db.prepare(`
    INSERT INTO sessions (user_id, token_hash, expires_at)
    VALUES (?, ?, ?)
  `).run(userId, tokenHash, expiresAt);

  res.cookie("session", token, sessionCookieOptions());
}

app.get("/api/health", (_req, res) => {
  res.json({ ok: true });
});

app.post("/api/auth/register", authLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password || password.length < 10) {
    return res.status(400).json({ error: "Use an email and a password with at least 10 characters" });
  }

  const passwordHash = await argon2.hash(password, { type: argon2.argon2id });
  const envelope = makeVaultKeyEnvelope(password);

  try {
    const result = db.prepare(`
      INSERT INTO users (email, password_hash, vault_key_salt, encrypted_vault_key)
      VALUES (?, ?, ?, ?)
    `).run(email.toLowerCase(), passwordHash, envelope.salt, envelope.encryptedVaultKey);

    createSession(result.lastInsertRowid, res);
    logAudit(result.lastInsertRowid, "registered", "user", result.lastInsertRowid);
    res.status(201).json({ user: { id: result.lastInsertRowid, email: email.toLowerCase() } });
  } catch (error) {
    res.status(409).json({ error: "That email is already registered" });
  }
});

app.post("/api/auth/login", authLimiter, async (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(String(email || "").toLowerCase());

  if (!user || !(await argon2.verify(user.password_hash, password || ""))) {
    return res.status(401).json({ error: "Invalid email or password" });
  }

  createSession(user.id, res);
  logAudit(user.id, "logged_in", "user", user.id);
  res.json({ user: { id: user.id, email: user.email } });
});

app.post("/api/auth/logout", requireAuth, (req, res) => {
  const token = req.cookies.session;
  db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(hashToken(token));
  res.clearCookie("session", sessionCookieOptions());
  logAudit(req.user.id, "logged_out", "user", req.user.id);
  res.json({ ok: true });
});

app.get("/api/me", requireAuth, (req, res) => {
  res.json({ user: req.user });
});

app.get("/api/projects", requireAuth, (req, res) => {
  const projects = db
    .prepare("SELECT * FROM projects WHERE user_id = ? ORDER BY name")
    .all(req.user.id);
  res.json({ projects });
});

app.post("/api/projects", requireAuth, (req, res) => {
  const name = String(req.body.name || "").trim();
  const description = String(req.body.description || "").trim();
  if (!name) return res.status(400).json({ error: "Project name is required" });

  try {
    const result = db.prepare(`
      INSERT INTO projects (user_id, name, description)
      VALUES (?, ?, ?)
    `).run(req.user.id, name, description);
    logAudit(req.user.id, "created", "project", result.lastInsertRowid, { name });
    res.status(201).json({ project: { id: result.lastInsertRowid, name, description } });
  } catch (error) {
    res.status(409).json({ error: "Project already exists" });
  }
});

app.get("/api/secrets", requireAuth, (req, res) => {
  const secrets = db.prepare(`
    SELECT secrets.id, secrets.project_id, projects.name AS project_name, secrets.name,
           secrets.environment, secrets.notes, secrets.expires_at, secrets.updated_at, secrets.created_at
    FROM secrets
    JOIN projects ON projects.id = secrets.project_id
    WHERE secrets.user_id = ?
    ORDER BY projects.name, secrets.environment, secrets.name
  `).all(req.user.id);

  res.json({ secrets });
});

app.post("/api/secrets", requireAuth, async (req, res) => {
  const { projectId, name, environment, value, notes, expiresAt, password } = req.body;
  if (!projectId || !name || !environment || !value || !password) {
    return res.status(400).json({ error: "Project, name, environment, value, and password are required" });
  }

  const project = db
    .prepare("SELECT id FROM projects WHERE id = ? AND user_id = ?")
    .get(projectId, req.user.id);
  if (!project) return res.status(404).json({ error: "Project not found" });

  try {
    const vaultKey = await verifyPasswordAndGetVaultKey(req.user.id, password);
    const encryptedValue = encryptJson(String(value), vaultKey);
    const result = db.prepare(`
      INSERT INTO secrets (user_id, project_id, name, environment, encrypted_value, notes, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      req.user.id,
      projectId,
      String(name).trim(),
      String(environment).trim(),
      encryptedValue,
      String(notes || "").trim(),
      expiresAt || null
    );

    logAudit(req.user.id, "created", "secret", result.lastInsertRowid, { name, environment });
    res.status(201).json({ id: result.lastInsertRowid });
  } catch (error) {
    res.status(401).json({ error: "Password check failed" });
  }
});

app.post("/api/secrets/:id/reveal", requireAuth, async (req, res) => {
  const secret = db
    .prepare("SELECT * FROM secrets WHERE id = ? AND user_id = ?")
    .get(req.params.id, req.user.id);
  if (!secret) return res.status(404).json({ error: "Secret not found" });

  try {
    const vaultKey = await verifyPasswordAndGetVaultKey(req.user.id, req.body.password || "");
    const value = decryptJson(secret.encrypted_value, vaultKey);
    logAudit(req.user.id, req.body.action === "copy" ? "copied" : "viewed", "secret", secret.id, {
      name: secret.name,
      environment: secret.environment
    });
    res.json({ value });
  } catch (error) {
    res.status(401).json({ error: "Password check failed" });
  }
});

app.delete("/api/secrets/:id", requireAuth, (req, res) => {
  const secret = db
    .prepare("SELECT id, name, environment FROM secrets WHERE id = ? AND user_id = ?")
    .get(req.params.id, req.user.id);
  if (!secret) return res.status(404).json({ error: "Secret not found" });

  db.prepare("DELETE FROM secrets WHERE id = ? AND user_id = ?").run(secret.id, req.user.id);
  logAudit(req.user.id, "deleted", "secret", secret.id, {
    name: secret.name,
    environment: secret.environment
  });
  res.json({ ok: true });
});

app.get("/api/audit-logs", requireAuth, (req, res) => {
  const logs = db.prepare(`
    SELECT * FROM audit_logs
    WHERE user_id = ?
    ORDER BY created_at DESC
    LIMIT 100
  `).all(req.user.id);
  res.json({ logs });
});

app.listen(PORT, () => {
  console.log(`API listening on http://localhost:${PORT}`);
});
