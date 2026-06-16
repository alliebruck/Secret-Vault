import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";

const tempDir = mkdtempSync(join(tmpdir(), "vault-api-test-"));
process.env.VAULT_DB_PATH = join(tempDir, "vault.db");

const { app } = await import("./index.js");
const { db } = await import("./db.js");

let server;
let baseUrl;

before(async () => {
  server = app.listen(0);
  await new Promise((resolve) => server.once("listening", resolve));
  const address = server.address();
  baseUrl = `http://127.0.0.1:${address.port}/api`;
});

after(async () => {
  await new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
  db.close();
  rmSync(tempDir, { recursive: true, force: true });
});

async function request(path, { method = "GET", body, cookie, token } = {}) {
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers: {
      "content-type": "application/json",
      ...(cookie ? { cookie } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {})
    },
    body: body ? JSON.stringify(body) : undefined
  });
  const data = await response.json();
  return { response, data };
}

function sessionCookie(response) {
  const cookie = response.headers.get("set-cookie");
  assert.ok(cookie, "expected session cookie");
  return cookie.split(";")[0];
}

describe("secret version history", () => {
  test("stores previous encrypted versions that can be revealed and restored", async () => {
    const email = "dev@example.com";
    const password = "correct horse battery staple";

    const registered = await request("/auth/register", {
      method: "POST",
      body: { email, password }
    });
    assert.equal(registered.response.status, 201);
    const cookie = sessionCookie(registered.response);

    const project = await request("/projects", {
      method: "POST",
      cookie,
      body: { name: "billing-api", description: "Billing service" }
    });
    assert.equal(project.response.status, 201);

    const created = await request("/secrets", {
      method: "POST",
      cookie,
      body: {
        projectId: project.data.project.id,
        name: "STRIPE_SECRET_KEY",
        environment: "dev",
        value: "sk_test_old",
        notes: "initial key",
        expiresAt: "2026-12-31",
        password
      }
    });
    assert.equal(created.response.status, 201);

    const secretId = created.data.id;
    const firstSecretRow = db.prepare("SELECT encrypted_value FROM secrets WHERE id = ?").get(secretId);
    assert.ok(firstSecretRow.encrypted_value.includes("AES-256-GCM"));
    assert.ok(!firstSecretRow.encrypted_value.includes("sk_test_old"));

    const edited = await request(`/secrets/${secretId}`, {
      method: "PUT",
      cookie,
      body: {
        name: "STRIPE_SECRET_KEY",
        environment: "dev",
        value: "sk_test_new",
        notes: "rotated key",
        expiresAt: "2027-01-31",
        reason: "Quarterly rotation",
        password
      }
    });
    assert.equal(edited.response.status, 200);

    const versionRows = db.prepare("SELECT * FROM secret_versions WHERE secret_id = ?").all(secretId);
    assert.equal(versionRows.length, 1);
    assert.equal(versionRows[0].version_number, 1);
    assert.equal(versionRows[0].reason, "Quarterly rotation");
    assert.equal(versionRows[0].notes, "initial key");
    assert.ok(versionRows[0].encrypted_value.includes("AES-256-GCM"));
    assert.ok(!versionRows[0].encrypted_value.includes("sk_test_old"));

    const versions = await request(`/secrets/${secretId}/versions`, { cookie });
    assert.equal(versions.response.status, 200);
    assert.equal(versions.data.versions.length, 1);
    assert.equal(versions.data.versions[0].version_number, 1);
    assert.equal(versions.data.versions[0].encrypted_value, undefined);

    const revealedVersion = await request(`/secrets/${secretId}/versions/${versions.data.versions[0].id}/reveal`, {
      method: "POST",
      cookie,
      body: { password }
    });
    assert.equal(revealedVersion.response.status, 200);
    assert.equal(revealedVersion.data.value, "sk_test_old");

    const restored = await request(`/secrets/${secretId}/versions/${versions.data.versions[0].id}/restore`, {
      method: "POST",
      cookie,
      body: { password }
    });
    assert.equal(restored.response.status, 200);

    const revealedCurrent = await request(`/secrets/${secretId}/reveal`, {
      method: "POST",
      cookie,
      body: { password, action: "view" }
    });
    assert.equal(revealedCurrent.response.status, 200);
    assert.equal(revealedCurrent.data.value, "sk_test_old");

    const allVersionRows = db
      .prepare("SELECT reason FROM secret_versions WHERE secret_id = ? ORDER BY version_number")
      .all(secretId);
    assert.deepEqual(
      allVersionRows.map((row) => row.reason),
      ["Quarterly rotation", "Before restore to v1"]
    );

    const auditActions = db
      .prepare("SELECT action FROM audit_logs ORDER BY id")
      .all()
      .map((row) => row.action);
    assert.ok(auditActions.includes("created"));
    assert.ok(auditActions.includes("edited"));
    assert.ok(auditActions.includes("viewed_version"));
    assert.ok(auditActions.includes("restored_version"));
    assert.ok(auditActions.includes("viewed"));
  });
});

describe("CLI sessions", () => {
  test("logout revokes bearer tokens", async () => {
    const registered = await request("/auth/register", {
      method: "POST",
      body: {
        email: "cli@example.com",
        password: "correct horse battery staple",
        client: "cli"
      }
    });
    assert.equal(registered.response.status, 201);
    assert.ok(registered.data.sessionToken);

    const authenticated = await request("/me", { token: registered.data.sessionToken });
    assert.equal(authenticated.response.status, 200);
    assert.equal(authenticated.data.user.email, "cli@example.com");

    const loggedOut = await request("/auth/logout", {
      method: "POST",
      token: registered.data.sessionToken
    });
    assert.equal(loggedOut.response.status, 200);

    const afterLogout = await request("/me", { token: registered.data.sessionToken });
    assert.equal(afterLogout.response.status, 401);
  });
});
