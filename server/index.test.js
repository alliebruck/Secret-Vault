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

async function registerUser(email, password = "correct horse battery staple") {
  const registered = await request("/auth/register", {
    method: "POST",
    body: { email, password }
  });
  assert.equal(registered.response.status, 201);
  return {
    email,
    password,
    cookie: sessionCookie(registered.response)
  };
}

async function createProject(cookie, name) {
  const project = await request("/projects", {
    method: "POST",
    cookie,
    body: { name, description: `${name} service` }
  });
  assert.equal(project.response.status, 201);
  return project.data.project;
}

async function createSecret(cookie, projectId, password, overrides = {}) {
  const created = await request("/secrets", {
    method: "POST",
    cookie,
    body: {
      projectId,
      name: overrides.name || "API_TOKEN",
      environment: overrides.environment || "dev",
      value: overrides.value || "secret-value",
      notes: overrides.notes || "",
      expiresAt: overrides.expiresAt || null,
      password
    }
  });
  assert.equal(created.response.status, 201);
  return created.data.id;
}

async function editSecret(cookie, secretId, password, overrides = {}) {
  const edited = await request(`/secrets/${secretId}`, {
    method: "PUT",
    cookie,
    body: {
      name: overrides.name || "API_TOKEN",
      environment: overrides.environment || "dev",
      value: overrides.value || "rotated-secret-value",
      notes: overrides.notes || "rotated",
      expiresAt: overrides.expiresAt || null,
      reason: overrides.reason || "Test rotation",
      password
    }
  });
  assert.equal(edited.response.status, 200);
  return edited;
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

describe("security checks", () => {
  test("protected routes require authentication", async () => {
    const routes = [
      request("/me"),
      request("/projects"),
      request("/secrets"),
      request("/audit-logs"),
      request("/secrets/1/reveal", { method: "POST", body: { password: "anything" } })
    ];

    const results = await Promise.all(routes);
    for (const result of results) {
      assert.equal(result.response.status, 401);
      assert.equal(result.data.error, "Authentication required");
    }
  });

  test("wrong master password cannot reveal or restore secrets", async () => {
    const user = await registerUser("wrong-password@example.com");
    const project = await createProject(user.cookie, "wrong-password-api");
    const secretId = await createSecret(user.cookie, project.id, user.password, {
      value: "original-secret"
    });
    await editSecret(user.cookie, secretId, user.password, {
      value: "new-secret",
      reason: "Create version for negative test"
    });

    const versions = await request(`/secrets/${secretId}/versions`, { cookie: user.cookie });
    assert.equal(versions.response.status, 200);
    const versionId = versions.data.versions[0].id;

    const reveal = await request(`/secrets/${secretId}/reveal`, {
      method: "POST",
      cookie: user.cookie,
      body: { password: "wrong password", action: "view" }
    });
    assert.equal(reveal.response.status, 401);
    assert.equal(reveal.data.error, "Password check failed");

    const restore = await request(`/secrets/${secretId}/versions/${versionId}/restore`, {
      method: "POST",
      cookie: user.cookie,
      body: { password: "wrong password" }
    });
    assert.equal(restore.response.status, 401);
    assert.equal(restore.data.error, "Password check failed");

    const current = await request(`/secrets/${secretId}/reveal`, {
      method: "POST",
      cookie: user.cookie,
      body: { password: user.password, action: "view" }
    });
    assert.equal(current.response.status, 200);
    assert.equal(current.data.value, "new-secret");
  });

  test("deleted secrets cannot be revealed", async () => {
    const user = await registerUser("delete@example.com");
    const project = await createProject(user.cookie, "delete-api");
    const secretId = await createSecret(user.cookie, project.id, user.password, {
      value: "delete-me"
    });

    const deleted = await request(`/secrets/${secretId}`, {
      method: "DELETE",
      cookie: user.cookie
    });
    assert.equal(deleted.response.status, 200);

    const revealed = await request(`/secrets/${secretId}/reveal`, {
      method: "POST",
      cookie: user.cookie,
      body: { password: user.password, action: "view" }
    });
    assert.equal(revealed.response.status, 404);
    assert.equal(revealed.data.error, "Secret not found");
  });

  test("users cannot access another user's secret or version", async () => {
    const owner = await registerUser("owner@example.com");
    const attacker = await registerUser("attacker@example.com");
    const project = await createProject(owner.cookie, "private-api");
    const secretId = await createSecret(owner.cookie, project.id, owner.password, {
      value: "owner-secret"
    });
    await editSecret(owner.cookie, secretId, owner.password, {
      value: "owner-secret-new",
      reason: "Owner rotation"
    });

    const ownerVersions = await request(`/secrets/${secretId}/versions`, { cookie: owner.cookie });
    assert.equal(ownerVersions.response.status, 200);
    const versionId = ownerVersions.data.versions[0].id;

    const listedByAttacker = await request("/secrets", { cookie: attacker.cookie });
    assert.equal(listedByAttacker.response.status, 200);
    assert.equal(listedByAttacker.data.secrets.some((secret) => secret.id === secretId), false);

    const revealByAttacker = await request(`/secrets/${secretId}/reveal`, {
      method: "POST",
      cookie: attacker.cookie,
      body: { password: attacker.password, action: "view" }
    });
    assert.equal(revealByAttacker.response.status, 404);
    assert.equal(revealByAttacker.data.error, "Secret not found");

    const versionsByAttacker = await request(`/secrets/${secretId}/versions`, {
      cookie: attacker.cookie
    });
    assert.equal(versionsByAttacker.response.status, 404);
    assert.equal(versionsByAttacker.data.error, "Secret not found");

    const restoreByAttacker = await request(`/secrets/${secretId}/versions/${versionId}/restore`, {
      method: "POST",
      cookie: attacker.cookie,
      body: { password: attacker.password }
    });
    assert.equal(restoreByAttacker.response.status, 404);
    assert.equal(restoreByAttacker.data.error, "Secret not found");
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
