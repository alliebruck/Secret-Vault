import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Clipboard,
  Eye,
  EyeOff,
  History,
  KeyRound,
  Lock,
  LogOut,
  Pencil,
  Plus,
  RefreshCcw,
  RotateCcw,
  Save,
  Search,
  ShieldCheck,
  Trash2,
  X
} from "lucide-react";
import "./styles.css";

const API = "http://localhost:4000/api";

async function api(path, options = {}) {
  const response = await fetch(`${API}${path}`, {
    credentials: "include",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
    body: options.body ? JSON.stringify(options.body) : undefined
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
}

function generateSecret(length = 40) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-+=!@#$%^&*";
  const bytes = new Uint32Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => chars[byte % chars.length]).join("");
}

function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api("/me")
      .then((data) => setUser(data.user))
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <main className="center-screen">Loading vault...</main>;
  if (!user) return <AuthScreen onAuthed={setUser} />;
  return <VaultScreen user={user} onLogout={() => setUser(null)} />;
}

function AuthScreen({ onAuthed }) {
  const [mode, setMode] = useState("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  async function submit(event) {
    event.preventDefault();
    setError("");
    try {
      const data = await api(`/auth/${mode}`, { method: "POST", body: { email, password } });
      onAuthed(data.user);
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <main className="auth-shell">
      <section className="auth-panel">
        <div className="brand-row">
          <span className="brand-mark"><ShieldCheck size={24} /></span>
          <div>
            <h1>Developer Secret Vault</h1>
            <p>Encrypted project secrets with audit visibility.</p>
          </div>
        </div>

        <div className="segmented">
          <button className={mode === "login" ? "active" : ""} onClick={() => setMode("login")}>Login</button>
          <button className={mode === "register" ? "active" : ""} onClick={() => setMode("register")}>Register</button>
        </div>

        <form onSubmit={submit} className="stack">
          <label>
            Email
            <input type="email" value={email} onChange={(event) => setEmail(event.target.value)} required />
          </label>
          <label>
            Master password
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              minLength={10}
              required
            />
          </label>
          {error && <p className="error">{error}</p>}
          <button className="primary" type="submit">
            <Lock size={18} />
            {mode === "login" ? "Unlock vault" : "Create vault"}
          </button>
        </form>
      </section>
    </main>
  );
}

function VaultScreen({ user, onLogout }) {
  const [projects, setProjects] = useState([]);
  const [secrets, setSecrets] = useState([]);
  const [logs, setLogs] = useState([]);
  const [showSecretForm, setShowSecretForm] = useState(false);
  const [query, setQuery] = useState("");
  const [environment, setEnvironment] = useState("all");
  const [selectedProject, setSelectedProject] = useState("all");
  const [notice, setNotice] = useState("");

  async function refresh() {
    const [projectData, secretData, logData] = await Promise.all([
      api("/projects"),
      api("/secrets"),
      api("/audit-logs")
    ]);
    setProjects(projectData.projects);
    setSecrets(secretData.secrets);
    setLogs(logData.logs);
  }

  useEffect(() => {
    refresh();
  }, []);

  useEffect(() => {
    if (!secrets.length) setShowSecretForm(true);
  }, [secrets.length]);

  const filteredSecrets = useMemo(() => {
    return secrets.filter((secret) => {
      const haystack = `${secret.name} ${secret.project_name} ${secret.environment} ${secret.notes}`.toLowerCase();
      return (
        haystack.includes(query.toLowerCase()) &&
        (environment === "all" || secret.environment === environment) &&
        (selectedProject === "all" || String(secret.project_id) === selectedProject)
      );
    });
  }, [secrets, query, environment, selectedProject]);

  async function logout() {
    await api("/auth/logout", { method: "POST" });
    onLogout();
  }

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand-row compact">
          <span className="brand-mark"><ShieldCheck size={22} /></span>
          <div>
            <strong>Secret Vault</strong>
            <span>{user.email}</span>
          </div>
        </div>
        <ProjectForm onCreated={refresh} />
        <button className="ghost full" onClick={logout}><LogOut size={17} /> Logout</button>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <h1>Secrets</h1>
            <p>{secrets.length} stored, {logs.length} recent audit events</p>
          </div>
          <div className="topbar-actions">
            <button className="primary" onClick={() => setShowSecretForm((current) => !current)}>
              <Plus size={17} /> {showSecretForm ? "Close form" : "Add secret"}
            </button>
            <button className="secondary" onClick={refresh}><RefreshCcw size={17} /> Refresh</button>
          </div>
        </header>

        <div className="toolbar">
          <label className="search-box">
            <Search size={18} />
            <input placeholder="Search secrets, projects, notes" value={query} onChange={(event) => setQuery(event.target.value)} />
          </label>
          <select value={selectedProject} onChange={(event) => setSelectedProject(event.target.value)}>
            <option value="all">All projects</option>
            {projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}
          </select>
          <select value={environment} onChange={(event) => setEnvironment(event.target.value)}>
            <option value="all">All envs</option>
            <option value="dev">dev</option>
            <option value="staging">staging</option>
            <option value="prod">prod</option>
          </select>
        </div>

        {notice && <p className="notice">{notice}</p>}

        <div className="content-grid">
          <section>
            {showSecretForm && (
              <SecretForm
                projects={projects}
                onCreated={() => {
                  setShowSecretForm(false);
                  refresh();
                }}
              />
            )}
            <div className="secret-list">
              {filteredSecrets.map((secret) => (
                <SecretCard
                  key={secret.id}
                  secret={secret}
                  onChanged={refresh}
                  onNotice={setNotice}
                />
              ))}
              {filteredSecrets.length === 0 && <div className="empty-state">No matching secrets.</div>}
            </div>
          </section>
          <AuditPanel logs={logs} />
        </div>
      </section>
    </main>
  );
}

function ProjectForm({ onCreated }) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState("");

  async function submit(event) {
    event.preventDefault();
    setError("");
    try {
      await api("/projects", { method: "POST", body: { name, description } });
      setName("");
      setDescription("");
      onCreated();
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <form className="sidebar-form" onSubmit={submit}>
      <h2>New project</h2>
      <input placeholder="billing-api" value={name} onChange={(event) => setName(event.target.value)} required />
      <textarea placeholder="Short description" value={description} onChange={(event) => setDescription(event.target.value)} />
      {error && <p className="error">{error}</p>}
      <button className="primary" type="submit"><Plus size={17} /> Add project</button>
    </form>
  );
}

function SecretForm({ projects, onCreated }) {
  const [form, setForm] = useState({
    projectId: "",
    name: "",
    environment: "dev",
    value: "",
    notes: "",
    expiresAt: "",
    password: ""
  });
  const [error, setError] = useState("");

  useEffect(() => {
    if (!form.projectId && projects[0]) setForm((current) => ({ ...current, projectId: String(projects[0].id) }));
  }, [projects, form.projectId]);

  function update(field, value) {
    setForm((current) => ({ ...current, [field]: value }));
  }

  async function submit(event) {
    event.preventDefault();
    setError("");
    try {
      await api("/secrets", { method: "POST", body: form });
      setForm((current) => ({ ...current, name: "", value: "", notes: "", expiresAt: "", password: "" }));
      onCreated();
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <form className="tool-panel" onSubmit={submit}>
      <div className="panel-heading">
        <h2>Add encrypted secret</h2>
        <button type="button" className="secondary" onClick={() => update("value", generateSecret())}>
          <KeyRound size={17} /> Generate
        </button>
      </div>
      <div className="form-grid">
        <label>
          Project
          <select value={form.projectId} onChange={(event) => update("projectId", event.target.value)} required>
            {projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}
          </select>
        </label>
        <label>
          Environment
          <select value={form.environment} onChange={(event) => update("environment", event.target.value)}>
            <option value="dev">dev</option>
            <option value="staging">staging</option>
            <option value="prod">prod</option>
          </select>
        </label>
        <label>
          Secret name
          <input placeholder="STRIPE_SECRET_KEY" value={form.name} onChange={(event) => update("name", event.target.value)} required />
        </label>
        <label>
          Rotation date
          <input type="date" value={form.expiresAt} onChange={(event) => update("expiresAt", event.target.value)} />
        </label>
      </div>
      <label>
        Secret value
        <textarea value={form.value} onChange={(event) => update("value", event.target.value)} required />
      </label>
      <label>
        Rotation notes
        <textarea value={form.notes} onChange={(event) => update("notes", event.target.value)} />
      </label>
      <label>
        Re-enter master password
        <input type="password" value={form.password} onChange={(event) => update("password", event.target.value)} required />
      </label>
      {error && <p className="error">{error}</p>}
      <button className="primary" type="submit" disabled={!projects.length}>
        <Lock size={17} /> Encrypt and save
      </button>
    </form>
  );
}

function SecretCard({ secret, onChanged, onNotice }) {
  const [password, setPassword] = useState("");
  const [revealed, setRevealed] = useState("");
  const [editing, setEditing] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [versions, setVersions] = useState([]);
  const [versionValues, setVersionValues] = useState({});
  const [error, setError] = useState("");
  const [editForm, setEditForm] = useState({
    name: secret.name,
    environment: secret.environment,
    value: "",
    notes: secret.notes || "",
    expiresAt: secret.expires_at || "",
    reason: "Rotated secret value"
  });

  useEffect(() => {
    setEditForm({
      name: secret.name,
      environment: secret.environment,
      value: revealed || "",
      notes: secret.notes || "",
      expiresAt: secret.expires_at || "",
      reason: "Rotated secret value"
    });
  }, [secret, revealed]);

  async function reveal(action = "view") {
    setError("");
    try {
      const data = await api(`/secrets/${secret.id}/reveal`, {
        method: "POST",
        body: { password, action }
      });
      setRevealed(data.value);
      if (action === "copy") {
        await navigator.clipboard.writeText(data.value);
        onNotice(`Copied ${secret.name}`);
      }
      onChanged();
    } catch (err) {
      setError(err.message);
    }
  }

  async function remove() {
    await api(`/secrets/${secret.id}`, { method: "DELETE" });
    onChanged();
  }

  async function saveEdit(event) {
    event.preventDefault();
    setError("");
    try {
      await api(`/secrets/${secret.id}`, {
        method: "PUT",
        body: { ...editForm, password }
      });
      setEditing(false);
      setRevealed("");
      onNotice(`Updated ${editForm.name}`);
      onChanged();
    } catch (err) {
      setError(err.message);
    }
  }

  async function loadVersions() {
    setError("");
    try {
      const data = await api(`/secrets/${secret.id}/versions`);
      setVersions(data.versions);
      setShowHistory(true);
    } catch (err) {
      setError(err.message);
    }
  }

  async function revealVersion(versionId) {
    setError("");
    try {
      const data = await api(`/secrets/${secret.id}/versions/${versionId}/reveal`, {
        method: "POST",
        body: { password }
      });
      setVersionValues((current) => ({ ...current, [versionId]: data.value }));
      onChanged();
    } catch (err) {
      setError(err.message);
    }
  }

  async function restoreVersion(version) {
    setError("");
    try {
      await api(`/secrets/${secret.id}/versions/${version.id}/restore`, {
        method: "POST",
        body: { password }
      });
      setShowHistory(false);
      setVersionValues({});
      setRevealed("");
      onNotice(`Restored ${secret.name} to v${version.version_number}`);
      onChanged();
    } catch (err) {
      setError(err.message);
    }
  }

  function updateEdit(field, value) {
    setEditForm((current) => ({ ...current, [field]: value }));
  }

  const expired = secret.expires_at && new Date(secret.expires_at) < new Date();

  return (
    <article className={`secret-card ${expired ? "expired" : ""}`}>
      <div className="secret-main">
        <div>
          <h3>{secret.name}</h3>
          <p>{secret.project_name} / {secret.environment}</p>
        </div>
        <span className="pill">{expired ? "rotation due" : secret.expires_at || "no expiry"}</span>
      </div>
      {secret.notes && <p className="notes">{secret.notes}</p>}
      <div className="reveal-row">
        <input
          type="password"
          placeholder="Master password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
        />
        <button className="action-button" title="Reveal secret" onClick={() => reveal("view")}><Eye size={17} /> Reveal</button>
        <button className="action-button" title="Copy secret" onClick={() => reveal("copy")}><Clipboard size={17} /> Copy</button>
        <button className="action-button" title="Edit secret" onClick={() => setEditing((current) => !current)}><Pencil size={17} /> Edit</button>
        <button className="action-button" title="Version history" onClick={showHistory ? () => setShowHistory(false) : loadVersions}><History size={17} /> History</button>
        <button className="action-button danger" title="Delete secret" onClick={remove}><Trash2 size={17} /> Delete</button>
      </div>
      {revealed && (
        <pre className="secret-value">
          <button className="hide-button" onClick={() => setRevealed("")} title="Hide secret"><EyeOff size={16} /></button>
          {revealed}
        </pre>
      )}
      {editing && (
        <form className="edit-panel" onSubmit={saveEdit}>
          <div className="panel-heading">
            <h4>Edit secret</h4>
            <button className="ghost compact-button" type="button" onClick={() => setEditing(false)}>
              <X size={16} /> Cancel
            </button>
          </div>
          <div className="form-grid">
            <label>
              Secret name
              <input value={editForm.name} onChange={(event) => updateEdit("name", event.target.value)} required />
            </label>
            <label>
              Environment
              <select value={editForm.environment} onChange={(event) => updateEdit("environment", event.target.value)}>
                <option value="dev">dev</option>
                <option value="staging">staging</option>
                <option value="prod">prod</option>
              </select>
            </label>
            <label>
              Rotation date
              <input type="date" value={editForm.expiresAt || ""} onChange={(event) => updateEdit("expiresAt", event.target.value)} />
            </label>
            <label>
              Change reason
              <input value={editForm.reason} onChange={(event) => updateEdit("reason", event.target.value)} />
            </label>
          </div>
          <label>
            Secret value
            <textarea value={editForm.value} onChange={(event) => updateEdit("value", event.target.value)} required />
          </label>
          <label>
            Rotation notes
            <textarea value={editForm.notes} onChange={(event) => updateEdit("notes", event.target.value)} />
          </label>
          <button className="primary" type="submit"><Save size={17} /> Save new version</button>
        </form>
      )}
      {showHistory && (
        <VersionHistory
          versions={versions}
          versionValues={versionValues}
          onReveal={revealVersion}
          onRestore={restoreVersion}
        />
      )}
      {error && <p className="error">{error}</p>}
    </article>
  );
}

function VersionHistory({ versions, versionValues, onReveal, onRestore }) {
  if (!versions.length) {
    return <div className="history-panel empty-history">No previous versions yet.</div>;
  }

  return (
    <div className="history-panel">
      <h4>Version history</h4>
      {versions.map((version) => (
        <div className="version-row" key={version.id}>
          <div>
            <strong>v{version.version_number}: {version.name}</strong>
            <span>{version.environment} / {version.reason || "No reason"}</span>
            <time>{new Date(version.created_at).toLocaleString()}</time>
          </div>
          <div className="version-actions">
            <button className="secondary compact-button" type="button" onClick={() => onReveal(version.id)}>
              <Eye size={16} /> Reveal
            </button>
            <button className="secondary compact-button" type="button" onClick={() => onRestore(version)}>
              <RotateCcw size={16} /> Restore
            </button>
          </div>
          {versionValues[version.id] && <pre className="secret-value history-value">{versionValues[version.id]}</pre>}
        </div>
      ))}
    </div>
  );
}

function AuditPanel({ logs }) {
  return (
    <aside className="audit-panel">
      <h2>Audit log</h2>
      <div className="audit-list">
        {logs.map((log) => (
          <div key={log.id} className="audit-row">
            <strong>{log.action}</strong>
            <span>{log.entity_type}{log.entity_id ? ` #${log.entity_id}` : ""}</span>
            <time>{new Date(log.created_at).toLocaleString()}</time>
          </div>
        ))}
      </div>
    </aside>
  );
}

createRoot(document.getElementById("root")).render(<App />);
