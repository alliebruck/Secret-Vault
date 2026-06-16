#!/usr/bin/env node
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { spawn } from "node:child_process";
import readline from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";

const CONFIG_PATH = join(homedir(), ".vaultx", "config.json");
const DEFAULT_API_URL = "http://localhost:4000/api";

function printHelp() {
  console.log(`
vaultx - Developer Secret Vault CLI

Usage:
  vaultx login [--api http://localhost:4000/api]
  vaultx logout
  vaultx whoami
  vaultx list [--project NAME] [--env dev]
  vaultx get SECRET_NAME --project NAME --env dev
  vaultx run --project NAME --env dev -- command [args...]

Commands that decrypt secrets ask for your master password.
`);
}

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--") {
      args._.push(...argv.slice(i));
      break;
    }
    if (arg.startsWith("--")) {
      const key = arg.slice(2);
      const next = argv[i + 1];
      if (!next || next.startsWith("--")) {
        args[key] = true;
      } else {
        args[key] = next;
        i += 1;
      }
    } else {
      args._.push(arg);
    }
  }
  return args;
}

async function prompt(label, { silent = false } = {}) {
  if (!silent) {
    const rl = readline.createInterface({ input, output });
    const answer = await rl.question(label);
    rl.close();
    return answer;
  }

  output.write(label);
  const wasRaw = input.isRaw;
  input.setRawMode?.(true);
  input.resume();

  return new Promise((resolve) => {
    let value = "";
    function onData(chunk) {
      const text = chunk.toString("utf8");
      for (const char of text) {
        if (char === "\r" || char === "\n") {
          input.off("data", onData);
          input.setRawMode?.(wasRaw || false);
          output.write("\n");
          resolve(value);
          return;
        }
        if (char === "\u0003") process.exit(130);
        if (char === "\u007f") {
          value = value.slice(0, -1);
          continue;
        }
        value += char;
      }
    }
    input.on("data", onData);
  });
}

async function readConfig() {
  if (!existsSync(CONFIG_PATH)) return {};
  return JSON.parse(await readFile(CONFIG_PATH, "utf8"));
}

async function writeConfig(config) {
  await mkdir(dirname(CONFIG_PATH), { recursive: true });
  await writeFile(CONFIG_PATH, JSON.stringify(config, null, 2), { mode: 0o600 });
}

async function request(path, options = {}) {
  const config = await readConfig();
  const apiUrl = options.apiUrl || config.apiUrl || DEFAULT_API_URL;
  const headers = {
    "Content-Type": "application/json",
    ...(config.sessionToken ? { Authorization: `Bearer ${config.sessionToken}` } : {}),
    ...(options.headers || {})
  };

  const response = await fetch(`${apiUrl}${path}`, {
    ...options,
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `Request failed with ${response.status}`);
  return data;
}

function requireOption(args, name) {
  if (!args[name]) throw new Error(`Missing --${name}`);
  return args[name];
}

async function login(args) {
  const apiUrl = args.api || DEFAULT_API_URL;
  const email = args.email || await prompt("Email: ");
  const password = args.password || await prompt("Master password: ", { silent: true });
  const data = await request("/auth/login", {
    method: "POST",
    apiUrl,
    body: { email, password, client: "cli" }
  });

  await writeConfig({ apiUrl, sessionToken: data.sessionToken, email: data.user.email });
  console.log(`Logged in as ${data.user.email}`);
}

async function logout() {
  const config = await readConfig();
  if (!config.sessionToken) {
    await rm(CONFIG_PATH, { force: true });
    console.log("Already logged out.");
    return;
  }

  try {
    await request("/auth/logout", { method: "POST" });
  } catch (error) {
    console.warn(`Could not revoke server session: ${error.message}`);
  }

  await rm(CONFIG_PATH, { force: true });
  console.log("Logged out.");
}

async function whoami() {
  const data = await request("/me");
  console.log(data.user.email);
}

async function listSecrets(args) {
  const data = await request("/secrets");
  const secrets = filterSecrets(data.secrets, args);
  if (!secrets.length) {
    console.log("No matching secrets.");
    return;
  }

  for (const secret of secrets) {
    console.log(`${secret.project_name}\t${secret.environment}\t${secret.name}`);
  }
}

function filterSecrets(secrets, args) {
  return secrets.filter((secret) => {
    return (
      (!args.project || secret.project_name === args.project) &&
      (!args.env || secret.environment === args.env) &&
      (!args.name || secret.name === args.name)
    );
  });
}

async function revealSecret(secret, password, action = "view") {
  const data = await request(`/secrets/${secret.id}/reveal`, {
    method: "POST",
    body: { password, action }
  });
  return data.value;
}

async function getSecret(args) {
  const name = args._[1] || args.name;
  if (!name) throw new Error("Usage: vaultx get SECRET_NAME --project NAME --env dev");

  const project = requireOption(args, "project");
  const env = requireOption(args, "env");
  const password = args.password || await prompt("Master password: ", { silent: true });
  const data = await request("/secrets");
  const matches = filterSecrets(data.secrets, { project, env, name });

  if (matches.length !== 1) {
    throw new Error(matches.length ? "Multiple matching secrets found" : "Secret not found");
  }

  console.log(await revealSecret(matches[0], password, "view"));
}

async function runWithSecrets(args) {
  const separatorIndex = args._.indexOf("--");
  const command = separatorIndex >= 0 ? args._.slice(separatorIndex + 1) : [];
  if (!command.length) throw new Error("Usage: vaultx run --project NAME --env dev -- command [args...]");

  const project = requireOption(args, "project");
  const env = requireOption(args, "env");
  const password = args.password || await prompt("Master password: ", { silent: true });
  const data = await request("/secrets");
  const secrets = filterSecrets(data.secrets, { project, env });
  if (!secrets.length) throw new Error("No matching secrets to inject");

  const injected = {};
  for (const secret of secrets) {
    injected[secret.name] = await revealSecret(secret, password, "view");
  }

  const child = spawn(command[0], command.slice(1), {
    stdio: "inherit",
    shell: process.platform === "win32",
    env: { ...process.env, ...injected }
  });

  child.on("exit", (code, signal) => {
    if (signal) process.kill(process.pid, signal);
    process.exit(code ?? 0);
  });
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const command = args._[0];

  if (!command || args.help || args.h) {
    printHelp();
    return;
  }

  if (command === "login") return login(args);
  if (command === "logout") return logout();
  if (command === "whoami") return whoami();
  if (command === "list") return listSecrets(args);
  if (command === "get") return getSecret(args);
  if (command === "run") return runWithSecrets(args);

  throw new Error(`Unknown command: ${command}`);
}

main().catch((error) => {
  console.error(`vaultx: ${error.message}`);
  process.exit(1);
});
