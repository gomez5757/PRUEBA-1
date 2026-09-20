#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const AUDIENCE = "diana-luna-auth-v1";
const MAX_PATCH = 8 * 1024 * 1024;
const FORBIDDEN = [
  ".github/",
  ".codex/",
  "AGENTS.md",
  "GOVERNANCE.md",
  ".luna-",
  "infra/luna-",
  "docs/LUNA_",
  "scripts/luna_",
];

function fail(msg) {
  throw new Error(String(msg || "failure").slice(0, 500));
}

function cleanBroker(value) {
  const s = String(value || "").replace(/\/$/, "");
  if (!s.startsWith("https://")) fail("broker must use https");
  return s;
}

function safeId(value, label) {
  const s = String(value || "").toLowerCase();
  if (!/^[a-z0-9][a-z0-9._-]{0,79}$/.test(s)) fail("invalid " + label);
  return s;
}

function safeRel(value) {
  const p = String(value || "").replace(/\\/g, "/");
  if (!p || p.startsWith("/") || p.includes("\0")) fail("invalid path");
  const n = path.posix.normalize(p).replace(/^\.\//, "");
  if (n === ".." || n.startsWith("../") || n.length > 300) fail("unsafe path");
  return n;
}

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

async function oidcToken() {
  const base = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const reqToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!base || !reqToken) fail("GitHub OIDC unavailable");
  const u = new URL(base);
  u.searchParams.set("audience", AUDIENCE);
  const r = await fetch(u, { headers: { Authorization: "Bearer " + reqToken } });
  if (!r.ok) fail("OIDC request failed: " + r.status);
  const data = await r.json();
  if (!data || !data.value) fail("OIDC token missing");
  return data.value;
}

async function postJson(broker, endpoint, body) {
  const token = await oidcToken();
  const r = await fetch(broker + endpoint, {
    method: "POST",
    headers: {
      Authorization: "Bearer " + token,
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
    body: JSON.stringify(body || {}),
  });
  const raw = await r.text();
  let data = {};
  try { data = raw ? JSON.parse(raw) : {}; } catch {}
  if (!r.ok) {
    const err = new Error("broker " + endpoint + " failed: " + r.status + " " + String(data.error || ""));
    err.status = r.status;
    err.data = data;
    throw err;
  }
  return data;
}

async function leaseAuth(broker, home) {
  await fsp.mkdir(home, { recursive: true, mode: 0o700 });
  const pair = crypto.generateKeyPairSync("rsa", {
    modulusLength: 3072,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const data = await postJson(broker, "/v1/auth/lease", { public_key_pem: pair.publicKey });
  if (!data.ok) fail("auth lease rejected");

  const aes = crypto.privateDecrypt({
    key: pair.privateKey,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: "sha256",
  }, Buffer.from(data.wrapped_key_b64, "base64"));
  const nonce = Buffer.from(data.nonce_b64, "base64");
  const tag = Buffer.from(data.tag_b64, "base64");
  const aad = Buffer.from(data.aad_b64, "base64");
  const ciphertext = Buffer.from(data.ciphertext_b64, "base64");
  const decipher = crypto.createDecipheriv("aes-256-gcm", aes, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  const auth = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  const parsed = JSON.parse(auth.toString("utf8"));
  if (parsed.auth_mode && parsed.auth_mode !== "chatgpt") fail("not ChatGPT auth");
  if (!parsed.tokens || !parsed.tokens.access_token || !parsed.tokens.refresh_token) fail("incomplete ChatGPT auth");
  await fsp.writeFile(path.join(home, "auth.json"), auth, { mode: 0o600 });
  await fsp.writeFile(path.join(home, ".lease.json"), JSON.stringify({
    lease_id: data.lease_id,
    base_hash: data.base_hash,
  }), { mode: 0o600 });
  aes.fill(0);
  auth.fill(0);
}

async function commitAuth(broker, home) {
  try {
    const state = JSON.parse(await fsp.readFile(path.join(home, ".lease.json"), "utf8"));
    const auth = await fsp.readFile(path.join(home, "auth.json"));
    try {
      await postJson(broker, "/v1/auth/commit", {
        lease_id: state.lease_id,
        base_hash: state.base_hash,
        auth_b64: auth.toString("base64"),
      });
    } catch (e) {
      if (e.status !== 409 || !e.data || !e.data.stale) throw e;
    } finally {
      auth.fill(0);
    }
  } catch (e) {
    console.error("LUNA_AUTH_PERSIST_WARNING=" + String(e.message || e).slice(0, 180));
  }
}

function run(command, args, opts) {
  const p = spawnSync(command, args, {
    cwd: opts && opts.cwd ? opts.cwd : undefined,
    env: opts && opts.env ? opts.env : process.env,
    encoding: "utf8",
    maxBuffer: opts && opts.maxBuffer ? opts.maxBuffer : 32 * 1024 * 1024,
    timeout: opts && opts.timeout ? opts.timeout : 120000,
  });
  return p;
}

function requireOk(p, label) {
  if (p.status !== 0) fail(label + " failed");
  return String(p.stdout || "");
}

function validateArchive(file) {
  const list = run("tar", ["-tzf", file], { maxBuffer: 16 * 1024 * 1024 });
  requireOk(list, "archive listing");
  const names = String(list.stdout || "").split("\n").filter(Boolean);
  if (!names.length || names.length > 30000) fail("unsafe archive file count");
  for (const raw of names) safeRel(raw.replace(/\/$/, ""));
  const verbose = run("tar", ["-tvzf", file], { maxBuffer: 24 * 1024 * 1024 });
  requireOk(verbose, "archive inspection");
  for (const line of String(verbose.stdout || "").split("\n")) {
    if (/^[lh]/.test(line)) fail("archive links are forbidden");
  }
}

function allowedPath(file, allowed) {
  const p = safeRel(file);
  if (FORBIDDEN.some((prefix) => p === prefix.replace(/\/$/, "") || p.startsWith(prefix))) return false;
  if (!allowed.length) return false;
  return allowed.some((prefix) => {
    const a = safeRel(prefix).replace(/\/$/, "");
    return p === a || p.startsWith(a + "/");
  });
}

function git(cwd, args, timeout) {
  return run("git", args, { cwd, timeout: timeout || 120000, maxBuffer: 32 * 1024 * 1024 });
}

async function claim(broker) {
  const data = await postJson(broker, "/v1/cycles/claim", {});
  process.stdout.write(JSON.stringify({
    has_work: data.has_work === true,
    cycle_id: data.cycle_id || null,
    task_ids: Array.isArray(data.task_ids) ? data.task_ids : [],
  }));
}

async function executeTask(broker, cycleArg, taskArg) {
  const cycleId = safeId(cycleArg, "cycle id");
  const taskId = safeId(taskArg, "task id");
  const root = await fsp.mkdtemp(path.join(process.env.RUNNER_TEMP || os.tmpdir(), "luna-public-"));
  const workspace = path.join(root, "workspace");
  const codexHome = path.join(root, "codex-home");
  const archive = path.join(root, "source.tgz");
  const schemaPath = path.join(root, "result-schema.json");
  const finalPath = path.join(root, "final.json");
  const patchPath = path.join(root, "result.patch");

  let fetched = null;
  let task = null;
  let model = "";
  let effort = "";
  let modelVerified = false;
  let exitCode = 1;
  let changed = [];
  let result = {
    status: "BLOCKED",
    summary: "Worker failed before producing a validated result.",
    tests: [],
    remaining: [],
    confidence: "low",
  };

  try {
    fetched = await postJson(broker, "/v1/tasks/fetch", { cycle_id: cycleId, task_id: taskId });
    if (!fetched.ok || fetched.cycle_id !== cycleId || fetched.task.id !== taskId) fail("invalid fetched task");
    task = fetched.task;
    if (!/^[0-9a-f]{40}$/.test(String(fetched.base_sha || ""))) fail("invalid fetched base sha");

    const source = Buffer.from(String(fetched.source_tgz_b64 || ""), "base64");
    if (!source.length || sha256(source) !== fetched.source_sha256) fail("source integrity failure");
    await fsp.writeFile(archive, source, { mode: 0o600 });
    source.fill(0);
    validateArchive(archive);
    await fsp.mkdir(workspace, { recursive: true, mode: 0o700 });
    requireOk(run("tar", ["-xzf", archive, "-C", workspace, "--no-same-owner", "--no-same-permissions"], { timeout: 120000 }), "source extraction");

    requireOk(git(workspace, ["init", "-q"]), "git init");
    requireOk(git(workspace, ["config", "user.name", "Luna Worker"]), "git config");
    requireOk(git(workspace, ["config", "user.email", "luna-worker@invalid.local"]), "git config");
    requireOk(git(workspace, ["add", "-A"]), "git add baseline");
    requireOk(git(workspace, ["commit", "-qm", "baseline"]), "git baseline commit");

    await leaseAuth(broker, codexHome);
    const env = { ...process.env, CODEX_HOME: codexHome, HOME: process.env.HOME || "/home/runner" };
    delete env.OPENAI_API_KEY;
    delete env.CODEX_API_KEY;
    delete env.CODEX_ACCESS_TOKEN;

    const login = run("codex", ["login", "status"], { env, timeout: 15000 });
    if (login.status !== 0 || !/chatgpt/i.test(String(login.stdout || "") + String(login.stderr || ""))) {
      fail("Codex ChatGPT login verification failed");
    }

    const schema = {
      type: "object",
      properties: {
        status: { type: "string", enum: ["DONE", "NOOP", "BLOCKED"] },
        summary: { type: "string" },
        tests: { type: "array", items: { type: "string" } },
        remaining: { type: "array", items: { type: "string" } },
        confidence: { type: "string", enum: ["high", "medium", "low"] },
      },
      required: ["status", "summary", "tests", "remaining", "confidence"],
      additionalProperties: false,
    };
    await fsp.writeFile(schemaPath, JSON.stringify(schema), { mode: 0o600 });

    const allowed = Array.isArray(task.allowed_paths) ? task.allowed_paths.map(safeRel) : [];
    const allowedText = allowed.length ? allowed.join(", ") : "(read-only: no tracked file may change)";
    const prompt = [
      "You are one isolated Diana+ implementation worker.",
      "Complete only the task below. Do not broaden scope.",
      "",
      "TASK:",
      String(task.prompt || ""),
      "",
      "HARD SAFETY RULES:",
      "- You may modify only these allowed paths/prefixes: " + allowedText,
      "- Never modify .github/, .codex/, AGENTS.md, GOVERNANCE.md, .luna-* files, infra/luna-*, docs/LUNA_* or scripts/luna_*.",
      "- Do not access credentials, external services, production systems, browsers, Cloudflare, billing, licensing production, or user data.",
      "- Network access is disabled. Do not attempt to enable it.",
      "- Do not spawn subagents. Multi-agent mode is disabled.",
      "- Inspect before editing; preserve existing behavior outside scope.",
      "- Run only relevant local tests that fit the task. Do not weaken tests or validators.",
      "- If the task cannot be completed safely, make no unrelated changes and return BLOCKED.",
      "",
      "Return only the requested structured final result.",
    ].join("\n");

    const args = [
      "exec",
      "--skip-git-repo-check",
      "--ephemeral",
      "--ignore-user-config",
      "--sandbox", "workspace-write",
      "--color", "never",
      "--output-schema", schemaPath,
      "--output-last-message", finalPath,
      "-m", "gpt-5.6-luna",
      "-c", "model_reasoning_effort=max",
      "-c", "approval_policy=never",
      "-c", "agents.enabled=false",
      "-c", "sandbox_workspace_write.network_access=false",
      prompt,
    ];

    const started = Date.now();
    const codex = run("codex", args, {
      cwd: workspace,
      env,
      timeout: Math.max(60000, Number(task.timeout_seconds || 900) * 1000),
      maxBuffer: 48 * 1024 * 1024,
    });
    exitCode = Number.isInteger(codex.status) ? codex.status : 124;
    const log = String(codex.stdout || "") + "\n" + String(codex.stderr || "");
    const modelMatch = log.match(/^\s*model:\s*([^\s]+)\s*$/mi);
    const effortMatch = log.match(/^\s*reasoning effort:\s*([^\r\n]+)\s*$/mi);
    model = modelMatch ? modelMatch[1].trim() : "";
    effort = effortMatch ? effortMatch[1].trim().toLowerCase() : "";
    const forbiddenModel = /^gpt-5\.6-(astra|sol|terra)$/i.test(model) || /astra/i.test(model);
    modelVerified = exitCode === 0 && model === "gpt-5.6-luna" && effort === "max" && !forbiddenModel;

    if (!modelVerified) fail("model verification failed closed");
    if (Date.now() - started > Number(task.timeout_seconds || 900) * 1000 + 15000) fail("worker timeout exceeded");

    const finalRaw = await fsp.readFile(finalPath, "utf8");
    result = JSON.parse(finalRaw);
    if (!["DONE", "NOOP", "BLOCKED"].includes(result.status)) fail("invalid final status");

    requireOk(git(workspace, ["add", "-N", "."]), "git intent-to-add");
    const changedOut = requireOk(git(workspace, ["diff", "--name-only", "--no-renames", "HEAD"]), "git changed files");
    changed = changedOut.split("\n").map((x) => x.trim()).filter(Boolean).map(safeRel);
    for (const file of changed) {
      if (!allowedPath(file, allowed)) fail("worker changed forbidden path");
    }

    if (result.status === "BLOCKED" && changed.length) fail("blocked worker left tracked changes");
    if (result.status === "NOOP" && changed.length) fail("NOOP worker left tracked changes");

    const patch = requireOk(git(workspace, ["diff", "--binary", "--full-index", "--no-ext-diff", "HEAD"]), "git patch");
    const patchBuf = Buffer.from(patch, "utf8");
    if (patchBuf.length > MAX_PATCH) fail("patch too large");
    await fsp.writeFile(patchPath, patchBuf, { mode: 0o600 });

    await postJson(broker, "/v1/tasks/result", {
      cycle_id: cycleId,
      task_id: taskId,
      base_sha: fetched.base_sha,
      patch_b64: patchBuf.toString("base64"),
      changed_files: changed,
      result,
      execution: {
        model,
        reasoning_effort: effort,
        model_verified: true,
        exit_code: 0,
      },
    });
    patchBuf.fill(0);
    console.log("LUNA_TASK_OK=" + taskId);
    console.log("LUNA_MODEL=gpt-5.6-luna");
    console.log("LUNA_REASONING=max");
  } catch (e) {
    const message = String(e && e.message ? e.message : e).slice(0, 300);
    try {
      if (fetched && task) {
        await postJson(broker, "/v1/tasks/result", {
          cycle_id: cycleId,
          task_id: taskId,
          base_sha: fetched.base_sha,
          patch_b64: "",
          changed_files: [],
          result: {
            status: "BLOCKED",
            summary: "Worker failed closed: " + message,
            tests: [],
            remaining: ["Retry after resolving the worker failure."],
            confidence: "low",
          },
          execution: {
            model,
            reasoning_effort: effort,
            model_verified: false,
            exit_code: exitCode,
          },
        });
      }
    } catch (submitError) {
      console.error("LUNA_RESULT_SUBMIT_ERROR=" + String(submitError.message || submitError).slice(0, 180));
    }
    console.error("LUNA_TASK_FAILED=" + taskId + ":" + message);
    process.exitCode = 1;
  } finally {
    if (fs.existsSync(path.join(codexHome, "auth.json"))) await commitAuth(broker, codexHome);
    await fsp.rm(root, { recursive: true, force: true });
  }
}

const args = process.argv.slice(2);
const command = args.shift();
try {
  if (command === "claim") {
    const broker = cleanBroker(args[0]);
    await claim(broker);
  } else if (command === "run") {
    const broker = cleanBroker(args[0]);
    await executeTask(broker, args[1], args[2]);
  } else {
    fail("usage: luna_public_fabric.mjs claim BROKER | run BROKER CYCLE TASK");
  }
} catch (e) {
  console.error("LUNA_FABRIC_ERROR=" + String(e.message || e).slice(0, 300));
  process.exit(1);
}
