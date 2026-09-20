import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { spawnSync } from "node:child_process";

const PORT = Number(process.env.PORT || 8080);
const CODEX_HOME = process.env.CODEX_HOME || "/root/.codex";
const AUTH_PATH = path.join(CODEX_HOME, "auth.json");
const FABRIC_ROOT = path.join(CODEX_HOME, "luna-fabric");
const EXPECTED_ISS = "https://token.actions.githubusercontent.com";
const EXPECTED_AUD = "diana-luna-auth-v1";

const WORKER = {
  repo: "gomez5757/PRUEBA-1",
  repoId: "1203071224",
  refs: new Set(["refs/heads/main"]),
  workflow: "gomez5757/PRUEBA-1/.github/workflows/luna-public-worker.yml@",
  runner: "github-hosted",
  events: new Set(["schedule", "workflow_dispatch", "push"]),
};

const PRIVATE = {
  repo: "gomez5757/diana-plus",
  repoId: "1322643727",
  refs: new Set([
    "refs/heads/chatgpt-auto/luna-integration",
    "refs/heads/chatgpt-auto/luna-fabric-migration-20260920",
  ]),
  workflow: "gomez5757/diana-plus/.github/workflows/luna-private-fabric.yml@",
  runner: "self-hosted",
  events: new Set(["push", "workflow_dispatch"]),
};

const MAX_BODY = 64 * 1024 * 1024;
const MAX_AUTH = 128 * 1024;
const MAX_SOURCE = 40 * 1024 * 1024;
const MAX_PATCH = 8 * 1024 * 1024;
const MAX_TASKS = 24;
const MAX_PROMPT = 32000;
const CLAIM_SECONDS = 45 * 60;

const seenJti = new Map();
let jwksCache = { at: 0, keys: [] };
let lockTail = Promise.resolve();

function json(res, status, obj) {
  const body = Buffer.from(JSON.stringify(obj));
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": body.length,
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  res.end(body);
}

function b64urlDecode(s) {
  return Buffer.from(String(s).replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function nowIso() {
  return new Date().toISOString();
}

async function withLock(fn) {
  let release;
  const previous = lockTail;
  lockTail = new Promise((resolve) => { release = resolve; });
  await previous;
  try { return await fn(); }
  finally { release(); }
}

async function fetchJson(url) {
  const r = await fetch(url, { headers: { "user-agent": "diana-luna-broker/2" } });
  if (!r.ok) throw new Error("fetch failed " + r.status);
  return r.json();
}

async function getJwks() {
  const now = Date.now();
  if (jwksCache.keys.length && now - jwksCache.at < 15 * 60 * 1000) return jwksCache.keys;
  const cfg = await fetchJson(EXPECTED_ISS + "/.well-known/openid-configuration");
  const data = await fetchJson(cfg.jwks_uri);
  if (!Array.isArray(data.keys) || !data.keys.length) throw new Error("empty JWKS");
  jwksCache = { at: now, keys: data.keys };
  return data.keys;
}

function audienceOk(aud) {
  if (Array.isArray(aud)) return aud.some((x) => safeEqual(x, EXPECTED_AUD));
  return safeEqual(aud || "", EXPECTED_AUD);
}

async function verifyOidc(token) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) throw new Error("malformed bearer");

  const header = JSON.parse(b64urlDecode(parts[0]).toString("utf8"));
  const claims = JSON.parse(b64urlDecode(parts[1]).toString("utf8"));
  if (header.alg !== "RS256" || !header.kid) throw new Error("unsupported JWT header");

  let keys = await getJwks();
  let jwk = keys.find((k) => k.kid === header.kid && k.kty === "RSA");
  if (!jwk) {
    jwksCache = { at: 0, keys: [] };
    keys = await getJwks();
    jwk = keys.find((k) => k.kid === header.kid && k.kty === "RSA");
  }
  if (!jwk) throw new Error("unknown JWT key");

  const key = crypto.createPublicKey({ key: jwk, format: "jwk" });
  const signing = Buffer.from(parts[0] + "." + parts[1]);
  if (!crypto.verify("RSA-SHA256", signing, key, b64urlDecode(parts[2]))) {
    throw new Error("bad JWT signature");
  }

  const now = Math.floor(Date.now() / 1000);
  if (!safeEqual(claims.iss || "", EXPECTED_ISS)) throw new Error("bad issuer");
  if (!audienceOk(claims.aud)) throw new Error("bad audience");
  if (!Number.isFinite(claims.exp) || claims.exp < now - 15 || claims.exp > now + 10 * 60) {
    throw new Error("bad exp");
  }
  if (claims.nbf && claims.nbf > now + 30) throw new Error("bad nbf");
  if (claims.iat && claims.iat > now + 30) throw new Error("bad iat");

  const jti = String(claims.jti || "");
  if (!jti) throw new Error("missing jti");
  for (const [id, exp] of seenJti) if (exp < now) seenJti.delete(id);
  if (seenJti.has(jti)) throw new Error("OIDC replay");
  seenJti.set(jti, claims.exp);
  return claims;
}

function assertProfile(claims, profile) {
  if (!safeEqual(claims.repository || "", profile.repo)) throw new Error("wrong repository");
  if (!safeEqual(String(claims.repository_id || ""), profile.repoId)) throw new Error("wrong repository id");
  if (!profile.refs.has(String(claims.ref || ""))) throw new Error("ref not allowed");
  if (!safeEqual(String(claims.runner_environment || ""), profile.runner)) throw new Error("runner environment not allowed");
  if (!profile.events.has(String(claims.event_name || ""))) throw new Error("event not allowed");
  if (!String(claims.workflow_ref || "").includes(profile.workflow)) throw new Error("workflow not allowed");
  if (!claims.run_id) throw new Error("missing run_id");
  return claims;
}

async function authorize(req, profile) {
  const h = String(req.headers.authorization || "");
  if (!h.startsWith("Bearer ")) throw Object.assign(new Error("missing bearer"), { status: 401 });
  try {
    const claims = await verifyOidc(h.slice(7));
    return assertProfile(claims, profile);
  } catch (e) {
    throw Object.assign(e, { status: 403 });
  }
}

async function readJsonBody(req) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > MAX_BODY) throw Object.assign(new Error("request too large"), { status: 413 });
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  try { return raw ? JSON.parse(raw) : {}; }
  catch { throw Object.assign(new Error("invalid json"), { status: 400 }); }
}

function codexLoginOk(home = CODEX_HOME) {
  const p = spawnSync("codex", ["login", "status"], {
    env: { ...process.env, CODEX_HOME: home, HOME: "/root" },
    encoding: "utf8",
    timeout: 15000,
  });
  return p.status === 0 && /chatgpt/i.test(String(p.stdout || "") + String(p.stderr || ""));
}

function validateAuth(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 32 || buf.length > MAX_AUTH) throw new Error("invalid auth size");
  const obj = JSON.parse(buf.toString("utf8"));
  if (!obj || typeof obj !== "object") throw new Error("invalid auth json");
  if (obj.auth_mode && obj.auth_mode !== "chatgpt") throw new Error("auth mode is not chatgpt");
  if (!obj.tokens || typeof obj.tokens !== "object" || !obj.tokens.access_token || !obj.tokens.refresh_token) {
    throw new Error("missing chatgpt tokens");
  }
  return obj;
}

async function currentAuth() {
  const buf = await fsp.readFile(AUTH_PATH);
  validateAuth(buf);
  if (!codexLoginOk()) throw new Error("codex chatgpt login is not healthy");
  return buf;
}

async function validateCandidate(buf) {
  validateAuth(buf);
  const tmp = await fsp.mkdtemp("/tmp/codex-auth-check-");
  try {
    await fsp.writeFile(path.join(tmp, "auth.json"), buf, { mode: 0o600 });
    if (!codexLoginOk(tmp)) throw new Error("candidate auth rejected by codex");
  } finally {
    await fsp.rm(tmp, { recursive: true, force: true });
  }
}

function encryptFor(pubPem, plaintext, aadText) {
  const pub = crypto.createPublicKey(pubPem);
  if (pub.asymmetricKeyType !== "rsa") throw new Error("ephemeral key must be RSA");
  const key = crypto.randomBytes(32);
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
  const aad = Buffer.from(aadText, "utf8");
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  const wrapped = crypto.publicEncrypt({
    key: pub,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: "sha256",
  }, key);
  key.fill(0);
  return {
    wrapped_key_b64: wrapped.toString("base64"),
    nonce_b64: nonce.toString("base64"),
    tag_b64: tag.toString("base64"),
    ciphertext_b64: ciphertext.toString("base64"),
    aad_b64: aad.toString("base64"),
  };
}

async function authLease(req, res) {
  const claims = await authorize(req, WORKER);
  const body = await readJsonBody(req);
  const pub = String(body.public_key_pem || "");
  if (pub.length < 100 || pub.length > 8192 || !pub.includes("BEGIN PUBLIC KEY")) {
    throw Object.assign(new Error("invalid public key"), { status: 400 });
  }
  const auth = await currentAuth();
  const hash = sha256(auth);
  const leaseId = crypto.randomUUID();
  const aad = `${leaseId}|${hash}|${claims.run_id}|${claims.run_attempt || ""}`;
  const enc = encryptFor(pub, auth, aad);
  auth.fill(0);
  return json(res, 200, { ok: true, schema: 2, lease_id: leaseId, base_hash: hash, ...enc });
}

async function authCommit(req, res) {
  const claims = await authorize(req, WORKER);
  const body = await readJsonBody(req);
  const baseHash = String(body.base_hash || "");
  const leaseId = String(body.lease_id || "");
  const b64 = String(body.auth_b64 || "");
  if (!/^[0-9a-f]{64}$/.test(baseHash) || leaseId.length < 10 || b64.length > MAX_AUTH * 2) {
    throw Object.assign(new Error("invalid commit metadata"), { status: 400 });
  }

  const next = Buffer.from(b64, "base64");
  await validateCandidate(next);
  const cur = await fsp.readFile(AUTH_PATH);
  const curHash = sha256(cur);
  if (curHash !== baseHash) {
    next.fill(0);
    cur.fill(0);
    return json(res, 409, { ok: false, stale: true, current_hash: curHash });
  }
  const nextHash = sha256(next);
  if (nextHash === curHash) {
    next.fill(0);
    cur.fill(0);
    return json(res, 200, { ok: true, updated: false, hash: curHash });
  }

  const tmp = AUTH_PATH + ".tmp." + crypto.randomUUID();
  await fsp.writeFile(tmp, next, { mode: 0o600 });
  await fsp.rename(tmp, AUTH_PATH);
  next.fill(0);
  cur.fill(0);
  console.log(JSON.stringify({ event: "auth_updated", run_id: String(claims.run_id), hash: nextHash.slice(0, 12) }));
  return json(res, 200, { ok: true, updated: true, hash: nextHash });
}

function safeId(value, label = "id") {
  const s = String(value || "").toLowerCase();
  if (!/^[a-z0-9][a-z0-9._-]{0,79}$/.test(s)) throw new Error("invalid " + label);
  return s;
}

function safeRelPath(value) {
  const p = String(value || "").replace(/\\/g, "/");
  if (!p || p.startsWith("/") || p.includes("\0")) throw new Error("invalid relative path");
  const norm = path.posix.normalize(p);
  if (norm === ".." || norm.startsWith("../")) throw new Error("path traversal");
  if (norm.length > 300) throw new Error("path too long");
  return norm.replace(/^\.\//, "");
}

function validateBranch(value) {
  const s = String(value || "");
  if (!s.startsWith("chatgpt-luna/") || s.length > 180 || s.includes("..") || !/^[A-Za-z0-9._\/-]+$/.test(s)) {
    throw new Error("invalid task branch");
  }
  return s;
}

function validateTask(raw) {
  const id = safeId(raw?.id, "task id");
  const branch = validateBranch(raw?.branch);
  const prompt = String(raw?.prompt || "");
  if (!prompt || prompt.length > MAX_PROMPT) throw new Error("invalid task prompt");
  const allowed = Array.isArray(raw?.allowed_paths) ? raw.allowed_paths.map(safeRelPath) : [];
  if (allowed.length > 100) throw new Error("too many allowed paths");
  const timeout = Math.max(60, Math.min(1500, Math.floor(Number(raw?.timeout_seconds || 900))));
  return {
    id,
    branch,
    prompt,
    allowed_paths: [...new Set(allowed)],
    timeout_seconds: timeout,
    status: "READY",
    created_at: nowIso(),
  };
}

function cycleDir(cycleId) {
  return path.join(FABRIC_ROOT, safeId(cycleId, "cycle id"));
}

async function atomicJson(file, obj) {
  const tmp = file + ".tmp." + crypto.randomUUID();
  await fsp.writeFile(tmp, JSON.stringify(obj, null, 2) + "\n", { mode: 0o600 });
  await fsp.rename(tmp, file);
}

async function readManifest(cycleId) {
  const file = path.join(cycleDir(cycleId), "manifest.json");
  return JSON.parse(await fsp.readFile(file, "utf8"));
}

async function writeManifest(cycleId, manifest) {
  manifest.updated_at = nowIso();
  await atomicJson(path.join(cycleDir(cycleId), "manifest.json"), manifest);
}

function archiveLooksSafe(file) {
  const list = spawnSync("tar", ["-tzf", file], { encoding: "utf8", maxBuffer: 8 * 1024 * 1024 });
  if (list.status !== 0) throw new Error("invalid source archive");
  const names = String(list.stdout || "").split("\n").filter(Boolean);
  if (!names.length || names.length > 30000) throw new Error("invalid source file count");
  for (const raw of names) safeRelPath(raw.replace(/\/$/, ""));
  const verbose = spawnSync("tar", ["-tvzf", file], { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  if (verbose.status !== 0) throw new Error("cannot inspect source archive");
  for (const line of String(verbose.stdout || "").split("\n")) {
    if (/^[lh]/.test(line)) throw new Error("archive links are not allowed");
  }
}

async function cycleUpload(req, res) {
  await authorize(req, PRIVATE);
  const body = await readJsonBody(req);
  const cycleId = safeId(body.cycle_id, "cycle id");
  const baseSha = String(body.base_sha || "");
  if (!/^[0-9a-f]{40}$/.test(baseSha)) throw Object.assign(new Error("invalid base sha"), { status: 400 });
  const sourceB64 = String(body.source_tgz_b64 || "");
  if (!sourceB64) throw Object.assign(new Error("missing source"), { status: 400 });
  const source = Buffer.from(sourceB64, "base64");
  if (!source.length || source.length > MAX_SOURCE) throw Object.assign(new Error("source too large"), { status: 413 });
  const declaredHash = String(body.source_sha256 || "");
  const sourceHash = sha256(source);
  if (declaredHash && declaredHash !== sourceHash) throw Object.assign(new Error("source hash mismatch"), { status: 400 });

  if (!Array.isArray(body.tasks) || body.tasks.length < 1 || body.tasks.length > MAX_TASKS) {
    throw Object.assign(new Error("invalid task count"), { status: 400 });
  }
  const tasks = body.tasks.map(validateTask);
  if (new Set(tasks.map((t) => t.id)).size !== tasks.length) throw new Error("duplicate task id");
  if (new Set(tasks.map((t) => t.branch)).size !== tasks.length) throw new Error("duplicate task branch");

  return withLock(async () => {
    const dir = cycleDir(cycleId);
    const manifestPath = path.join(dir, "manifest.json");
    try {
      const existing = JSON.parse(await fsp.readFile(manifestPath, "utf8"));
      const sameTasks = JSON.stringify(existing.tasks.map((t) => [t.id, t.branch])) === JSON.stringify(tasks.map((t) => [t.id, t.branch]));
      if (existing.base_sha === baseSha && existing.source_sha256 === sourceHash && sameTasks) {
        source.fill(0);
        return json(res, 200, { ok: true, schema: 2, cycle_id: cycleId, idempotent: true, status: existing.status });
      }
      source.fill(0);
      return json(res, 409, { ok: false, error: "cycle id already exists with different content" });
    } catch (e) {
      if (e?.code && e.code !== "ENOENT") throw e;
    }

    await fsp.mkdir(dir, { recursive: true, mode: 0o700 });
    const sourcePath = path.join(dir, "source.tgz");
    await fsp.writeFile(sourcePath, source, { mode: 0o600 });
    source.fill(0);
    archiveLooksSafe(sourcePath);

    const manifest = {
      schema: 2,
      cycle_id: cycleId,
      base_sha: baseSha,
      source_sha256: sourceHash,
      status: "PENDING",
      created_at: nowIso(),
      updated_at: nowIso(),
      claimed_run_id: null,
      claim_expires_at: null,
      tasks,
    };
    await writeManifest(cycleId, manifest);
    console.log(JSON.stringify({ event: "cycle_uploaded", cycle_id: cycleId, tasks: tasks.length, base_sha: baseSha.slice(0, 12) }));
    return json(res, 200, { ok: true, schema: 2, cycle_id: cycleId, idempotent: false, tasks: tasks.length });
  });
}

async function listCycleIds() {
  await fsp.mkdir(FABRIC_ROOT, { recursive: true, mode: 0o700 });
  const rows = [];
  for (const name of await fsp.readdir(FABRIC_ROOT)) {
    const p = path.join(FABRIC_ROOT, name, "manifest.json");
    try {
      const st = await fsp.stat(p);
      if (st.isFile()) rows.push({ name, mtime: st.mtimeMs });
    } catch {}
  }
  rows.sort((a, b) => a.mtime - b.mtime);
  return rows.map((r) => r.name);
}

async function cycleClaim(req, res) {
  const claims = await authorize(req, WORKER);
  await readJsonBody(req);
  return withLock(async () => {
    const now = Date.now();
    for (const cycleId of await listCycleIds()) {
      const m = await readManifest(cycleId);
      if (["COLLECTED", "ABORTED", "RESULTS_READY"].includes(m.status)) continue;
      const expired = m.status === "RUNNING" && (!m.claim_expires_at || Date.parse(m.claim_expires_at) < now);
      if (m.status !== "PENDING" && !expired) continue;

      if (expired) {
        for (const task of m.tasks) if (task.status === "RUNNING") task.status = "READY";
      }
      const taskIds = m.tasks.filter((t) => t.status === "READY").map((t) => t.id);
      if (!taskIds.length) {
        if (m.tasks.every((t) => t.status === "COMPLETE")) {
          m.status = "RESULTS_READY";
          await writeManifest(cycleId, m);
        }
        continue;
      }

      m.status = "RUNNING";
      m.claimed_run_id = String(claims.run_id);
      m.claimed_run_attempt = String(claims.run_attempt || "1");
      m.claim_expires_at = new Date(now + CLAIM_SECONDS * 1000).toISOString();
      await writeManifest(cycleId, m);
      console.log(JSON.stringify({ event: "cycle_claimed", cycle_id: cycleId, run_id: String(claims.run_id), tasks: taskIds.length }));
      return json(res, 200, { ok: true, schema: 2, has_work: true, cycle_id: cycleId, task_ids: taskIds });
    }
    return json(res, 200, { ok: true, schema: 2, has_work: false, cycle_id: null, task_ids: [] });
  });
}

async function taskFetch(req, res) {
  const claims = await authorize(req, WORKER);
  const body = await readJsonBody(req);
  const cycleId = safeId(body.cycle_id, "cycle id");
  const taskId = safeId(body.task_id, "task id");

  return withLock(async () => {
    const m = await readManifest(cycleId);
    if (m.status !== "RUNNING" || String(m.claimed_run_id) !== String(claims.run_id)) {
      return json(res, 409, { ok: false, error: "cycle not claimed by this workflow run" });
    }
    const task = m.tasks.find((t) => t.id === taskId);
    if (!task) return json(res, 404, { ok: false, error: "task not found" });
    if (!["READY", "RUNNING"].includes(task.status)) return json(res, 409, { ok: false, error: "task not runnable" });
    task.status = "RUNNING";
    task.worker_started_at ||= nowIso();
    await writeManifest(cycleId, m);

    const source = await fsp.readFile(path.join(cycleDir(cycleId), "source.tgz"));
    if (sha256(source) !== m.source_sha256) throw new Error("stored source hash mismatch");
    return json(res, 200, {
      ok: true,
      schema: 2,
      cycle_id: cycleId,
      base_sha: m.base_sha,
      source_sha256: m.source_sha256,
      source_tgz_b64: source.toString("base64"),
      task: {
        id: task.id,
        branch: task.branch,
        prompt: task.prompt,
        allowed_paths: task.allowed_paths,
        timeout_seconds: task.timeout_seconds,
      },
    });
  });
}

async function taskResult(req, res) {
  const claims = await authorize(req, WORKER);
  const body = await readJsonBody(req);
  const cycleId = safeId(body.cycle_id, "cycle id");
  const taskId = safeId(body.task_id, "task id");
  const baseSha = String(body.base_sha || "");
  const patch = Buffer.from(String(body.patch_b64 || ""), "base64");
  if (patch.length > MAX_PATCH) throw Object.assign(new Error("patch too large"), { status: 413 });
  const changed = Array.isArray(body.changed_files) ? body.changed_files.map(safeRelPath) : [];
  if (changed.length > 500) throw new Error("too many changed files");
  const result = body.result && typeof body.result === "object" ? body.result : {};
  const execution = body.execution && typeof body.execution === "object" ? body.execution : {};

  return withLock(async () => {
    const m = await readManifest(cycleId);
    if (m.status !== "RUNNING" || String(m.claimed_run_id) !== String(claims.run_id)) {
      patch.fill(0);
      return json(res, 409, { ok: false, error: "cycle not claimed by this workflow run" });
    }
    if (baseSha !== m.base_sha) {
      patch.fill(0);
      return json(res, 409, { ok: false, error: "base sha mismatch" });
    }
    const task = m.tasks.find((t) => t.id === taskId);
    if (!task) {
      patch.fill(0);
      return json(res, 404, { ok: false, error: "task not found" });
    }

    const taskDir = path.join(cycleDir(cycleId), "results", taskId);
    await fsp.mkdir(taskDir, { recursive: true, mode: 0o700 });
    await fsp.writeFile(path.join(taskDir, "patch.bin"), patch, { mode: 0o600 });
    patch.fill(0);
    await atomicJson(path.join(taskDir, "result.json"), {
      schema: 2,
      cycle_id: cycleId,
      task_id: taskId,
      changed_files: changed,
      result,
      execution: {
        model: String(execution.model || ""),
        reasoning_effort: String(execution.reasoning_effort || ""),
        model_verified: execution.model_verified === true,
        exit_code: Number.isFinite(Number(execution.exit_code)) ? Number(execution.exit_code) : 1,
      },
      received_at: nowIso(),
    });

    task.status = "COMPLETE";
    task.changed_files = changed;
    task.worker_finished_at = nowIso();
    if (m.tasks.every((t) => t.status === "COMPLETE")) {
      m.status = "RESULTS_READY";
      m.claim_expires_at = null;
    }
    await writeManifest(cycleId, m);
    console.log(JSON.stringify({ event: "task_result", cycle_id: cycleId, task_id: taskId, changed: changed.length }));
    return json(res, 200, { ok: true, schema: 2, cycle_id: cycleId, task_id: taskId, cycle_status: m.status });
  });
}

async function cycleStatus(req, res) {
  await authorize(req, PRIVATE);
  const body = await readJsonBody(req);
  const cycleId = safeId(body.cycle_id, "cycle id");
  const m = await readManifest(cycleId);
  return json(res, 200, {
    ok: true,
    schema: 2,
    cycle_id: cycleId,
    base_sha: m.base_sha,
    status: m.status,
    tasks: m.tasks.map((t) => ({ id: t.id, branch: t.branch, status: t.status, changed_files: t.changed_files || [] })),
  });
}

async function resultFetch(req, res) {
  await authorize(req, PRIVATE);
  const body = await readJsonBody(req);
  const cycleId = safeId(body.cycle_id, "cycle id");
  const taskId = safeId(body.task_id, "task id");
  const m = await readManifest(cycleId);
  const task = m.tasks.find((t) => t.id === taskId);
  if (!task) return json(res, 404, { ok: false, error: "task not found" });
  if (task.status !== "COMPLETE") return json(res, 409, { ok: false, error: "task result not complete" });
  const taskDir = path.join(cycleDir(cycleId), "results", taskId);
  const [patch, resultRaw] = await Promise.all([
    fsp.readFile(path.join(taskDir, "patch.bin")),
    fsp.readFile(path.join(taskDir, "result.json"), "utf8"),
  ]);
  return json(res, 200, {
    ok: true,
    schema: 2,
    cycle_id: cycleId,
    base_sha: m.base_sha,
    task: {
      id: task.id,
      branch: task.branch,
      prompt: task.prompt,
      allowed_paths: task.allowed_paths,
    },
    patch_b64: patch.toString("base64"),
    result: JSON.parse(resultRaw),
  });
}

async function cycleAck(req, res) {
  await authorize(req, PRIVATE);
  const body = await readJsonBody(req);
  const cycleId = safeId(body.cycle_id, "cycle id");
  return withLock(async () => {
    const m = await readManifest(cycleId);
    if (m.status !== "RESULTS_READY") return json(res, 409, { ok: false, error: "cycle not ready to acknowledge" });
    m.status = "COLLECTED";
    m.collected_at = nowIso();
    m.collection = body.collection && typeof body.collection === "object" ? body.collection : {};
    await writeManifest(cycleId, m);
    console.log(JSON.stringify({ event: "cycle_collected", cycle_id: cycleId }));
    return json(res, 200, { ok: true, schema: 2, cycle_id: cycleId, status: m.status });
  });
}

async function health(res) {
  let auth = false;
  let storage = false;
  try {
    const st = await fsp.stat(AUTH_PATH);
    storage = st.isFile();
    auth = storage && codexLoginOk();
  } catch {}
  await fsp.mkdir(FABRIC_ROOT, { recursive: true, mode: 0o700 }).catch(() => {});
  return json(res, auth ? 200 : 503, {
    ok: auth,
    mode: "luna-fabric-broker",
    storage,
    codex_auth: auth,
    schema: 2,
  });
}

await fsp.mkdir(FABRIC_ROOT, { recursive: true, mode: 0o700 });
const server = http.createServer(async (req, res) => {
  try {
    if (req.method === "GET" && req.url === "/health") return await health(res);
    if (req.method === "POST" && req.url === "/v1/auth/lease") return await authLease(req, res);
    if (req.method === "POST" && req.url === "/v1/auth/commit") return await authCommit(req, res);
    if (req.method === "POST" && req.url === "/v1/cycles/upload") return await cycleUpload(req, res);
    if (req.method === "POST" && req.url === "/v1/cycles/claim") return await cycleClaim(req, res);
    if (req.method === "POST" && req.url === "/v1/tasks/fetch") return await taskFetch(req, res);
    if (req.method === "POST" && req.url === "/v1/tasks/result") return await taskResult(req, res);
    if (req.method === "POST" && req.url === "/v1/cycles/status") return await cycleStatus(req, res);
    if (req.method === "POST" && req.url === "/v1/tasks/result-fetch") return await resultFetch(req, res);
    if (req.method === "POST" && req.url === "/v1/cycles/ack") return await cycleAck(req, res);
    return json(res, 404, { ok: false, error: "not found" });
  } catch (e) {
    const status = Number(e.status) || (e.code === "ENOENT" ? 404 : 500);
    console.error(JSON.stringify({ event: "request_error", status, error: String(e.message || e).slice(0, 300) }));
    return json(res, status, { ok: false, error: String(e.message || e).slice(0, 300) });
  }
});
server.headersTimeout = 15000;
server.requestTimeout = 120000;
server.listen(PORT, "0.0.0.0", () => {
  console.log(JSON.stringify({ event: "luna_fabric_broker_ready", port: PORT, oidc: true, schema: 2 }));
});
