import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import readline from "node:readline";
import { spawn, spawnSync } from "node:child_process";

const PORT = Number(process.env.PORT || 8080);
const CODEX_HOME = process.env.CODEX_HOME || "/root/.codex";
const JOB_ROOT = path.join(CODEX_HOME, "diana-bridge", "jobs");
const EXPECTED_ISS = "https://token.actions.githubusercontent.com";
const EXPECTED_AUD = process.env.DIANA_OIDC_AUDIENCE || "diana-luna-bridge-v1";
const EXPECTED_REPO = process.env.DIANA_REPOSITORY || "gomez5757/diana-plus";
const EXPECTED_REPO_ID = String(process.env.DIANA_REPOSITORY_ID || "1322643727");
const ALLOWED_REFS = new Set((process.env.DIANA_ALLOWED_REFS ||
  "refs/heads/main,refs/heads/chatgpt-auto/luna-integration").split(",").filter(Boolean));
const MAX_BODY = 32 * 1024 * 1024;
const MAX_META = 128 * 1024;
const MAX_PATCH = 8 * 1024 * 1024;
const MAX_RESULT = 2 * 1024 * 1024;
const MAX_LOG_TAIL = 12000;
const MAX_CONCURRENT = 2;
const MAX_QUEUE = 8;
const MAX_TIMEOUT = 26 * 60;
const MIN_TIMEOUT = 30;
const ALLOWED_RESULTS = new Set([".luna-result.json", ".luna-audit.json"]);
const seenJti = new Map();
let active = 0;
const waiters = [];
let jwksCache = { at: 0, keys: [] };

async function acquireSlot() {
  if (active < MAX_CONCURRENT) {
    active++;
    return;
  }
  if (waiters.length >= MAX_QUEUE) throw new Error("Luna queue full");
  await new Promise((resolve) => waiters.push(resolve));
  active++;
}

function releaseSlot() {
  active = Math.max(0, active - 1);
  const next = waiters.shift();
  if (next) next();
}

function json(res, status, obj) {
  const body = Buffer.from(JSON.stringify(obj));
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": body.length,
    "cache-control": "no-store",
  });
  res.end(body);
}

function b64urlDecode(s) {
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

async function fetchJson(url) {
  const r = await fetch(url, { headers: { "user-agent": "diana-luna-bridge/1" } });
  if (!r.ok) throw new Error("fetch failed " + url + " -> " + r.status);
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
  if (!crypto.verify("RSA-SHA256", signing, key, b64urlDecode(parts[2])))
    throw new Error("bad JWT signature");

  const now = Math.floor(Date.now() / 1000);
  if (!safeEqual(claims.iss || "", EXPECTED_ISS)) throw new Error("bad issuer");
  if (!audienceOk(claims.aud)) throw new Error("bad audience");
  if (!Number.isFinite(claims.exp) || claims.exp < now - 15 || claims.exp > now + 10 * 60)
    throw new Error("bad exp");
  if (claims.nbf && claims.nbf > now + 30) throw new Error("bad nbf");
  if (claims.iat && claims.iat > now + 30) throw new Error("bad iat");
  if (!safeEqual(claims.repository || "", EXPECTED_REPO)) throw new Error("wrong repository");
  if (!safeEqual(String(claims.repository_id || ""), EXPECTED_REPO_ID))
    throw new Error("wrong repository id");
  if (!ALLOWED_REFS.has(String(claims.ref || ""))) throw new Error("ref not allowed");
  if (!safeEqual(String(claims.runner_environment || ""), "self-hosted"))
    throw new Error("runner environment not allowed");
  const ev = String(claims.event_name || "");
  if (!["schedule", "workflow_dispatch", "push"].includes(ev)) throw new Error("event not allowed");
  const wf = String(claims.workflow_ref || "");
  if (!wf.includes(EXPECTED_REPO + "/.github/workflows/luna-autopilot.yml@"))
    throw new Error("workflow not allowed");

  const jti = String(claims.jti || "");
  if (!jti) throw new Error("missing jti");
  for (const [id, exp] of seenJti) if (exp < now) seenJti.delete(id);
  if (seenJti.has(jti)) throw new Error("OIDC replay");
  seenJti.set(jti, claims.exp);
  return claims;
}

function run(cmd, args, opts = {}) {
  const p = spawnSync(cmd, args, {
    cwd: opts.cwd,
    env: opts.env || process.env,
    encoding: "utf8",
    maxBuffer: opts.maxBuffer || 16 * 1024 * 1024,
  });
  return { code: p.status ?? 1, out: String(p.stdout || "") + String(p.stderr || "") };
}

async function readRequestToFile(req, file) {
  const out = fs.createWriteStream(file, { flags: "wx", mode: 0o600 });
  let total = 0;
  try {
    for await (const chunk of req) {
      total += chunk.length;
      if (total > MAX_BODY) throw new Error("request too large");
      if (!out.write(chunk)) await new Promise((resolve) => out.once("drain", resolve));
    }
    await new Promise((resolve, reject) => out.end((e) => e ? reject(e) : resolve()));
    return total;
  } catch (e) {
    out.destroy();
    throw e;
  }
}

async function parseEnvelope(file) {
  const fh = await fsp.open(file, "r");
  try {
    const head = Buffer.alloc(4);
    if ((await fh.read(head, 0, 4, 0)).bytesRead !== 4) throw new Error("short envelope");
    const n = head.readUInt32BE(0);
    if (n < 2 || n > MAX_META) throw new Error("bad metadata length");
    const mb = Buffer.alloc(n);
    if ((await fh.read(mb, 0, n, 4)).bytesRead !== n) throw new Error("short metadata");
    const meta = JSON.parse(mb.toString("utf8"));
    const stat = await fh.stat();
    if (stat.size <= 4 + n) throw new Error("archive missing");
    const tarFile = file + ".tgz";
    await new Promise((resolve, reject) => {
      const rs = fs.createReadStream(file, { start: 4 + n });
      const ws = fs.createWriteStream(tarFile, { flags: "wx", mode: 0o600 });
      rs.on("error", reject); ws.on("error", reject); ws.on("finish", resolve);
      rs.pipe(ws);
    });
    return { meta, tarFile };
  } finally {
    await fh.close();
  }
}

function sanitizeJobId(v) {
  const s = String(v || "").toLowerCase().replace(/[^a-z0-9._-]/g, "-").slice(0, 80);
  if (!s || s === "." || s === "..") throw new Error("invalid job id");
  return s;
}

function validateMeta(meta) {
  const jobId = sanitizeJobId(meta.job_id);
  const baseSha = String(meta.base_sha || "");
  if (!/^[0-9a-f]{40}$/.test(baseSha)) throw new Error("invalid base sha");
  const prompt = String(meta.prompt || "");
  if (!prompt || prompt.length > 64000) throw new Error("invalid prompt");
  const resultFile = String(meta.result_file || "");
  if (!ALLOWED_RESULTS.has(resultFile)) throw new Error("invalid result file");
  const timeout = Math.max(MIN_TIMEOUT, Math.min(MAX_TIMEOUT, Number(meta.timeout || 600)));
  return { jobId, baseSha, prompt, resultFile, timeout };
}

function validateArchive(tarFile) {
  const ls = run("tar", ["-tzf", tarFile], { maxBuffer: 8 * 1024 * 1024 });
  if (ls.code) throw new Error("invalid tar: " + ls.out.slice(-500));
  const names = ls.out.split("\n").filter(Boolean);
  if (!names.length || names.length > 20000) throw new Error("archive file count invalid");
  for (const raw of names) {
    const name = raw.replace(/\\/g, "/");
    if (name.startsWith("/") || name.includes("\0")) throw new Error("unsafe archive path");
    const norm = path.posix.normalize(name);
    if (norm === ".." || norm.startsWith("../")) throw new Error("archive traversal");
  }
  const tv = run("tar", ["-tvzf", tarFile], { maxBuffer: 16 * 1024 * 1024 });
  if (tv.code) throw new Error("cannot inspect tar");
  for (const line of tv.out.split("\n")) {
    if (/^[lh]/.test(line)) throw new Error("archive links not allowed");
  }
}

async function emptyDir(dir) {
  await fsp.mkdir(dir, { recursive: true });
  for (const name of await fsp.readdir(dir))
    await fsp.rm(path.join(dir, name), { recursive: true, force: true });
}

async function prepareWorkspace(jobDir, tarFile, baseSha) {
  const marker = path.join(jobDir, ".diana-base-sha");
  let reuse = false;
  try {
    reuse = (await fsp.readFile(marker, "utf8")).trim() === baseSha &&
      fs.existsSync(path.join(jobDir, ".git"));
  } catch {}
  if (reuse) {
    await fsp.writeFile(path.join(jobDir, ".last-used"), new Date().toISOString());
    return { reused: true };
  }

  await emptyDir(jobDir);
  const ex = run("tar", ["-xzf", tarFile, "--no-same-owner", "--no-same-permissions", "-C", jobDir]);
  if (ex.code) throw new Error("tar extract failed: " + ex.out.slice(-1000));
  for (const transient of [".luna-result.json", ".luna-audit.json"])
    await fsp.rm(path.join(jobDir, transient), { force: true });

  let r = run("git", ["init"], { cwd: jobDir });
  if (r.code) throw new Error(r.out);
  await fsp.writeFile(
    path.join(jobDir, ".git", "info", "exclude"),
    ".diana-base-sha\n.last-used\n.codex-last.log\n.codex-output-schema.json\n.codex-final-message.json\n.luna-result.json\n.luna-audit.json\n",
    { encoding: "utf8" }
  );
  run("git", ["config", "user.name", "Diana Luna Bridge"], { cwd: jobDir });
  run("git", ["config", "user.email", "bridge@invalid.local"], { cwd: jobDir });
  r = run("git", ["add", "-A"], { cwd: jobDir });
  if (r.code) throw new Error(r.out);
  r = run("git", ["commit", "-m", "baseline " + baseSha], { cwd: jobDir });
  if (r.code) throw new Error(r.out);
  await fsp.writeFile(marker, baseSha + "\n", { mode: 0o600 });
  await fsp.writeFile(path.join(jobDir, ".last-used"), new Date().toISOString());
  return { reused: false };
}

async function cleanupJobs() {
  await fsp.mkdir(JOB_ROOT, { recursive: true, mode: 0o700 });
  const entries = [];
  for (const name of await fsp.readdir(JOB_ROOT)) {
    const p = path.join(JOB_ROOT, name);
    try {
      const st = await fsp.stat(p);
      if (st.isDirectory()) entries.push({ p, m: st.mtimeMs });
    } catch {}
  }
  entries.sort((a, b) => b.m - a.m);
  const now = Date.now();
  const cutoff = now - 3 * 24 * 60 * 60 * 1000;
  const smokeCutoff = now - 5 * 60 * 1000;
  for (let i = 0; i < entries.length; i++) {
    const name = path.basename(entries[i].p);
    const staleSmoke = name.startsWith("smoke-") && entries[i].m < smokeCutoff;
    if (staleSmoke || i >= 6 || entries[i].m < cutoff)
      await fsp.rm(entries[i].p, { recursive: true, force: true });
  }
}

function outputSchema(resultFile) {
  if (resultFile === ".luna-audit.json") {
    return {
      type: "object",
      properties: {
        schema: { type: "integer" },
        smoke: { type: "string" },
        findings: {
          type: "array",
          items: {
            type: "object",
            properties: {
              title: { type: "string" },
              priority: { type: "string", enum: ["P1", "P2", "P3"] },
              why: { type: "string" },
              evidence: { type: "string" },
              acceptance: { type: "string" },
              paths: { type: "array", items: { type: "string" } },
              conflict_keys: { type: "array", items: { type: "string" } }
            },
            required: ["title","priority","why","evidence","acceptance","paths","conflict_keys"],
            additionalProperties: false
          }
        }
      },
      required: ["schema","smoke","findings"],
      additionalProperties: false
    };
  }
  return {
    type: "object",
    properties: {
      schema: { type: "integer" },
      task_id: { type: "string" },
      worker: { type: "string" },
      status: { type: "string", enum: ["READY_FOR_INTEGRATION","CONTINUE","BLOCKED","NOOP"] },
      summary: { type: "string" },
      tests: {
        type: "array",
        items: {
          type: "object",
          properties: {
            command: { type: "string" },
            exit_code: { type: "integer" }
          },
          required: ["command","exit_code"],
          additionalProperties: false
        }
      },
      files: { type: "array", items: { type: "string" } },
      notes: { type: "string" }
    },
    required: ["schema","task_id","worker","status","summary","tests","files","notes"],
    additionalProperties: false
  };
}

async function runCodex(jobDir, prompt, timeout, logFile, resultFile) {
  const env = {
    PATH: process.env.PATH || "/usr/local/bin:/usr/bin:/bin",
    HOME: "/root",
    CODEX_HOME,
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    CI: "1",
  };
  const schemaFile = path.join(jobDir, ".codex-output-schema.json");
  const finalFile = path.join(jobDir, ".codex-final-message.json");
  await fsp.writeFile(schemaFile, JSON.stringify(outputSchema(resultFile)), { mode: 0o600 });
  await fsp.rm(finalFile, { force: true });
  const args = [
    "exec", "--skip-git-repo-check", "--ephemeral", "--ignore-user-config",
    "--sandbox", "workspace-write", "--color", "never",
    "--output-schema", schemaFile, "--output-last-message", finalFile,
    "-m", "gpt-5.6-luna", "-c", "model_reasoning_effort=max", prompt,
  ];
  const out = fs.createWriteStream(logFile, { flags: "w", mode: 0o600 });
  const child = spawn("codex", args, { cwd: jobDir, env, stdio: ["ignore", "pipe", "pipe"] });
  child.stdout.pipe(out, { end: false });
  child.stderr.pipe(out, { end: false });
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    child.kill("SIGTERM");
    setTimeout(() => child.kill("SIGKILL"), 5000).unref();
  }, timeout * 1000);
  const code = await new Promise((resolve) =>
    child.on("exit", (c, sig) => resolve(c ?? (sig ? 128 : 1))));
  clearTimeout(timer);
  await new Promise((resolve) => out.end(resolve));
  return { code, timedOut };
}

async function collectResult(jobDir, resultFile, logFile) {
  const rp = path.join(jobDir, resultFile);
  const finalMessage = path.join(jobDir, ".codex-final-message.json");
  let result = null;
  for (const candidate of [rp, finalMessage]) {
    try {
      const st = await fsp.stat(candidate);
      if (st.size > MAX_RESULT) throw new Error("result file too large");
      result = JSON.parse(await fsp.readFile(candidate, "utf8"));
      if (result && typeof result === "object") break;
    } catch {}
  }
  await fsp.rm(rp, { force: true });
  await fsp.rm(finalMessage, { force: true });
  await fsp.rm(path.join(jobDir, ".codex-output-schema.json"), { force: true });
  const other = resultFile === ".luna-result.json" ? ".luna-audit.json" : ".luna-result.json";
  await fsp.rm(path.join(jobDir, other), { force: true });

  let r = run("git", ["add", "-A"], { cwd: jobDir });
  if (r.code) throw new Error(r.out);
  const names = run("git", ["diff", "--cached", "--name-only", "HEAD"], { cwd: jobDir });
  if (names.code) throw new Error(names.out);
  const patch = run("git", ["diff", "--cached", "--binary", "--full-index", "HEAD"], {
    cwd: jobDir, maxBuffer: MAX_PATCH + 1024 * 1024,
  });
  if (patch.code) throw new Error(patch.out);
  const pb = Buffer.from(patch.out, "utf8");
  if (pb.length > MAX_PATCH) throw new Error("patch too large");

  let logTail = "";
  try {
    const b = await fsp.readFile(logFile);
    logTail = b.subarray(Math.max(0, b.length - MAX_LOG_TAIL)).toString("utf8");
  } catch {}
  await fsp.writeFile(path.join(jobDir, ".last-used"), new Date().toISOString());
  return {
    result,
    changed_files: names.out.split("\n").filter(Boolean),
    patch_b64: pb.toString("base64"),
    log_tail: logTail,
  };
}


class CodexAppServerClient {
  constructor() {
    this.proc = null;
    this.rl = null;
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = new Set();
    this.startPromise = null;
    this.stderrTail = "";
  }

  async ensureStarted() {
    if (this.proc && this.proc.exitCode === null) return;
    if (this.startPromise) return this.startPromise;
    this.startPromise = this._start();
    try { await this.startPromise; }
    finally { this.startPromise = null; }
  }

  async _start() {
    const env = {
      PATH: process.env.PATH || "/usr/local/bin:/usr/bin:/bin",
      HOME: "/root",
      CODEX_HOME,
      LANG: "C.UTF-8",
      LC_ALL: "C.UTF-8",
      CI: "1",
    };
    const proc = spawn("codex", ["app-server", "--stdio"], {
      env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.proc = proc;
    this.stderrTail = "";
    this.rl = readline.createInterface({ input: proc.stdout });

    proc.stderr.on("data", (buf) => {
      this.stderrTail = (this.stderrTail + buf.toString("utf8")).slice(-16000);
    });

    this.rl.on("line", (line) => {
      if (!line.trim()) return;
      let msg;
      try { msg = JSON.parse(line); }
      catch { return; }
      if (Object.prototype.hasOwnProperty.call(msg, "id") && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        if (msg.error) reject(new Error("app-server RPC error: " + JSON.stringify(msg.error).slice(0, 2000)));
        else resolve(msg.result);
        return;
      }
      for (const listener of this.listeners) {
        try { listener(msg); } catch {}
      }
    });

    const failAll = (reason) => {
      const err = reason instanceof Error ? reason : new Error(String(reason || "app-server exited"));
      for (const { reject } of this.pending.values()) reject(err);
      this.pending.clear();
      this.proc = null;
    };
    proc.on("error", failAll);
    proc.on("exit", (code, signal) => failAll(new Error("app-server exited code=" + code + " signal=" + signal)));

    const init = await this.request("initialize", {
      clientInfo: { name: "diana_luna_bridge", title: "Diana Luna Bridge", version: "1.0.0" },
    }, 30000);
    if (!init) throw new Error("app-server initialize returned no result");
    this.notify("initialized", {});
  }

  request(method, params, timeoutMs = 30000) {
    if (!this.proc || this.proc.exitCode !== null) return Promise.reject(new Error("app-server unavailable"));
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (this.pending.delete(id)) reject(new Error("app-server RPC timeout: " + method));
      }, timeoutMs);
      this.pending.set(id, {
        resolve: (v) => { clearTimeout(timer); resolve(v); },
        reject: (e) => { clearTimeout(timer); reject(e); },
      });
      this.proc.stdin.write(JSON.stringify({ method, id, params }) + "\n");
    });
  }

  notify(method, params) {
    if (!this.proc || this.proc.exitCode !== null) throw new Error("app-server unavailable");
    this.proc.stdin.write(JSON.stringify({ method, params }) + "\n");
  }

  async runTurn(jobDir, prompt, timeout, resultFile, logFile) {
    await this.ensureStarted();

    const threadStart = await this.request("thread/start", {
      model: "gpt-5.6-luna",
      cwd: jobDir,
      approvalPolicy: "never",
      sandbox: "workspace-write",
      ephemeral: true,
      serviceName: "diana_luna_bridge",
      config: {
        "agents.enabled": false
      }
    }, 60000);
    const threadId = threadStart?.thread?.id;
    if (!threadId) throw new Error("app-server thread/start missing thread id");

    const events = [];
    const messages = [];
    let turnDoneResolve, turnDoneReject;
    const turnDone = new Promise((resolve, reject) => {
      turnDoneResolve = resolve;
      turnDoneReject = reject;
    });
    let turnId = null;

    const listener = (msg) => {
      const method = String(msg?.method || "");
      const p = msg?.params || {};
      if (p.threadId && p.threadId !== threadId) return;

      if (method === "item/completed") {
        const item = p.item || {};
        if (item.type === "agentMessage" && typeof item.text === "string") {
          messages.push({ text: item.text, phase: item.phase || null });
        }
      }
      if (method === "turn/completed") {
        if (turnId && p?.turn?.id && p.turn.id !== turnId) return;
        turnDoneResolve(p.turn || {});
      }
      if (method === "error") {
        events.push({ method, params: p });
      }
      if (events.length < 200) events.push({ method, params: p });
    };
    this.listeners.add(listener);

    let timedOut = false;
    try {
      const turn = await this.request("turn/start", {
        threadId,
        input: [{ type: "text", text: prompt }],
        cwd: jobDir,
        approvalPolicy: "never",
        sandboxPolicy: {
          type: "workspaceWrite",
          writableRoots: [jobDir],
          networkAccess: false
        },
        model: "gpt-5.6-luna",
        effort: "max",
        summary: "concise",
        outputSchema: outputSchema(resultFile)
      }, 60000);
      turnId = turn?.turn?.id || null;

      let timer;
      const timeoutPromise = new Promise((resolve) => {
        timer = setTimeout(() => resolve({ __timeout: true }), timeout * 1000);
      });
      const completed = await Promise.race([turnDone, timeoutPromise]);
      clearTimeout(timer);
      if (completed?.__timeout) {
        timedOut = true;
        if (turnId) {
          await this.request("turn/interrupt", { threadId, turnId }, 15000).catch(() => {});
        }
      }

      let finalText = "";
      for (let i = messages.length - 1; i >= 0; i--) {
        if (messages[i].phase === "final_answer") { finalText = messages[i].text; break; }
        if (!finalText) finalText = messages[i].text;
      }

      let parsed = null;
      if (finalText) {
        try { parsed = JSON.parse(finalText); }
        catch {}
      }

      const compactEvents = events.slice(-60).map((e) => ({
        method: e.method,
        threadId: e.params?.threadId || null,
        turnId: e.params?.turnId || e.params?.turn?.id || null,
        itemType: e.params?.item?.type || null,
        status: e.params?.turn?.status || e.params?.item?.status || null,
      }));
      await fsp.writeFile(logFile,
        JSON.stringify({
          backend: "app-server",
          threadId,
          turnId,
          timedOut,
          finalMessageCount: messages.length,
          stderrTail: this.stderrTail.slice(-4000),
          events: compactEvents,
        }, null, 2) + "\n",
        { mode: 0o600 }
      );

      return {
        code: timedOut ? 124 : (parsed ? 0 : 2),
        timedOut,
        result: parsed,
        threadId,
        turnId,
      };
    } finally {
      this.listeners.delete(listener);
      await this.request("thread/delete", { threadId }, 15000).catch(() => {});
    }
  }
}

const appServer = new CodexAppServerClient();

async function handleAppRun(req, res) {
  const authz = String(req.headers.authorization || "");
  if (!authz.startsWith("Bearer ")) return json(res, 401, { ok: false, error: "missing bearer" });
  try { await verifyOidc(authz.slice(7)); }
  catch (e) { return json(res, 403, { ok: false, error: String(e.message || e) }); }

  const requestFile = path.join(os.tmpdir(), "diana-app-" + crypto.randomUUID() + ".bin");
  let tarFile = "";
  try {
    await cleanupJobs();
    await readRequestToFile(req, requestFile);
    const envelope = await parseEnvelope(requestFile);
    tarFile = envelope.tarFile;
    const meta = validateMeta(envelope.meta);
    validateArchive(tarFile);
    const jobDir = path.join(JOB_ROOT, "app-" + meta.jobId);
    const prepared = await prepareWorkspace(jobDir, tarFile, meta.baseSha);
    const logFile = path.join(jobDir, ".codex-app-last.log");
    const exec = await appServer.runTurn(jobDir, meta.prompt, meta.timeout, meta.resultFile, logFile);

    if (exec.result !== null && exec.result !== undefined) {
      await fsp.writeFile(
        path.join(jobDir, meta.resultFile),
        JSON.stringify(exec.result) + "\n",
        { mode: 0o600 }
      );
    }
    const collected = await collectResult(jobDir, meta.resultFile, logFile);
    return json(res, 200, {
      ok: true,
      backend: "app-server",
      job_id: meta.jobId,
      base_sha: meta.baseSha,
      reused_workspace: prepared.reused,
      model_exit: exec.code,
      timed_out: exec.timedOut,
      thread_id: exec.threadId,
      turn_id: exec.turnId,
      ...collected,
    });
  } catch (e) {
    return json(res, 500, {
      ok: false,
      backend: "app-server",
      error: String(e.message || e).slice(0, 3000),
    });
  } finally {
    await fsp.rm(requestFile, { force: true }).catch(() => {});
    if (tarFile) await fsp.rm(tarFile, { force: true }).catch(() => {});
  }
}

async function health() {
  const mount = run("findmnt", ["-n", CODEX_HOME]);
  const auth = run("codex", ["login", "status"]);
  return {
    ok: mount.code === 0 && auth.code === 0,
    storage: mount.code === 0,
    codex_auth: auth.code === 0,
    active,
    queued: waiters.length,
    max_concurrent: MAX_CONCURRENT,
  };
}

async function handleRun(req, res) {
  const authz = String(req.headers.authorization || "");
  if (!authz.startsWith("Bearer ")) return json(res, 401, { ok: false, error: "missing bearer" });
  try { await verifyOidc(authz.slice(7)); }
  catch (e) { return json(res, 403, { ok: false, error: String(e.message || e) }); }

  try {
    await acquireSlot();
  } catch (e) {
    return json(res, 429, { ok: false, error: String(e.message || e) });
  }
  const requestFile = path.join(os.tmpdir(), "diana-" + crypto.randomUUID() + ".bin");
  let tarFile = "";
  try {
    await cleanupJobs();
    await readRequestToFile(req, requestFile);
    const envelope = await parseEnvelope(requestFile);
    tarFile = envelope.tarFile;
    const meta = validateMeta(envelope.meta);
    validateArchive(tarFile);
    const jobDir = path.join(JOB_ROOT, meta.jobId);
    const prepared = await prepareWorkspace(jobDir, tarFile, meta.baseSha);
    const logFile = path.join(jobDir, ".codex-last.log");
    const exec = await runCodex(jobDir, meta.prompt, meta.timeout, logFile, meta.resultFile);
    const collected = await collectResult(jobDir, meta.resultFile, logFile);
    return json(res, 200, {
      ok: true,
      job_id: meta.jobId,
      base_sha: meta.baseSha,
      reused_workspace: prepared.reused,
      model_exit: exec.code,
      timed_out: exec.timedOut,
      ...collected,
    });
  } catch (e) {
    return json(res, 500, { ok: false, error: String(e.message || e).slice(0, 2000) });
  } finally {
    releaseSlot();
    await fsp.rm(requestFile, { force: true }).catch(() => {});
    if (tarFile) await fsp.rm(tarFile, { force: true }).catch(() => {});
  }
}

await fsp.mkdir(JOB_ROOT, { recursive: true, mode: 0o700 });
const startup = await health();
if (!startup.ok) {
  console.error("bridge startup health failed", startup);
  process.exit(1);
}
console.log(JSON.stringify({ event: "bridge_ready", port: PORT, oidc: true, codex_auth: true }));

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === "GET" && req.url === "/health") return json(res, 200, await health());
    if (req.method === "POST" && req.url === "/run") return await handleRun(req, res);
    if (req.method === "POST" && req.url === "/app-run") return await handleAppRun(req, res);
    return json(res, 404, { ok: false, error: "not found" });
  } catch (e) {
    return json(res, 500, { ok: false, error: String(e.message || e).slice(0, 1000) });
  }
});
server.headersTimeout = 30000;
server.requestTimeout = (MAX_TIMEOUT + 120) * 1000;
server.listen(PORT, "0.0.0.0");
