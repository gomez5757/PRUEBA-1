#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

const AUDIENCE = "diana-luna-auth-v1";

function die(msg) {
  console.error("[luna-auth] " + msg);
  process.exit(1);
}

async function oidcToken() {
  const url = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const reqToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!url || !reqToken) die("GitHub OIDC is unavailable");
  const u = new URL(url);
  u.searchParams.set("audience", AUDIENCE);
  const r = await fetch(u, { headers: { Authorization: `Bearer ${reqToken}` } });
  if (!r.ok) die("OIDC request failed: " + r.status);
  const data = await r.json();
  if (!data?.value) die("OIDC response had no token");
  return data.value;
}

async function postJson(url, body) {
  const token = await oidcToken();
  const r = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
    body: JSON.stringify(body),
  });
  const text = await r.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch {}
  return { r, data };
}

async function lease(broker, outDir) {
  await fs.mkdir(outDir, { recursive: true, mode: 0o700 });
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 3072,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  const { r, data } = await postJson(broker + "/v1/auth/lease", {
    public_key_pem: publicKey,
  });
  if (!r.ok || !data?.ok) die("credential lease rejected: " + r.status);

  const aes = crypto.privateDecrypt({
    key: privateKey,
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
  if (parsed?.auth_mode && parsed.auth_mode !== "chatgpt") die("leased auth is not ChatGPT auth");
  if (!parsed?.tokens?.access_token || !parsed?.tokens?.refresh_token) die("leased auth is incomplete");

  const authPath = path.join(outDir, "auth.json");
  await fs.writeFile(authPath, auth, { mode: 0o600 });
  const statePath = path.join(outDir, ".lease.json");
  await fs.writeFile(statePath, JSON.stringify({
    lease_id: data.lease_id,
    base_hash: data.base_hash,
  }), { mode: 0o600 });

  aes.fill(0);
  auth.fill(0);
  console.log("LUNA_AUTH_LEASE_OK=yes");
}

async function commit(broker, codexHome) {
  const statePath = path.join(codexHome, ".lease.json");
  const authPath = path.join(codexHome, "auth.json");
  const [stateRaw, auth] = await Promise.all([
    fs.readFile(statePath, "utf8"),
    fs.readFile(authPath),
  ]);
  const state = JSON.parse(stateRaw);
  const { r, data } = await postJson(broker + "/v1/auth/commit", {
    lease_id: state.lease_id,
    base_hash: state.base_hash,
    auth_b64: auth.toString("base64"),
  });
  auth.fill(0);
  if (r.status === 409 && data?.stale) {
    console.log("LUNA_AUTH_COMMIT=stale-safe");
    return;
  }
  if (!r.ok || !data?.ok) die("credential commit rejected: " + r.status);
  console.log("LUNA_AUTH_COMMIT=" + (data.updated ? "updated" : "unchanged"));
}

const [cmd, brokerArg, homeArg] = process.argv.slice(2);
if (!["lease", "commit"].includes(cmd)) die("usage: luna_hosted_auth.mjs lease|commit BROKER CODEX_HOME");
const broker = String(brokerArg || "").replace(/\/$/, "");
if (!broker.startsWith("https://")) die("broker must use https");
if (!homeArg) die("CODEX_HOME path required");

try {
  if (cmd === "lease") await lease(broker, homeArg);
  else await commit(broker, homeArg);
} catch (e) {
  die(String(e?.message || e).slice(0, 500));
}
