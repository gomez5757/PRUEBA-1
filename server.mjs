import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { spawnSync } from "node:child_process";

const PORT = Number(process.env.PORT || 8080);
const CODEX_HOME = process.env.CODEX_HOME || "/root/.codex";
const AUTH_PATH = path.join(CODEX_HOME, "auth.json");
const EXPECTED_ISS = "https://token.actions.githubusercontent.com";
const EXPECTED_AUD = process.env.DIANA_OIDC_AUDIENCE || "diana-luna-auth-v1";
const EXPECTED_REPO = process.env.DIANA_REPOSITORY || "gomez5757/PRUEBA-1";
const EXPECTED_REPO_ID = String(process.env.DIANA_REPOSITORY_ID || "1203071224");
const ALLOWED_REFS = new Set((process.env.DIANA_ALLOWED_REFS ||
  "refs/heads/main").split(",").filter(Boolean));
const ALLOWED_WORKFLOW = process.env.DIANA_ALLOWED_WORKFLOW ||
  `${EXPECTED_REPO}/.github/workflows/luna-public-worker.yml@`;
const MAX_BODY = 256 * 1024;
const MAX_AUTH = 128 * 1024;
const seenJti = new Map();
let jwksCache = { at: 0, keys: [] };

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
function b64urlDecode(s) { return Buffer.from(String(s).replace(/-/g, "+").replace(/_/g, "/"), "base64"); }
function safeEqual(a,b) {
  const x=Buffer.from(String(a)), y=Buffer.from(String(b));
  return x.length===y.length && crypto.timingSafeEqual(x,y);
}
async function fetchJson(url) {
  const r=await fetch(url,{headers:{"user-agent":"diana-luna-auth-broker/1"}});
  if(!r.ok) throw new Error(`fetch failed ${r.status}`);
  return r.json();
}
async function getJwks() {
  const now=Date.now();
  if(jwksCache.keys.length && now-jwksCache.at<15*60*1000) return jwksCache.keys;
  const cfg=await fetchJson(EXPECTED_ISS+"/.well-known/openid-configuration");
  const data=await fetchJson(cfg.jwks_uri);
  if(!Array.isArray(data.keys)||!data.keys.length) throw new Error("empty JWKS");
  jwksCache={at:now,keys:data.keys}; return data.keys;
}
function audienceOk(aud) {
  return Array.isArray(aud) ? aud.some(x=>safeEqual(x,EXPECTED_AUD)) : safeEqual(aud||"",EXPECTED_AUD);
}
async function verifyOidc(token) {
  const parts=String(token||"").split(".");
  if(parts.length!==3) throw new Error("malformed bearer");
  const header=JSON.parse(b64urlDecode(parts[0]).toString("utf8"));
  const claims=JSON.parse(b64urlDecode(parts[1]).toString("utf8"));
  if(header.alg!=="RS256"||!header.kid) throw new Error("unsupported JWT header");
  let keys=await getJwks();
  let jwk=keys.find(k=>k.kid===header.kid&&k.kty==="RSA");
  if(!jwk){ jwksCache={at:0,keys:[]}; keys=await getJwks(); jwk=keys.find(k=>k.kid===header.kid&&k.kty==="RSA"); }
  if(!jwk) throw new Error("unknown JWT key");
  const key=crypto.createPublicKey({key:jwk,format:"jwk"});
  const signing=Buffer.from(parts[0]+"."+parts[1]);
  if(!crypto.verify("RSA-SHA256",signing,key,b64urlDecode(parts[2]))) throw new Error("bad JWT signature");
  const now=Math.floor(Date.now()/1000);
  if(!safeEqual(claims.iss||"",EXPECTED_ISS)) throw new Error("bad issuer");
  if(!audienceOk(claims.aud)) throw new Error("bad audience");
  if(!Number.isFinite(claims.exp)||claims.exp<now-15||claims.exp>now+10*60) throw new Error("bad exp");
  if(claims.nbf&&claims.nbf>now+30) throw new Error("bad nbf");
  if(claims.iat&&claims.iat>now+30) throw new Error("bad iat");
  if(!safeEqual(claims.repository||"",EXPECTED_REPO)) throw new Error("wrong repository");
  if(!safeEqual(String(claims.repository_id||""),EXPECTED_REPO_ID)) throw new Error("wrong repository id");
  if(!ALLOWED_REFS.has(String(claims.ref||""))) throw new Error("ref not allowed");
  if(!safeEqual(String(claims.runner_environment||""),"github-hosted")) throw new Error("runner environment not allowed");
  if(!["workflow_dispatch","push","schedule"].includes(String(claims.event_name||""))) throw new Error("event not allowed");
  if(!String(claims.workflow_ref||"").includes(ALLOWED_WORKFLOW)) throw new Error("workflow not allowed");
  const jti=String(claims.jti||"");
  if(!jti) throw new Error("missing jti");
  for(const [id,exp] of seenJti) if(exp<now) seenJti.delete(id);
  if(seenJti.has(jti)) throw new Error("OIDC replay");
  seenJti.set(jti,claims.exp);
  return claims;
}
async function readJsonBody(req) {
  const chunks=[]; let total=0;
  for await (const c of req) { total+=c.length; if(total>MAX_BODY) throw new Error("request too large"); chunks.push(c); }
  const raw=Buffer.concat(chunks).toString("utf8");
  return raw ? JSON.parse(raw) : {};
}
function sha256(buf){ return crypto.createHash("sha256").update(buf).digest("hex"); }
function validateAuth(buf) {
  if(!Buffer.isBuffer(buf)||buf.length<32||buf.length>MAX_AUTH) throw new Error("invalid auth size");
  const obj=JSON.parse(buf.toString("utf8"));
  if(!obj||typeof obj!=="object") throw new Error("invalid auth json");
  if(obj.auth_mode && obj.auth_mode!=="chatgpt") throw new Error("auth mode is not chatgpt");
  const tokens=obj.tokens;
  if(!tokens||typeof tokens!=="object"||!tokens.access_token||!tokens.refresh_token) throw new Error("missing chatgpt tokens");
  return obj;
}
function codexLoginOk(home=CODEX_HOME) {
  const p=spawnSync("codex",["login","status"],{env:{...process.env,CODEX_HOME:home,HOME:"/root"},encoding:"utf8",timeout:15000});
  return p.status===0 && /chatgpt/i.test(String(p.stdout||"")+String(p.stderr||""));
}
async function currentAuth() {
  const buf=await fsp.readFile(AUTH_PATH);
  validateAuth(buf);
  if(!codexLoginOk()) throw new Error("codex chatgpt login is not healthy");
  return buf;
}
async function validateCandidate(buf) {
  validateAuth(buf);
  const tmp=await fsp.mkdtemp("/tmp/codex-auth-check-");
  try {
    await fsp.writeFile(path.join(tmp,"auth.json"),buf,{mode:0o600});
    if(!codexLoginOk(tmp)) throw new Error("candidate auth rejected by codex");
  } finally { await fsp.rm(tmp,{recursive:true,force:true}); }
}
function encryptFor(pubPem, plaintext, aadText) {
  const pub=crypto.createPublicKey(pubPem);
  if(pub.asymmetricKeyType!=="rsa") throw new Error("ephemeral key must be RSA");
  const key=crypto.randomBytes(32), nonce=crypto.randomBytes(12);
  const cipher=crypto.createCipheriv("aes-256-gcm",key,nonce);
  const aad=Buffer.from(aadText,"utf8"); cipher.setAAD(aad);
  const ciphertext=Buffer.concat([cipher.update(plaintext),cipher.final()]);
  const tag=cipher.getAuthTag();
  const wrapped=crypto.publicEncrypt({key:pub,padding:crypto.constants.RSA_PKCS1_OAEP_PADDING,oaepHash:"sha256"},key);
  return {wrapped_key_b64:wrapped.toString("base64"),nonce_b64:nonce.toString("base64"),tag_b64:tag.toString("base64"),ciphertext_b64:ciphertext.toString("base64"),aad_b64:aad.toString("base64")};
}
async function authorize(req) {
  const h=String(req.headers.authorization||"");
  if(!h.startsWith("Bearer ")) throw Object.assign(new Error("missing bearer"),{status:401});
  try { return await verifyOidc(h.slice(7)); }
  catch(e){ throw Object.assign(e,{status:403}); }
}
async function lease(req,res) {
  const claims=await authorize(req); const body=await readJsonBody(req);
  const pub=String(body.public_key_pem||"");
  if(pub.length<100||pub.length>8192||!pub.includes("BEGIN PUBLIC KEY")) throw new Error("invalid public key");
  const auth=await currentAuth(); const hash=sha256(auth); const leaseId=crypto.randomUUID();
  const aad=`${leaseId}|${hash}|${claims.run_id||""}|${claims.run_attempt||""}`;
  const enc=encryptFor(pub,auth,aad);
  return json(res,200,{ok:true,schema:1,lease_id:leaseId,base_hash:hash,...enc});
}
async function commit(req,res) {
  const claims=await authorize(req); const body=await readJsonBody(req);
  const baseHash=String(body.base_hash||""); const leaseId=String(body.lease_id||"");
  const b64=String(body.auth_b64||"");
  if(!/^[0-9a-f]{64}$/.test(baseHash)||leaseId.length<10||b64.length>MAX_AUTH*2) throw new Error("invalid commit metadata");
  const next=Buffer.from(b64,"base64"); await validateCandidate(next);
  const cur=await fsp.readFile(AUTH_PATH); const curHash=sha256(cur);
  if(curHash!==baseHash) return json(res,409,{ok:false,stale:true,current_hash:curHash});
  const nextHash=sha256(next);
  if(nextHash===curHash) return json(res,200,{ok:true,updated:false,hash:curHash});
  const tmp=AUTH_PATH+`.tmp.${crypto.randomUUID()}`;
  await fsp.writeFile(tmp,next,{mode:0o600}); await fsp.rename(tmp,AUTH_PATH);
  console.log(JSON.stringify({event:"auth_updated",run_id:String(claims.run_id||""),hash:nextHash.slice(0,12)}));
  return json(res,200,{ok:true,updated:true,hash:nextHash});
}
async function health(res) {
  let auth=false, storage=false;
  try { const st=await fsp.stat(AUTH_PATH); storage=st.isFile(); auth=storage&&codexLoginOk(); } catch {}
  return json(res,auth?200:503,{ok:auth,mode:"credential-broker",storage,codex_auth:auth,schema:1});
}

const server=http.createServer(async(req,res)=>{
  try {
    if(req.method==="GET"&&req.url==="/health") return await health(res);
    if(req.method==="POST"&&req.url==="/v1/auth/lease") return await lease(req,res);
    if(req.method==="POST"&&req.url==="/v1/auth/commit") return await commit(req,res);
    return json(res,404,{ok:false,error:"not found"});
  } catch(e) {
    const status=Number(e.status)||500;
    console.error(JSON.stringify({event:"request_error",status,error:String(e.message||e).slice(0,300)}));
    return json(res,status,{ok:false,error:String(e.message||e).slice(0,300)});
  }
});
server.headersTimeout=15000; server.requestTimeout=30000;
server.listen(PORT,"0.0.0.0",()=>console.log(JSON.stringify({event:"auth_broker_ready",port:PORT,oidc:true})));
