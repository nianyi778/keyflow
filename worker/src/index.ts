import { Hono, type Context } from "hono";
import { cors } from "hono/cors";

type Bindings = {
  DB: D1Database;
  KV: KVNamespace;
  JWT_SECRET: string; // Set via wrangler secret put
};

type JWTPayload = {
  sub: string; // user_id
  iat: number;
  exp: number;
};

type Variables = {
  userId: string;
};

type PushEntry = {
  id: string;
  encrypted_blob: string;
  updated_at: string;
  is_deleted: number;
};

const TOKEN_LIFETIME_SECONDS = 365 * 24 * 60 * 60;
const RATE_LIMIT_PER_MINUTE = 100;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const LANDING_HTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<title>KeyFlow - Developer Key Vault</title>
<meta name="description" content="Local-first encrypted vault for API keys. CLI-native. MCP-ready. Cloud sync.">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='6' fill='%2322C55E'/><text x='16' y='22' text-anchor='middle' fill='%230F172A' font-family='monospace' font-weight='bold' font-size='14'>kf</text></svg>">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0F172A;--sf:#1E293B;--bd:#334155;--ac:#22C55E;--cy:#22d3ee;--am:#fbbf24;--rd:#f87171;--tx:#F8FAFC;--mt:#94A3B8;--dm:#64748B;--mn:'JetBrains Mono',monospace;--sn:'IBM Plex Sans',sans-serif}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--tx);font-family:var(--sn);line-height:1.6;-webkit-font-smoothing:antialiased;overflow-x:hidden}
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(15,23,42,.03) 2px,rgba(15,23,42,.03) 4px);pointer-events:none;z-index:9999}
a{color:var(--cy);text-decoration:none;transition:color .2s}a:hover{color:var(--ac)}
.w{max-width:880px;margin:0 auto;padding:0 24px}
nav{position:fixed;top:0;left:0;right:0;z-index:100;padding:16px 24px;display:flex;justify-content:space-between;align-items:center;background:rgba(15,23,42,.85);backdrop-filter:blur(12px);border-bottom:1px solid rgba(51,65,85,.5)}
nav .logo{font-family:var(--mn);font-weight:700;font-size:16px;color:var(--ac);letter-spacing:-0.5px}
nav .logo span{color:var(--dm)}
nav a.gh{font-family:var(--mn);font-size:12px;color:var(--mt);padding:6px 16px;border:1px solid var(--bd);border-radius:6px;transition:all .2s}
nav a.gh:hover{border-color:var(--ac);color:var(--tx)}
.hero{padding:120px 0 72px;text-align:center}
.pill{display:inline-block;font-family:var(--mn);font-size:11px;letter-spacing:2px;text-transform:uppercase;color:var(--ac);border:1px solid rgba(34,197,94,.3);padding:6px 16px;border-radius:20px;margin-bottom:24px;background:rgba(34,197,94,.06)}
.hero h1{font-family:var(--mn);font-weight:700;font-size:clamp(2.8rem,9vw,4.5rem);letter-spacing:-2px;margin-bottom:16px;color:var(--tx)}
.hero h1 em{font-style:normal;color:var(--ac)}
.hero-sub{font-size:1.1rem;color:var(--mt);max-width:480px;margin:0 auto 40px;line-height:1.8}
.tm{background:var(--sf);border:1px solid var(--bd);border-radius:10px;overflow:hidden;text-align:left}
.tm-bar{display:flex;align-items:center;gap:7px;padding:11px 16px;background:rgba(15,23,42,.5);border-bottom:1px solid var(--bd)}
.dot{width:11px;height:11px;border-radius:50%}.dot-r{background:#f87171}.dot-y{background:#fbbf24}.dot-g{background:#22c55e}
.tm-b{padding:18px 22px;font-family:var(--mn);font-size:13px;line-height:2.1;color:var(--mt)}
.ps{color:var(--tx)}.ps::before{content:'$ ';color:var(--ac)}
.out{padding-left:20px;color:var(--dm)}.hl{color:var(--ac)}.hl2{color:var(--am)}.hl3{color:var(--cy)}
.cur::after{content:'_';animation:blink 1s step-end infinite;color:var(--ac)}
@keyframes blink{50%{opacity:0}}
.sec{padding:72px 0}
.sec-l{font-family:var(--mn);font-size:11px;letter-spacing:3px;text-transform:uppercase;color:var(--dm);margin-bottom:10px}
.sec h2{font-family:var(--mn);font-size:clamp(1.3rem,3.5vw,1.6rem);font-weight:700;margin-bottom:12px;letter-spacing:-0.5px}
.sec-d{color:var(--mt);max-width:520px;line-height:1.8;font-size:15px;margin-bottom:28px}
.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:14px}
.card{background:var(--sf);border:1px solid var(--bd);border-radius:10px;padding:28px;transition:border-color .25s,transform .25s;cursor:default}
.card:hover{border-color:var(--ac);transform:translateY(-3px)}
.card-icon{font-family:var(--mn);font-size:22px;font-weight:700;margin-bottom:14px;width:44px;height:44px;display:flex;align-items:center;justify-content:center;border-radius:10px;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.15)}
.card h3{font-family:var(--mn);font-size:14px;font-weight:700;margin-bottom:8px}
.card p{font-size:13.5px;color:var(--mt);line-height:1.7}
.tags{display:flex;flex-wrap:wrap;gap:8px;margin-top:20px}
.tag{font-family:var(--mn);font-size:12px;padding:7px 16px;background:var(--sf);border:1px solid var(--bd);border-radius:6px;color:var(--mt);transition:all .2s;cursor:default}
.tag:hover{border-color:var(--cy);color:var(--tx)}.tag.active{border-color:var(--ac);color:var(--tx);background:rgba(34,197,94,.1)}
.sep{border:none;border-top:1px solid rgba(51,65,85,.5);margin:0}
.cta-box{text-align:center;padding:72px 0 56px}
.cta-btn{display:inline-block;font-family:var(--mn);font-size:14px;font-weight:700;padding:14px 40px;background:var(--ac);color:var(--bg);border-radius:8px;letter-spacing:0.5px;transition:all .25s}
.cta-btn:hover{transform:translateY(-2px);box-shadow:0 16px 48px rgba(34,197,94,.2);color:var(--bg)}
footer{padding:36px 0;text-align:center;font-size:12px;color:var(--dm);font-family:var(--mn);border-top:1px solid rgba(51,65,85,.5)}
.glow{position:fixed;top:-300px;left:50%;transform:translateX(-50%);width:800px;height:600px;background:radial-gradient(ellipse,rgba(34,197,94,.03),transparent 70%);pointer-events:none;z-index:-1}
@keyframes up{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:none}}
.hero,.sec,.cta-box{animation:up .6s ease both}
.sec:nth-of-type(2){animation-delay:.05s}.sec:nth-of-type(3){animation-delay:.1s}.sec:nth-of-type(4){animation-delay:.15s}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
@media(max-width:640px){.hero{padding:88px 0 48px}.sec{padding:48px 0}.grid{grid-template-columns:1fr}.tm-b{font-size:12px;padding:14px 16px}nav{padding:12px 16px}}
</style></head>
<body>
<div class="glow"></div>
<nav><div class="logo">kf<span>low</span></div><a class="gh" href="https://github.com/nianyi778/keyflow">GitHub</a></nav>
<div class="w">
<header class="hero">
<span class="pill">v0.5.0 -- open source</span>
<h1>Key<em>Flow</em></h1>
<p class="hero-sub">Local-first encrypted vault for API keys. Store once, search fast, reuse everywhere, expose safely to AI.</p>
<div class="tm" style="max-width:540px;margin:0 auto">
<div class="tm-bar"><span class="dot dot-r"></span><span class="dot dot-y"></span><span class="dot dot-g"></span></div>
<div class="tm-b">
<div class="ps">kf add OPENAI_API_KEY sk-*** --provider openai</div>
<div class="out"><span class="hl">+</span> Secret 'openai-api-key' added (env: <span class="hl2">OPENAI_API_KEY</span>)</div>
<div class="ps" style="margin-top:6px">kf search resend</div>
<div class="out"><span class="hl3">RESEND_API_KEY</span> provider:resend account:acme-mail</div>
<div class="ps" style="margin-top:6px">kf run --project myapp -- npm start</div>
<div class="out"><span class="hl">injecting 4 secrets for project: myapp</span><span class="cur"></span></div>
</div></div>
</header>
<hr class="sep">
<section class="sec">
<p class="sec-l">core</p>
<h2>Four things, done right</h2>
<div class="grid">
<div class="card"><div class="card-icon" style="color:var(--ac)">></div><h3>Secure Store</h3><p>AES-256-GCM encryption, Argon2 key derivation. Secrets never leave your machine unencrypted.</p></div>
<div class="card"><div class="card-icon" style="color:var(--cy)">?</div><h3>Instant Search</h3><p>Find keys by provider, project, account, or env var name. Ranked results from local SQLite vault.</p></div>
<div class="card"><div class="card-icon" style="color:var(--am)">#</div><h3>Stable Reuse</h3><p>Export .env per project. Inject at runtime with kf run. Track expiry, health, and rotation status.</p></div>
<div class="card"><div class="card-icon" style="color:var(--rd)">*</div><h3>AI-Safe</h3><p>MCP server exposes metadata only. AI reads what keys exist; plaintext values stay encrypted.</p></div>
</div></section>
<hr class="sep">
<section class="sec">
<p class="sec-l">install</p>
<h2>Up and running in 30 seconds</h2>
<div class="grid" style="grid-template-columns:1fr 1fr;gap:14px">
<div class="tm"><div class="tm-bar"><span class="dot dot-r"></span><span class="dot dot-y"></span><span class="dot dot-g"></span><span style="margin-left:auto;font-family:var(--mn);font-size:11px;color:var(--dm)">homebrew</span></div>
<div class="tm-b">
<div class="ps">brew tap nianyi778/keyflow</div>
<div class="ps">brew install keyflow</div>
<div class="ps" style="margin-top:6px">kf init</div>
<div class="out"><span class="hl">Ready.</span><span class="cur"></span></div>
</div></div>
<div class="tm"><div class="tm-bar"><span class="dot dot-r"></span><span class="dot dot-y"></span><span class="dot dot-g"></span><span style="margin-left:auto;font-family:var(--mn);font-size:11px;color:var(--dm)">cargo</span></div>
<div class="tm-b">
<div class="ps">cargo install --git https://github.com/nianyi778/keyflow</div>
<div class="ps" style="margin-top:6px">kf init</div>
<div class="out"><span class="hl">Ready.</span><span class="cur"></span></div>
</div></div>
</div></section>
<hr class="sep">
<section class="sec">
<p class="sec-l">mcp</p>
<h2>Native AI coding integration</h2>
<p class="sec-d">Ships an MCP server with 10 tools organized by discover / inspect / reuse / maintain. AI tools query your vault without seeing plaintext.</p>
<div class="tm" style="max-width:480px" id="mcp-tm">
<div class="tm-bar"><span class="dot dot-r"></span><span class="dot dot-y"></span><span class="dot dot-g"></span></div>
<div class="tm-b">
<div class="ps" id="mcp-cmd">kf setup claude</div>
<div class="out"><span class="hl">+</span> Configured <span id="mcp-name">Claude Code</span> MCP</div>
<div class="out">AI can now discover your keys<span class="cur"></span></div>
</div></div>
<div class="tags" id="mcp-tags">
<span class="tag active" data-cmd="kf setup claude" data-name="Claude Code">Claude Code</span>
<span class="tag" data-cmd="kf setup cursor" data-name="Cursor">Cursor</span>
<span class="tag" data-cmd="kf setup windsurf" data-name="Windsurf">Windsurf</span>
<span class="tag" data-cmd="kf setup gemini" data-name="Gemini CLI">Gemini CLI</span>
<span class="tag" data-cmd="kf setup opencode" data-name="OpenCode">OpenCode</span>
<span class="tag" data-cmd="kf setup codex" data-name="Codex">Codex</span>
<span class="tag" data-cmd="kf setup zed" data-name="Zed">Zed</span>
<span class="tag" data-cmd="kf setup cline" data-name="Cline">Cline</span>
<span class="tag" data-cmd="kf setup roo" data-name="Roo Code">Roo Code</span>
</div>
<div id="toast" style="position:fixed;bottom:32px;left:50%;transform:translateX(-50%) translateY(20px);font-family:var(--mn);font-size:13px;padding:10px 24px;background:var(--ac);color:var(--bg);border-radius:8px;opacity:0;transition:all .3s;pointer-events:none;z-index:200;font-weight:500"></div>
<script>
(function(){
var tags=document.getElementById('mcp-tags');
var cmd=document.getElementById('mcp-cmd');
var name=document.getElementById('mcp-name');
var toast=document.getElementById('toast');
var tid;
tags.addEventListener('click',function(e){
var t=e.target.closest('.tag');
if(!t||!t.dataset.cmd)return;
tags.querySelectorAll('.tag').forEach(function(el){el.classList.remove('active')});
t.classList.add('active');
cmd.textContent=t.dataset.cmd;
name.textContent=t.dataset.name;
navigator.clipboard.writeText(t.dataset.cmd).then(function(){
toast.textContent='Copied: '+t.dataset.cmd;
toast.style.opacity='1';
toast.style.transform='translateX(-50%) translateY(0)';
clearTimeout(tid);
tid=setTimeout(function(){
toast.style.opacity='0';
toast.style.transform='translateX(-50%) translateY(20px)';
},2000);
});
});
})();
</script>
</section>
<hr class="sep">
<section class="sec">
<p class="sec-l">sync</p>
<h2>Encrypted cloud sync</h2>
<p class="sec-d">End-to-end encrypted sync via Cloudflare Workers. The server never sees plaintext. Push, pull, conflict resolution -- all through <span style="font-family:var(--mn);color:var(--tx)">kf sync</span>.</p>
</section>
<hr class="sep">
<div class="cta-box">
<a class="cta-btn" href="https://github.com/nianyi778/keyflow">View on GitHub</a>
<p style="color:var(--dm);margin-top:18px;font-size:13px;font-family:var(--mn)">MIT / Rust / Local-first</p>
</div>
<footer><p>KeyFlow v0.5.0 -- MIT License -- <a href="https://github.com/nianyi778/keyflow" style="color:var(--dm)">github.com/nianyi778/keyflow</a></p></footer>
</div></body></html>`;

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>();

type AppContext = Context<{ Bindings: Bindings; Variables: Variables }>;

const jsonError = (c: AppContext, status: number, error: string, code: string) => {
  return c.json({ error, code }, status);
};

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(input: string): Uint8Array {
  const base64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const padding = base64.length % 4 === 0 ? "" : "=".repeat(4 - (base64.length % 4));
  const binary = atob(base64 + padding);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function importHmacKey(secret: string, usages: KeyUsage[]): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, usages);
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

async function signJWT(payload: JWTPayload, secret: string): Promise<string> {
  const header = { alg: "HS256", typ: "JWT" };
  const headerEncoded = toBase64Url(encoder.encode(JSON.stringify(header)));
  const payloadEncoded = toBase64Url(encoder.encode(JSON.stringify(payload)));
  const signingInput = `${headerEncoded}.${payloadEncoded}`;

  const key = await importHmacKey(secret, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(signingInput));
  const signatureEncoded = toBase64Url(new Uint8Array(signature));

  return `${signingInput}.${signatureEncoded}`;
}

async function verifyJWT(token: string, secret: string): Promise<JWTPayload | null> {
  const parts = token.split(".");
  if (parts.length !== 3) {
    return null;
  }

  const [headerEncoded, payloadEncoded, signatureEncoded] = parts;

  try {
    const headerRaw = decoder.decode(fromBase64Url(headerEncoded));
    const header = JSON.parse(headerRaw) as { alg?: string; typ?: string };
    if (header.alg !== "HS256" || header.typ !== "JWT") {
      return null;
    }

    const key = await importHmacKey(secret, ["verify"]);
    const signatureValid = await crypto.subtle.verify(
      "HMAC",
      key,
      toArrayBuffer(fromBase64Url(signatureEncoded)),
      encoder.encode(`${headerEncoded}.${payloadEncoded}`),
    );
    if (!signatureValid) {
      return null;
    }

    const payloadRaw = decoder.decode(fromBase64Url(payloadEncoded));
    const payload = JSON.parse(payloadRaw) as Partial<JWTPayload>;
    if (
      typeof payload.sub !== "string" ||
      typeof payload.iat !== "number" ||
      typeof payload.exp !== "number"
    ) {
      return null;
    }

    const now = Math.floor(Date.now() / 1000);
    if (payload.exp <= now) {
      return null;
    }

    return payload as JWTPayload;
  } catch {
    return null;
  }
}

async function issueToken(userId: string, secret: string): Promise<string> {
  const issuedAt = Math.floor(Date.now() / 1000);
  return signJWT(
    {
      sub: userId,
      iat: issuedAt,
      exp: issuedAt + TOKEN_LIFETIME_SECONDS,
    },
    secret,
  );
}

function isServerNewer(serverUpdatedAt: string, clientUpdatedAt: string): boolean {
  const serverTs = Date.parse(serverUpdatedAt);
  const clientTs = Date.parse(clientUpdatedAt);

  if (Number.isFinite(serverTs) && Number.isFinite(clientTs)) {
    return serverTs > clientTs;
  }

  return serverUpdatedAt > clientUpdatedAt;
}

app.use(
  "*",
  cors({
    origin: "*",
    allowMethods: ["GET", "POST", "OPTIONS"],
    allowHeaders: ["Content-Type", "Authorization"],
  }),
);

app.get("/", (c) => c.html(LANDING_HTML));

app.use("/api/*", async (c, next) => {
  const path = c.req.path;
  if (path === "/api/register" || path === "/api/login") {
    await next();
    return;
  }

  const authHeader = c.req.header("Authorization") ?? "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
  if (!token) {
    return jsonError(c, 401, "Missing bearer token", "UNAUTHORIZED");
  }

  const payload = await verifyJWT(token, c.env.JWT_SECRET);
  if (!payload) {
    return jsonError(c, 401, "Invalid or expired token", "UNAUTHORIZED");
  }

  c.set("userId", payload.sub);

  const minuteBucket = Math.floor(Date.now() / 60000);
  const rateKey = `rate:${payload.sub}:${minuteBucket}`;
  const currentRaw = await c.env.KV.get(rateKey);
  const parsed = currentRaw ? Number.parseInt(currentRaw, 10) : 0;
  const current = Number.isFinite(parsed) ? parsed : 0;

  if (current >= RATE_LIMIT_PER_MINUTE) {
    return jsonError(c, 429, "Rate limit exceeded", "RATE_LIMITED");
  }

  await c.env.KV.put(rateKey, String(current + 1), { expirationTtl: 120 });

  await next();
});

app.post("/api/register", async (c) => {
  const body = await c.req.json<{ password_hash: string }>().catch(() => null);
  if (!body || typeof body.password_hash !== "string" || body.password_hash.trim() === "") {
    return jsonError(c, 400, "Invalid request body", "BAD_REQUEST");
  }

  const userId = crypto.randomUUID();

  await c.env.DB.prepare("INSERT INTO users (id) VALUES (?)").bind(userId).run();
  await c.env.KV.put(`auth:${userId}`, body.password_hash);

  const token = await issueToken(userId, c.env.JWT_SECRET);
  return c.json({ user_id: userId, token });
});

app.post("/api/login", async (c) => {
  const body = await c.req.json<{ user_id: string; password_hash: string }>().catch(() => null);
  if (
    !body ||
    typeof body.user_id !== "string" ||
    body.user_id.trim() === "" ||
    typeof body.password_hash !== "string" ||
    body.password_hash.trim() === ""
  ) {
    return jsonError(c, 400, "Invalid request body", "BAD_REQUEST");
  }

  const storedHash = await c.env.KV.get(`auth:${body.user_id}`);
  if (!storedHash || storedHash !== body.password_hash) {
    return jsonError(c, 401, "Invalid credentials", "UNAUTHORIZED");
  }

  const token = await issueToken(body.user_id, c.env.JWT_SECRET);
  return c.json({ token });
});

app.post("/api/push", async (c) => {
  const userId = c.get("userId");
  const body = await c.req.json<{ entries: PushEntry[] }>().catch(() => null);
  if (!body || !Array.isArray(body.entries)) {
    return jsonError(c, 400, "Invalid request body", "BAD_REQUEST");
  }

  for (const entry of body.entries) {
    if (
      !entry ||
      typeof entry.id !== "string" ||
      entry.id.trim() === "" ||
      typeof entry.encrypted_blob !== "string" ||
      typeof entry.updated_at !== "string" ||
      (entry.is_deleted !== 0 && entry.is_deleted !== 1)
    ) {
      return jsonError(c, 400, "Invalid entry payload", "BAD_REQUEST");
    }
  }

  const latestSeqRow = await c.env.DB.prepare(
    "SELECT COALESCE(MAX(server_seq), 0) AS latest_seq FROM sync_entries WHERE user_id = ?",
  )
    .bind(userId)
    .first<{ latest_seq: number | string }>();
  let latestSeq = Number(latestSeqRow?.latest_seq ?? 0);

  if (body.entries.length === 0) {
    return c.json({ pushed: 0, conflicts: [], latest_seq: latestSeq });
  }

  const uniqueIds = [...new Set(body.entries.map((entry) => entry.id))];
  const placeholders = uniqueIds.map(() => "?").join(", ");
  const existingResult = await c.env.DB.prepare(
    `SELECT id, updated_at FROM sync_entries WHERE user_id = ? AND id IN (${placeholders})`,
  )
    .bind(userId, ...uniqueIds)
    .all<{ id: string; updated_at: string }>();

  const existingById = new Map<string, { updated_at: string }>();
  for (const row of existingResult.results ?? []) {
    existingById.set(row.id, { updated_at: row.updated_at });
  }

  const conflicts: Array<{ id: string; server_updated_at: string }> = [];
  const writes: D1PreparedStatement[] = [];

  for (const entry of body.entries) {
    const serverEntry = existingById.get(entry.id);
    if (serverEntry && isServerNewer(serverEntry.updated_at, entry.updated_at)) {
      conflicts.push({ id: entry.id, server_updated_at: serverEntry.updated_at });
      continue;
    }

    latestSeq += 1;
    writes.push(
      c.env.DB.prepare(
        "INSERT INTO sync_entries (id, user_id, encrypted_blob, updated_at, is_deleted, server_seq) VALUES (?, ?, ?, ?, ?, ?) " +
          "ON CONFLICT(id, user_id) DO UPDATE SET encrypted_blob = excluded.encrypted_blob, updated_at = excluded.updated_at, is_deleted = excluded.is_deleted, server_seq = excluded.server_seq",
      ).bind(entry.id, userId, entry.encrypted_blob, entry.updated_at, entry.is_deleted, latestSeq),
    );
  }

  if (writes.length > 0) {
    await c.env.DB.batch(writes);
  }

  return c.json({
    pushed: writes.length,
    conflicts,
    latest_seq: latestSeq,
  });
});

app.post("/api/pull", async (c) => {
  const userId = c.get("userId");
  const body = await c.req.json<{ since_seq: number }>().catch(() => null);
  if (!body || typeof body.since_seq !== "number" || body.since_seq < 0) {
    return jsonError(c, 400, "Invalid request body", "BAD_REQUEST");
  }

  const pullResult = await c.env.DB.prepare(
    "SELECT id, encrypted_blob, updated_at, is_deleted, server_seq FROM sync_entries WHERE user_id = ? AND server_seq > ? ORDER BY server_seq",
  )
    .bind(userId, body.since_seq)
    .all<{ id: string; encrypted_blob: string; updated_at: string; is_deleted: number; server_seq: number }>();

  const entries = (pullResult.results ?? []).map((row) => ({
    id: row.id,
    encrypted_blob: row.encrypted_blob,
    updated_at: row.updated_at,
    is_deleted: Number(row.is_deleted),
    server_seq: Number(row.server_seq),
  }));

  let latestSeq = entries.length > 0 ? entries[entries.length - 1].server_seq : 0;
  if (entries.length === 0) {
    const latestSeqRow = await c.env.DB.prepare(
      "SELECT COALESCE(MAX(server_seq), 0) AS latest_seq FROM sync_entries WHERE user_id = ?",
    )
      .bind(userId)
      .first<{ latest_seq: number | string }>();
    latestSeq = Number(latestSeqRow?.latest_seq ?? 0);
  }

  return c.json({ entries, latest_seq: latestSeq });
});

app.get("/api/status", async (c) => {
  const userId = c.get("userId");

  const row = await c.env.DB.prepare(
    "SELECT COUNT(*) AS total_entries, COALESCE(MAX(server_seq), 0) AS latest_seq, COALESCE(SUM(length(encrypted_blob)), 0) AS storage_bytes FROM sync_entries WHERE user_id = ?",
  )
    .bind(userId)
    .first<{ total_entries: number | string; latest_seq: number | string; storage_bytes: number | string }>();

  return c.json({
    total_entries: Number(row?.total_entries ?? 0),
    latest_seq: Number(row?.latest_seq ?? 0),
    storage_bytes: Number(row?.storage_bytes ?? 0),
  });
});

app.onError((err, c) => {
  console.error("Unhandled worker error", err);
  return jsonError(c, 500, "Internal server error", "INTERNAL_ERROR");
});

app.notFound((c) => {
  return jsonError(c, 404, "Not found", "NOT_FOUND");
});

export default app;
