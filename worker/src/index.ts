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
