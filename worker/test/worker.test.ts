import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import worker, { __test__ } from "../src/index";

// The bindings the worker expects. `env` is provided by the test pool and
// includes the D1/KV/secret bindings declared in vitest.config.ts.
type TestEnv = {
  DB: D1Database;
  KV: KVNamespace;
  JWT_SECRET: string;
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
};

const testEnv = env as unknown as TestEnv;
const JWT_SECRET = testEnv.JWT_SECRET;

/** Recreate the schema before each test so tests are independent. */
async function resetSchema(): Promise<void> {
  await testEnv.DB.exec("DROP TABLE IF EXISTS sync_entries");
  await testEnv.DB.exec("DROP TABLE IF EXISTS users");
  await testEnv.DB.exec(
    "CREATE TABLE users (id TEXT PRIMARY KEY, google_id TEXT UNIQUE, email TEXT, name TEXT, avatar_url TEXT, token_version INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT (datetime('now')))",
  );
  await testEnv.DB.exec(
    "CREATE TABLE sync_entries (id TEXT NOT NULL, user_id TEXT NOT NULL, encrypted_blob TEXT NOT NULL, updated_at TEXT NOT NULL, is_deleted INTEGER NOT NULL DEFAULT 0, server_seq INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (id, user_id))",
  );
}

/** Insert a user row and return its id + current token_version. */
async function seedUser(
  id: string,
  tokenVersion = 0,
): Promise<{ id: string; tokenVersion: number }> {
  await testEnv.DB.prepare(
    "INSERT INTO users (id, google_id, email, token_version) VALUES (?, ?, ?, ?)",
  )
    .bind(id, `google-${id}`, `${id}@example.com`, tokenVersion)
    .run();
  return { id, tokenVersion };
}

/** Dispatch a request through the worker with a fresh execution context. */
async function call(request: Request): Promise<Response> {
  const ctx = createExecutionContext();
  const response = await worker.fetch(request, env as never, ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

function apiRequest(
  path: string,
  method: string,
  token: string | null,
  body?: unknown,
): Request {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  return new Request(`https://keyflow.divinations.top${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

beforeEach(async () => {
  await resetSchema();
});

// ---------------------------------------------------------------------------
// JWT sign / verify
// ---------------------------------------------------------------------------
describe("JWT sign/verify", () => {
  it("round-trips a valid token", async () => {
    const token = await __test__.issueToken("user-1", 0, JWT_SECRET);
    const payload = await __test__.verifyJWT(token, JWT_SECRET);
    expect(payload).not.toBeNull();
    expect(payload?.sub).toBe("user-1");
    expect(payload?.tv).toBe(0);
  });

  it("rejects a token signed with a different secret", async () => {
    const token = await __test__.issueToken("user-1", 0, "the-real-secret");
    const payload = await __test__.verifyJWT(token, "an-attacker-secret");
    expect(payload).toBeNull();
  });

  it("rejects a tampered payload", async () => {
    const token = await __test__.signJWT(
      { sub: "user-1", iat: 1000, exp: 9999999999, tv: 0 },
      JWT_SECRET,
    );
    const [header, , signature] = token.split(".");
    // Forge a payload claiming to be a different user, keep the old signature.
    const forgedPayload = __test__.toBase64Url(
      new TextEncoder().encode(
        JSON.stringify({ sub: "user-2", iat: 1000, exp: 9999999999, tv: 0 }),
      ),
    );
    const forged = `${header}.${forgedPayload}.${signature}`;
    expect(await __test__.verifyJWT(forged, JWT_SECRET)).toBeNull();
  });

  it("rejects a tampered signature", async () => {
    const token = await __test__.issueToken("user-1", 0, JWT_SECRET);
    const parts = token.split(".");
    const forged = `${parts[0]}.${parts[1]}.${parts[2]}AAAA`;
    expect(await __test__.verifyJWT(forged, JWT_SECRET)).toBeNull();
  });

  it("rejects an expired token", async () => {
    const expired = await __test__.signJWT(
      { sub: "user-1", iat: 1000, exp: 1001, tv: 0 },
      JWT_SECRET,
    );
    expect(await __test__.verifyJWT(expired, JWT_SECRET)).toBeNull();
  });

  it("rejects a malformed token", async () => {
    expect(await __test__.verifyJWT("not.a.jwt", JWT_SECRET)).toBeNull();
    expect(await __test__.verifyJWT("only-one-part", JWT_SECRET)).toBeNull();
  });

  it("issues tokens with the shortened (7 day) lifetime", () => {
    expect(__test__.TOKEN_LIFETIME_SECONDS).toBe(7 * 24 * 60 * 60);
  });
});

// ---------------------------------------------------------------------------
// token_version revocation
// ---------------------------------------------------------------------------
describe("token_version revocation", () => {
  it("accepts a token whose tv matches the stored token_version", async () => {
    await seedUser("user-rev-1", 0);
    const token = await __test__.issueToken("user-rev-1", 0, JWT_SECRET);
    const res = await call(apiRequest("/api/status", "GET", token));
    expect(res.status).toBe(200);
  });

  it("rejects a token whose tv is stale after a revoke", async () => {
    await seedUser("user-rev-2", 0);
    const token = await __test__.issueToken("user-rev-2", 0, JWT_SECRET);

    // First request works.
    expect((await call(apiRequest("/api/status", "GET", token))).status).toBe(200);

    // Revoke bumps token_version to 1.
    const revokeRes = await call(apiRequest("/api/revoke", "POST", token));
    expect(revokeRes.status).toBe(200);

    // The same token now fails the revocation check.
    const after = await call(apiRequest("/api/status", "GET", token));
    expect(after.status).toBe(401);
    expect(((await after.json()) as { code: string }).code).toBe("TOKEN_REVOKED");
  });

  it("/api/logout also bumps token_version", async () => {
    await seedUser("user-rev-3", 0);
    const token = await __test__.issueToken("user-rev-3", 0, JWT_SECRET);
    expect((await call(apiRequest("/api/logout", "POST", token))).status).toBe(200);

    const row = await testEnv.DB.prepare("SELECT token_version FROM users WHERE id = ?")
      .bind("user-rev-3")
      .first<{ token_version: number }>();
    expect(Number(row?.token_version)).toBe(1);

    // A fresh token with the new tv works again.
    const fresh = await __test__.issueToken("user-rev-3", 1, JWT_SECRET);
    expect((await call(apiRequest("/api/status", "GET", fresh))).status).toBe(200);
  });

  it("rejects a token for an unknown user", async () => {
    const token = await __test__.issueToken("ghost-user", 0, JWT_SECRET);
    const res = await call(apiRequest("/api/status", "GET", token));
    expect(res.status).toBe(401);
  });

  it("rejects requests with no bearer token", async () => {
    const res = await call(apiRequest("/api/status", "GET", null));
    expect(res.status).toBe(401);
  });
});

// ---------------------------------------------------------------------------
// IDOR isolation: user A must never see/modify user B's data.
// ---------------------------------------------------------------------------
describe("IDOR isolation between users", () => {
  it("push writes are scoped to the calling user", async () => {
    await seedUser("alice", 0);
    await seedUser("bob", 0);
    const aliceToken = await __test__.issueToken("alice", 0, JWT_SECRET);
    const bobToken = await __test__.issueToken("bob", 0, JWT_SECRET);

    // Alice pushes an entry.
    const alicePush = await call(
      apiRequest("/api/push", "POST", aliceToken, {
        entries: [
          {
            id: "shared-id",
            encrypted_blob: "alice-secret",
            updated_at: "2026-01-01T00:00:00Z",
            is_deleted: 0,
          },
        ],
      }),
    );
    expect(alicePush.status).toBe(200);

    // Bob pulls: must see nothing of Alice's.
    const bobPull = await call(apiRequest("/api/pull", "POST", bobToken, { since_seq: 0 }));
    expect(bobPull.status).toBe(200);
    const bobEntries = ((await bobPull.json()) as { entries: unknown[] }).entries;
    expect(bobEntries).toHaveLength(0);

    // Alice pulls: sees her own entry.
    const alicePull = await call(
      apiRequest("/api/pull", "POST", aliceToken, { since_seq: 0 }),
    );
    const aliceEntries = ((await alicePull.json()) as {
      entries: { id: string; encrypted_blob: string }[];
    }).entries;
    expect(aliceEntries).toHaveLength(1);
    expect(aliceEntries[0].encrypted_blob).toBe("alice-secret");
  });

  it("a push with the same entry id under another user does not overwrite", async () => {
    await seedUser("alice", 0);
    await seedUser("bob", 0);
    const aliceToken = await __test__.issueToken("alice", 0, JWT_SECRET);
    const bobToken = await __test__.issueToken("bob", 0, JWT_SECRET);

    await call(
      apiRequest("/api/push", "POST", aliceToken, {
        entries: [
          {
            id: "collide",
            encrypted_blob: "alice-data",
            updated_at: "2026-01-01T00:00:00Z",
            is_deleted: 0,
          },
        ],
      }),
    );
    // Bob pushes an entry with the SAME id but newer timestamp.
    await call(
      apiRequest("/api/push", "POST", bobToken, {
        entries: [
          {
            id: "collide",
            encrypted_blob: "bob-data",
            updated_at: "2030-01-01T00:00:00Z",
            is_deleted: 0,
          },
        ],
      }),
    );

    // Alice's row must be untouched.
    const aliceRow = await testEnv.DB.prepare(
      "SELECT encrypted_blob FROM sync_entries WHERE user_id = ? AND id = ?",
    )
      .bind("alice", "collide")
      .first<{ encrypted_blob: string }>();
    expect(aliceRow?.encrypted_blob).toBe("alice-data");

    const bobRow = await testEnv.DB.prepare(
      "SELECT encrypted_blob FROM sync_entries WHERE user_id = ? AND id = ?",
    )
      .bind("bob", "collide")
      .first<{ encrypted_blob: string }>();
    expect(bobRow?.encrypted_blob).toBe("bob-data");
  });

  it("/api/status only counts the calling user's rows", async () => {
    await seedUser("alice", 0);
    await seedUser("bob", 0);
    const aliceToken = await __test__.issueToken("alice", 0, JWT_SECRET);
    const bobToken = await __test__.issueToken("bob", 0, JWT_SECRET);

    await call(
      apiRequest("/api/push", "POST", aliceToken, {
        entries: [
          {
            id: "a1",
            encrypted_blob: "x",
            updated_at: "2026-01-01T00:00:00Z",
            is_deleted: 0,
          },
          {
            id: "a2",
            encrypted_blob: "y",
            updated_at: "2026-01-01T00:00:00Z",
            is_deleted: 0,
          },
        ],
      }),
    );

    const bobStatus = await call(apiRequest("/api/status", "GET", bobToken));
    const bobBody = (await bobStatus.json()) as { total_entries: number };
    expect(bobBody.total_entries).toBe(0);

    const aliceStatus = await call(apiRequest("/api/status", "GET", aliceToken));
    const aliceBody = (await aliceStatus.json()) as { total_entries: number };
    expect(aliceBody.total_entries).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// Device flow PKCE
// ---------------------------------------------------------------------------
describe("device flow PKCE", () => {
  /** Approve a device session directly in KV, as the OAuth callback would. */
  async function approveSession(
    deviceCode: string,
    userId: string,
    codeChallenge: string | undefined,
    userCode: string,
  ): Promise<void> {
    await testEnv.KV.put(
      `device:${deviceCode}`,
      JSON.stringify({
        user_code: userCode,
        user_id: userId,
        status: "approved",
        created_at: new Date().toISOString(),
        approved_at: new Date().toISOString(),
        code_challenge: codeChallenge,
      }),
      { expirationTtl: 600 },
    );
  }

  it("start stores the code_challenge and returns a uuid device_code", async () => {
    const verifier = "verifier-" + crypto.randomUUID();
    const challenge = await __test__.sha256Base64Url(verifier);
    const res = await call(
      apiRequest("/api/device/start", "POST", null, { code_challenge: challenge }),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { device_code: string; user_code: string };
    expect(body.device_code).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
    expect(body.user_code).toMatch(/^[A-Z2-9]{8}$/);

    const stored = await testEnv.KV.get(`device:${body.device_code}`);
    expect(stored).not.toBeNull();
    expect(JSON.parse(stored as string).code_challenge).toBe(challenge);
  });

  it("poll succeeds when the correct verifier is supplied", async () => {
    await seedUser("pkce-user", 0);
    const verifier = "correct-verifier-secret";
    const challenge = await __test__.sha256Base64Url(verifier);
    const deviceCode = crypto.randomUUID();
    await approveSession(deviceCode, "pkce-user", challenge, "ABCD2345");

    const res = await call(
      apiRequest("/api/device/poll", "POST", null, {
        device_code: deviceCode,
        code_verifier: verifier,
      }),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string; token: string };
    expect(body.status).toBe("approved");

    // The issued token must be valid.
    const payload = await __test__.verifyJWT(body.token, JWT_SECRET);
    expect(payload?.sub).toBe("pkce-user");
  });

  it("poll rejects a mismatched verifier", async () => {
    await seedUser("pkce-user-2", 0);
    const challenge = await __test__.sha256Base64Url("the-real-verifier");
    const deviceCode = crypto.randomUUID();
    await approveSession(deviceCode, "pkce-user-2", challenge, "WXYZ2345");

    const res = await call(
      apiRequest("/api/device/poll", "POST", null, {
        device_code: deviceCode,
        code_verifier: "a-wrong-verifier",
      }),
    );
    expect(res.status).toBe(400);
    expect(((await res.json()) as { code: string }).code).toBe("PKCE_VERIFICATION_FAILED");

    // The session must NOT have been consumed by a failed poll.
    expect(await testEnv.KV.get(`device:${deviceCode}`)).not.toBeNull();
  });

  it("poll rejects a missing verifier when a challenge was set", async () => {
    await seedUser("pkce-user-3", 0);
    const challenge = await __test__.sha256Base64Url("some-verifier");
    const deviceCode = crypto.randomUUID();
    await approveSession(deviceCode, "pkce-user-3", challenge, "MNOP2345");

    const res = await call(
      apiRequest("/api/device/poll", "POST", null, { device_code: deviceCode }),
    );
    expect(res.status).toBe(400);
    expect(((await res.json()) as { code: string }).code).toBe("PKCE_VERIFICATION_FAILED");
  });

  it("poll consumes the session one-time on success", async () => {
    await seedUser("pkce-user-4", 0);
    const verifier = "one-time-verifier";
    const challenge = await __test__.sha256Base64Url(verifier);
    const deviceCode = crypto.randomUUID();
    await approveSession(deviceCode, "pkce-user-4", challenge, "QRST2345");

    const first = await call(
      apiRequest("/api/device/poll", "POST", null, {
        device_code: deviceCode,
        code_verifier: verifier,
      }),
    );
    expect(first.status).toBe(200);

    // Second poll: the session is gone.
    const second = await call(
      apiRequest("/api/device/poll", "POST", null, {
        device_code: deviceCode,
        code_verifier: verifier,
      }),
    );
    expect(second.status).toBe(404);
  });

  it("poll rejects a malformed (non-uuid) device_code", async () => {
    const res = await call(
      apiRequest("/api/device/poll", "POST", null, {
        device_code: "not-a-uuid",
        code_verifier: "x",
      }),
    );
    expect(res.status).toBe(400);
    expect(((await res.json()) as { code: string }).code).toBe("BAD_REQUEST");
  });

  it("a pending session returns 202", async () => {
    const deviceCode = crypto.randomUUID();
    await testEnv.KV.put(
      `device:${deviceCode}`,
      JSON.stringify({ user_code: "PEND2345", status: "pending" }),
      { expirationTtl: 600 },
    );
    const res = await call(
      apiRequest("/api/device/poll", "POST", null, { device_code: deviceCode }),
    );
    expect(res.status).toBe(202);
  });
});

// ---------------------------------------------------------------------------
// Push limits
// ---------------------------------------------------------------------------
describe("push size limits", () => {
  it("rejects a push with too many entries", async () => {
    await seedUser("limit-user", 0);
    const token = await __test__.issueToken("limit-user", 0, JWT_SECRET);
    const entries = Array.from({ length: 1001 }, (_, i) => ({
      id: `e${i}`,
      encrypted_blob: "x",
      updated_at: "2026-01-01T00:00:00Z",
      is_deleted: 0,
    }));
    const res = await call(apiRequest("/api/push", "POST", token, { entries }));
    expect(res.status).toBe(413);
    expect(((await res.json()) as { code: string }).code).toBe("TOO_MANY_ENTRIES");
  });

  it("rejects an oversized encrypted_blob", async () => {
    await seedUser("limit-user-2", 0);
    const token = await __test__.issueToken("limit-user-2", 0, JWT_SECRET);
    const bigBlob = "A".repeat(1024 * 1024 + 1);
    const res = await call(
      apiRequest("/api/push", "POST", token, {
        entries: [
          {
            id: "big",
            encrypted_blob: bigBlob,
            updated_at: "2026-01-01T00:00:00Z",
            is_deleted: 0,
          },
        ],
      }),
    );
    expect(res.status).toBe(413);
    expect(((await res.json()) as { code: string }).code).toBe("BLOB_TOO_LARGE");
  });

  it("assigns monotonically increasing server_seq across pushes", async () => {
    await seedUser("seq-user", 0);
    const token = await __test__.issueToken("seq-user", 0, JWT_SECRET);

    const push1 = await call(
      apiRequest("/api/push", "POST", token, {
        entries: [
          { id: "s1", encrypted_blob: "a", updated_at: "2026-01-01T00:00:00Z", is_deleted: 0 },
          { id: "s2", encrypted_blob: "b", updated_at: "2026-01-01T00:00:00Z", is_deleted: 0 },
        ],
      }),
    );
    const body1 = (await push1.json()) as { latest_seq: number };
    expect(body1.latest_seq).toBe(2);

    const push2 = await call(
      apiRequest("/api/push", "POST", token, {
        entries: [
          { id: "s3", encrypted_blob: "c", updated_at: "2026-01-01T00:00:00Z", is_deleted: 0 },
        ],
      }),
    );
    const body2 = (await push2.json()) as { latest_seq: number };
    expect(body2.latest_seq).toBe(3);

    // server_seq values must be unique.
    const rows = await testEnv.DB.prepare(
      "SELECT server_seq FROM sync_entries WHERE user_id = ? ORDER BY server_seq",
    )
      .bind("seq-user")
      .all<{ server_seq: number }>();
    const seqs = (rows.results ?? []).map((r) => Number(r.server_seq));
    expect(seqs).toEqual([1, 2, 3]);
    expect(new Set(seqs).size).toBe(seqs.length);
  });

  it("an updated entry advances server_seq so pull re-delivers it", async () => {
    await seedUser("upsert-user", 0);
    const token = await __test__.issueToken("upsert-user", 0, JWT_SECRET);

    await call(
      apiRequest("/api/push", "POST", token, {
        entries: [
          { id: "u1", encrypted_blob: "v1", updated_at: "2026-01-01T00:00:00Z", is_deleted: 0 },
          { id: "u2", encrypted_blob: "w1", updated_at: "2026-01-01T00:00:00Z", is_deleted: 0 },
        ],
      }),
    );
    // u1 has seq 1, u2 has seq 2. Now update u1 with a newer timestamp.
    const push2 = await call(
      apiRequest("/api/push", "POST", token, {
        entries: [
          { id: "u1", encrypted_blob: "v2", updated_at: "2030-01-01T00:00:00Z", is_deleted: 0 },
        ],
      }),
    );
    const body2 = (await push2.json()) as { latest_seq: number };
    // u1's new seq must exceed u2's seq (2).
    expect(body2.latest_seq).toBe(3);

    // A pull since_seq=2 must re-deliver the updated u1.
    const pull = await call(apiRequest("/api/pull", "POST", token, { since_seq: 2 }));
    const entries = ((await pull.json()) as {
      entries: { id: string; encrypted_blob: string }[];
    }).entries;
    expect(entries).toHaveLength(1);
    expect(entries[0].id).toBe("u1");
    expect(entries[0].encrypted_blob).toBe("v2");
  });

  it("rejects a push that would exceed the per-user storage quota", async () => {
    await seedUser("quota-user", 0);
    const token = await __test__.issueToken("quota-user", 0, JWT_SECRET);
    // 50 MiB quota; a single ~1 MiB blob is fine, 60 of them is not.
    const oneMib = "B".repeat(1024 * 1024 - 16);
    const entries = Array.from({ length: 60 }, (_, i) => ({
      id: `q${i}`,
      encrypted_blob: oneMib,
      updated_at: "2026-01-01T00:00:00Z",
      is_deleted: 0,
    }));
    const res = await call(apiRequest("/api/push", "POST", token, { entries }));
    expect(res.status).toBe(413);
    expect(((await res.json()) as { code: string }).code).toBe("QUOTA_EXCEEDED");
  });
});
