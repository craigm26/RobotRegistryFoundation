import { describe, it, expect, vi } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { onRequest } from "./[kid].js";

function b64(u8: Uint8Array): string {
  return Buffer.from(u8).toString("base64");
}

function makeEnv(initial: Record<string, string> = {}) {
  const store: Record<string, string> = { ...initial };
  return {
    env: {
      RRF_KV: {
        get: vi.fn(async (k: string) => store[k] ?? null),
        put: vi.fn(async (k: string, v: string) => { store[k] = v; }),
        list: vi.fn(async ({ prefix }: { prefix: string }) => ({
          keys: Object.keys(store).filter(k => k.startsWith(prefix)).map(name => ({ name })),
          list_complete: true,
        })),
        delete: vi.fn(),
      } as unknown as KVNamespace,
    },
    store,
  };
}

function makeContext(env: unknown, params: Record<string, string>, method = "GET") {
  return {
    request: new Request(`https://example.test/v2/keys/${params.kid}`, { method }),
    env,
    params,
    waitUntil: () => {},
    next: async () => new Response(),
    data: {},
    functionPath: "/v2/keys/[kid]",
  } as unknown as Parameters<typeof onRequest>[0];
}

function setupValidAuthority(store: Record<string, string>, kid = "bob-operator-2026") {
  const ed25519Priv = crypto.getRandomValues(new Uint8Array(32));
  const ed25519Pub = ed25519.getPublicKey(ed25519Priv);
  const pqPub = crypto.getRandomValues(new Uint8Array(1952));
  const pqKid = "deadbeef";

  const ran = "RAN-000000000019";
  store[`kid:${kid}:2026-05-04T15:00:00.000Z`] = JSON.stringify({
    ran,
    valid_from: "2026-05-04T00:00:00.000Z",
    registered_at: "2026-05-04T15:00:00.000Z",
    registered_by: "RAN-000000000018",
  });
  store[`authority:${ran}`] = JSON.stringify({
    ran,
    organization: "OpenCastor",
    display_name: "bob-operator-2026 — Phase 5 INVOKE signer for Bob",
    purpose: "operator-envelope",
    signing_pub: b64(ed25519Pub),
    pq_signing_pub: b64(pqPub),
    pq_kid: pqKid,
    signing_alg: ["Ed25519", "ML-DSA-65"],
    registered_at: "2026-05-04T15:00:00.000Z",
    status: "active",
  });
  return { ed25519Pub, pqPub, pqKid, ran };
}

describe("GET /v2/keys/<kid>", () => {
  it("returns 200 with hybrid response shape on a valid active kid", async () => {
    const { env, store } = makeEnv();
    const { ed25519Pub, pqPub, pqKid, ran } = setupValidAuthority(store);
    const res = await onRequest(makeContext(env, { kid: "bob-operator-2026" }));
    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;
    expect(body.kid).toBe("bob-operator-2026");
    expect(body.alg).toBe("Ed25519");
    expect(body.public_key_pem).toMatch(/^-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+-----END PUBLIC KEY-----\n$/);
    expect(body.pq_alg).toBe("ML-DSA-65");
    expect(body.pq_public_key_b64).toBe(b64(pqPub));
    expect(body.pq_kid).toBe(pqKid);
    expect(body.ran).toBe(ran);
    expect(body.status).toBe("active");
    expect(res.headers.get("Cache-Control")).toBe("public, max-age=60");
  });

  it("returns 404 when the kid has no records at all", async () => {
    const { env } = makeEnv();
    const res = await onRequest(makeContext(env, { kid: "nobody-2099" }));
    expect(res.status).toBe(404);
    const body = await res.json() as Record<string, unknown>;
    expect(body.error).toBe("kid not registered");
    expect(body.kid).toBe("nobody-2099");
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("returns 404 when kid records exist but none cover NOW", async () => {
    const { env, store } = makeEnv();
    setupValidAuthority(store);
    store["kid:bob-operator-2026:2026-05-04T15:00:00.000Z"] = JSON.stringify({
      ran: "RAN-000000000019",
      valid_from: "2020-01-01T00:00:00.000Z",
      valid_until: "2020-12-31T23:59:59.999Z",
      registered_at: "2020-01-01T00:00:00.000Z",
      registered_by: "RAN-000000000018",
    });
    const res = await onRequest(makeContext(env, { kid: "bob-operator-2026" }));
    expect(res.status).toBe(404);
    const body = await res.json() as Record<string, unknown>;
    expect(body.error).toBe("kid has no valid mapping at this time");
  });

  it("returns 410 when the authority has status: revoked", async () => {
    const { env, store } = makeEnv();
    const { ran } = setupValidAuthority(store);
    const auth = JSON.parse(store[`authority:${ran}`]);
    auth.status = "revoked";
    auth.revoked_at = "2026-05-04T16:00:00.000Z";
    auth.revocation_reason = "operator key rotation";
    store[`authority:${ran}`] = JSON.stringify(auth);
    const res = await onRequest(makeContext(env, { kid: "bob-operator-2026" }));
    expect(res.status).toBe(410);
    const body = await res.json() as Record<string, unknown>;
    expect(body.error).toBe("kid revoked");
    expect(body.revoked_at).toBe("2026-05-04T16:00:00.000Z");
    expect(body.revocation_reason).toBe("operator key rotation");
  });

  it("returns 502 when signing_pub is not 32 bytes", async () => {
    const { env, store } = makeEnv();
    const { ran } = setupValidAuthority(store);
    const auth = JSON.parse(store[`authority:${ran}`]);
    auth.signing_pub = b64(new Uint8Array(31));
    store[`authority:${ran}`] = JSON.stringify(auth);
    const res = await onRequest(makeContext(env, { kid: "bob-operator-2026" }));
    expect(res.status).toBe(502);
    const body = await res.json() as Record<string, unknown>;
    expect(body.error).toBe("registry data integrity error");
  });

  it("returns 502 when pq_signing_pub is not 1952 bytes", async () => {
    const { env, store } = makeEnv();
    const { ran } = setupValidAuthority(store);
    const auth = JSON.parse(store[`authority:${ran}`]);
    auth.pq_signing_pub = b64(new Uint8Array(100));
    store[`authority:${ran}`] = JSON.stringify(auth);
    const res = await onRequest(makeContext(env, { kid: "bob-operator-2026" }));
    expect(res.status).toBe(502);
  });

  it("returns 502 when authority record is unparseable JSON", async () => {
    const { env, store } = makeEnv();
    const { ran } = setupValidAuthority(store);
    store[`authority:${ran}`] = "{ not json";
    const res = await onRequest(makeContext(env, { kid: "bob-operator-2026" }));
    expect(res.status).toBe(502);
  });

  it("returns 405 on non-GET methods", async () => {
    const { env } = makeEnv();
    const res = await onRequest(makeContext(env, { kid: "bob-operator-2026" }, "POST"));
    expect(res.status).toBe(405);
  });

  it("most-recent registered_at wins when multiple kid mappings cover NOW", async () => {
    const { env, store } = makeEnv();
    setupValidAuthority(store);  // creates kid:bob-operator-2026:2026-05-04T15:00:00.000Z → RAN-019

    const ed25519Priv2 = crypto.getRandomValues(new Uint8Array(32));
    const ed25519Pub2 = ed25519.getPublicKey(ed25519Priv2);
    const pqPub2 = crypto.getRandomValues(new Uint8Array(1952));
    store["authority:RAN-000000000020"] = JSON.stringify({
      ran: "RAN-000000000020",
      organization: "OpenCastor",
      display_name: "bob-operator-2026 (rotated)",
      purpose: "operator-envelope",
      signing_pub: b64(ed25519Pub2),
      pq_signing_pub: b64(pqPub2),
      pq_kid: "cafef00d",
      signing_alg: ["Ed25519", "ML-DSA-65"],
      registered_at: "2026-05-04T16:00:00.000Z",
      status: "active",
    });
    store["kid:bob-operator-2026:2026-05-04T16:00:00.000Z"] = JSON.stringify({
      ran: "RAN-000000000020",
      valid_from: "2026-05-04T15:30:00.000Z",
      registered_at: "2026-05-04T16:00:00.000Z",
      registered_by: "RAN-000000000018",
    });

    const res = await onRequest(makeContext(env, { kid: "bob-operator-2026" }));
    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;
    expect(body.ran).toBe("RAN-000000000020");
    expect(body.pq_kid).toBe("cafef00d");
  });
});
