/**
 * /v2/authorities — RAN namespace tests
 *
 * Uses the same direct-function-import harness as functions/v2/components/register.test.ts.
 * Signing is done via rcan-ts signBody + makeTestKeypair from the shared test helper.
 */

import { describe, it, expect, vi } from "vitest";
import { onRequestPost } from "../../../functions/v2/authorities/register.js";
import { onRequestGet as onGetSingle, onRequestDelete } from "../../../functions/v2/authorities/[ran]/index.js";
import { onRequestGet as onGetList } from "../../../functions/v2/authorities/index.js";
import { signBody } from "rcan-ts";
import { makeTestKeypair } from "../../../functions/v2/_lib/test-helpers.js";

// ── Shared KV mock ────────────────────────────────────────────────────────────

function makeEnv(adminToken?: string) {
  const store: Record<string, string> = {};
  return {
    RRF_KV: {
      get: vi.fn(async (k: string) => store[k] ?? null),
      put: vi.fn(async (k: string, v: string) => { store[k] = v; }),
      list: vi.fn(async (opts: { prefix?: string; cursor?: string; limit?: number }) => {
        const prefix = opts?.prefix ?? "";
        const matching = Object.keys(store)
          .filter((k) => k.startsWith(prefix))
          .map((name) => ({ name }));
        return { keys: matching, list_complete: true };
      }),
      delete: vi.fn(async (k: string) => { delete store[k]; }),
    } as unknown as KVNamespace,
    RRF_ADMIN_TOKEN: adminToken,
    __store: store,
  };
}

function makeReq(method: string, url: string, body?: unknown, headers: Record<string, string> = {}): Request {
  return new Request(url, {
    method,
    headers: { "Content-Type": "application/json", ...headers },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
}

// ── Sign a registration body ─────────────────────────────────────────────────

type TestKp = Awaited<ReturnType<typeof makeTestKeypair>>;

async function buildSignedRegistration(
  meta: { organization: string; display_name: string; purpose: string },
  kp?: TestKp,
) {
  const keypair = kp ?? await makeTestKeypair();
  const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
  const ed25519PubB64 = b64(keypair.ed25519Public);
  // Include signing_pub and signing_alg in the body BEFORE signing so they
  // are part of the canonical message that verifyBody checks.
  const bodyToSign = {
    ...meta,
    signing_pub: ed25519PubB64,
    signing_alg: ["Ed25519", "ML-DSA-65"],
  };
  const signed = await signBody(keypair.mlDsa, bodyToSign as any, {
    ed25519Secret: keypair.ed25519Secret,
    ed25519Public: keypair.ed25519Public,
  });
  return signed;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("/v2/authorities — RAN namespace", () => {
  it("POST /v2/authorities/register creates a new RAN with hybrid keys (201)", async () => {
    const env = makeEnv();
    const body = await buildSignedRegistration({
      organization: "OpenCastor (the company)",
      display_name: "Test aggregator",
      purpose: "compatibility-matrix-aggregate",
    });
    const res = await onRequestPost({
      request: makeReq("POST", "https://x/v2/authorities/register", body),
      env,
    } as any);
    expect(res.status).toBe(201);
    const out = await res.json() as any;
    expect(out.ran).toMatch(/^RAN-\d{12}$/);
    expect(out.status).toBe("active");
    expect(out.registered_at).toBeTruthy();
  });

  it("GET /v2/authorities/<ran> returns the persisted record (200)", async () => {
    const env = makeEnv();
    // Register one first
    const body = await buildSignedRegistration({
      organization: "OpenCastor (the company)",
      display_name: "Aggregator for GET test",
      purpose: "attestation",
    });
    const postRes = await onRequestPost({
      request: makeReq("POST", "https://x/v2/authorities/register", body),
      env,
    } as any);
    expect(postRes.status).toBe(201);
    const { ran } = await postRes.json() as any;

    const getRes = await onGetSingle({
      params: { ran },
      env,
      request: makeReq("GET", `https://x/v2/authorities/${ran}`),
    } as any);
    expect(getRes.status).toBe(200);
    const out = await getRes.json() as any;
    expect(out.ran).toBe(ran);
    expect(out.signing_alg).toEqual(["Ed25519", "ML-DSA-65"]);
    expect(out.pq_signing_pub).toBeTruthy();
    expect(out.signing_pub).toBeTruthy();
    expect(out.status).toBe("active");
  });

  it("POST rejects registration with mismatched signing_pub vs sig.ed25519_pub (400)", async () => {
    const env = makeEnv();
    const body = await buildSignedRegistration({
      organization: "test", display_name: "test", purpose: "other",
    });
    // Tamper signing_pub to a different key
    const kp2 = await makeTestKeypair();
    const tampered = { ...body, signing_pub: btoa(String.fromCharCode(...kp2.ed25519Public)) };
    const res = await onRequestPost({
      request: makeReq("POST", "https://x/v2/authorities/register", tampered),
      env,
    } as any);
    expect(res.status).toBe(400);
    const out = await res.json() as any;
    expect(out.error).toMatch(/ed25519/i);
  });

  it("POST rejects registration without pq_signing_pub (400)", async () => {
    const env = makeEnv();
    const res = await onRequestPost({
      request: makeReq("POST", "https://x/v2/authorities/register", {
        organization: "x",
        display_name: "x",
        purpose: "other",
        signing_alg: ["Ed25519", "ML-DSA-65"],
        pq_kid: "x",
        signing_pub: "x",
        sig: { ml_dsa: "x", ed25519: "x", ed25519_pub: "x" },
        // pq_signing_pub deliberately omitted
      }),
      env,
    } as any);
    expect(res.status).toBe(400);
    const out = await res.json() as any;
    expect(out.error).toMatch(/pq_signing_pub.*required/i);
  });

  it("POST rejects duplicate pq_kid within RAN namespace (409)", async () => {
    const env = makeEnv();
    // Both registrations share the same ML-DSA keypair → same pq_kid (computed hash).
    const sharedKp = await makeTestKeypair();
    const b1 = await buildSignedRegistration(
      { organization: "x", display_name: "x", purpose: "other" },
      sharedKp,
    );
    const r1 = await onRequestPost({
      request: makeReq("POST", "https://x/v2/authorities/register", b1),
      env,
    } as any);
    expect(r1.status).toBe(201);

    // Second registration reuses same keypair → same pq_kid → duplicate
    const b2 = await buildSignedRegistration(
      { organization: "y", display_name: "y", purpose: "other" },
      sharedKp,
    );
    const r2 = await onRequestPost({
      request: makeReq("POST", "https://x/v2/authorities/register", b2),
      env,
    } as any);
    expect(r2.status).toBe(409);
    const out = await r2.json() as any;
    expect(out.error).toMatch(/pq_kid.*duplicate/i);
  });

  it("GET /v2/authorities lists registered authorities (200)", async () => {
    const env = makeEnv();
    // Register one
    const body = await buildSignedRegistration({
      organization: "ListOrg", display_name: "List test authority", purpose: "policy",
    });
    const postRes = await onRequestPost({
      request: makeReq("POST", "https://x/v2/authorities/register", body),
      env,
    } as any);
    expect(postRes.status).toBe(201);
    const { ran } = await postRes.json() as any;

    const listRes = await onGetList({
      env,
      request: makeReq("GET", "https://x/v2/authorities"),
    } as any);
    expect(listRes.status).toBe(200);
    const out = await listRes.json() as any;
    expect(Array.isArray(out.entries)).toBe(true);
    expect(out.entries.some((e: any) => e.ran === ran)).toBe(true);
  });

  it("DELETE /v2/authorities/<ran> requires admin token (401 without, 200 soft-delete with)", async () => {
    const adminToken = "test-admin-token-xyz";
    const env = makeEnv(adminToken);
    // Register one
    const body = await buildSignedRegistration({
      organization: "DeleteOrg", display_name: "Delete test", purpose: "other",
    });
    const postRes = await onRequestPost({
      request: makeReq("POST", "https://x/v2/authorities/register", body),
      env,
    } as any);
    expect(postRes.status).toBe(201);
    const { ran } = await postRes.json() as any;

    // Without token → 401
    const noAuthRes = await onRequestDelete({
      params: { ran },
      env,
      request: makeReq("DELETE", `https://x/v2/authorities/${ran}`),
    } as any);
    expect(noAuthRes.status).toBe(401);

    // With token → 200, soft-delete (status = "revoked", record preserved)
    const authRes = await onRequestDelete({
      params: { ran },
      env,
      request: makeReq("DELETE", `https://x/v2/authorities/${ran}`, undefined, {
        Authorization: `Bearer ${adminToken}`,
      }),
    } as any);
    expect(authRes.status).toBe(200);
    const out = await authRes.json() as any;
    expect(out.status).toBe("revoked");
    expect(out.record).toBeDefined();
    expect(out.record.status).toBe("revoked");
    expect(out.record.revoked_at).toBeTruthy();

    // GET on the same RAN returns 200 with status = "revoked" (proves record persists)
    const getAfterRes = await onGetSingle({
      params: { ran },
      env,
      request: makeReq("GET", `https://x/v2/authorities/${ran}`),
    } as any);
    expect(getAfterRes.status).toBe(200);
    const getAfterOut = await getAfterRes.json() as any;
    expect(getAfterOut.status).toBe("revoked");

    // DELETE on an already-revoked RAN → 409
    const doubleDeleteRes = await onRequestDelete({
      params: { ran },
      env,
      request: makeReq("DELETE", `https://x/v2/authorities/${ran}`, undefined, {
        Authorization: `Bearer ${adminToken}`,
      }),
    } as any);
    expect(doubleDeleteRes.status).toBe(409);
    const ddOut = await doubleDeleteRes.json() as any;
    expect(ddOut.error).toMatch(/already revoked/i);
  });

  it("POST rejects registration with cryptographically invalid signature", async () => {
    // Build a valid body, then corrupt the sig.ml_dsa bytes so verifyBody detects
    // that the signature doesn't verify against pq_signing_pub.
    const env = makeEnv();
    const body = await buildSignedRegistration({
      organization: "test", display_name: "test", purpose: "other",
    }) as Record<string, any>;

    // Tamper: corrupt a byte in sig.ml_dsa (the ML-DSA signature is what verifyBody checks).
    const sigBytes = Buffer.from(body.sig.ml_dsa, "base64");
    sigBytes[0] ^= 0xff;  // flip bits in the first byte
    body.sig = { ...body.sig, ml_dsa: sigBytes.toString("base64") };

    const r = await onRequestPost({
      request: makeReq("POST", "https://x/v2/authorities/register", body),
      env,
    } as any);
    expect(r.status).toBe(400);
    expect((await r.json() as any).error).toMatch(/sig|invalid|verif/i);
  });
});
