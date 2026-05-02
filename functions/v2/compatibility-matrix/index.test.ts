/**
 * Tests for /v2/compatibility-matrix (Plan 1 Task 16, REVISION 2).
 *
 * Envelope shape conforms to rcan-spec /schemas/version-tuple-envelope.json.
 * Signature verification is exercised via a module-level mutable seam
 * (__setVerifyEnvelopeForTests) — vi.doMock cannot swap an export that
 * onRequestPost has already lexically captured.
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import {
  onRequestGet,
  onRequestPost,
  __setVerifyEnvelopeForTests,
  __resetVerifyEnvelopeForTests,
} from "./index";
import type { VersionTupleEnvelope, AuthorityRecord } from "../_lib/types";

const AGGREGATOR_RAN = "RAN-000000000001";
const AGGREGATOR_PQ_KID = "8e2d0b5f";    // 8-hex; matches test authority record
const AGGREGATOR_KID = "ede25091";       // Ed25519 kid; same shape as real

function makeKV(initial: Record<string, string> = {}) {
  const store = new Map(Object.entries(initial));
  return {
    get: vi.fn(async (k: string) => store.get(k) ?? null),
    put: vi.fn(async (k: string, v: string, _opts?: any) => { store.set(k, v); }),
    list: vi.fn(async () => ({ keys: Array.from(store.keys()).map(name => ({ name })) })),
    _store: store,
  };
}

function makeAuthority(overrides: Partial<AuthorityRecord> = {}): AuthorityRecord {
  return {
    ran: AGGREGATOR_RAN as `RAN-${string}`,
    organization: "OpenCastor (the company)",
    display_name: "OpenCastor compatibility-matrix aggregator",
    purpose: "compatibility-matrix-aggregate",
    signing_pub: "AAAA",  // base64; real values come from RAN registration
    pq_signing_pub: "BBBB",
    pq_kid: AGGREGATOR_PQ_KID,
    signing_alg: ["Ed25519", "ML-DSA-65"],
    registered_at: "2026-05-02T00:00:00Z",
    status: "active",
    ...overrides,
  } as AuthorityRecord;
}

function makeEnvelope(overrides: Partial<VersionTupleEnvelope> = {}): VersionTupleEnvelope {
  // Inner payload: minimal valid matrix shape.
  const inner = {
    matrix_version: "1.0",
    matrix_signed_at: "2026-05-04T14:21:42Z",
    projects: {},
    drift: [],
    fetch_errors: [],
    findings: [],
  };
  const payload = btoa(JSON.stringify(inner));  // base64, schema-conformant
  return {
    ran: AGGREGATOR_RAN,
    alg: ["ML-DSA-65", "Ed25519"],
    pq_kid: AGGREGATOR_PQ_KID,
    kid: AGGREGATOR_KID,
    payload,
    signature_mldsa65: "AAAA",
    signature_ed25519: "BBBB",
    signed_at: "2026-05-04T14:21:42Z",
    ...overrides,
  };
}

afterEach(() => {
  __resetVerifyEnvelopeForTests();
});

describe("GET /v2/compatibility-matrix", () => {
  it("returns 503 when no matrix has been pushed yet", async () => {
    const env = { RRF_KV: makeKV() } as any;
    const r = await onRequestGet({ env, request: new Request("https://x/") } as any);
    expect(r.status).toBe(503);
    const body = await r.json() as any;
    expect(body.error.toLowerCase()).toContain("no matrix");
  });

  it("returns the latest stored envelope as-is", async () => {
    const stored = makeEnvelope({ ran: AGGREGATOR_RAN });
    const env = { RRF_KV: makeKV({
      "compatibility-matrix:latest": JSON.stringify(stored),
    }) } as any;
    const r = await onRequestGet({ env, request: new Request("https://x/") } as any);
    expect(r.status).toBe(200);
    const body = await r.json() as any;
    expect(body.ran).toBe(AGGREGATOR_RAN);
    expect(body.alg).toEqual(["ML-DSA-65", "Ed25519"]);
    expect(body.signature_mldsa65).toBeDefined();
  });
});

describe("POST /v2/compatibility-matrix", () => {
  it("rejects 400 when body is not valid JSON", async () => {
    const env = { RRF_KV: makeKV() } as any;
    const r = await onRequestPost({ env, request: new Request("https://x/", { method: "POST", body: "not-json" }) } as any);
    expect(r.status).toBe(400);
  });

  it("rejects 400 when required envelope fields are missing", async () => {
    const env = { RRF_KV: makeKV() } as any;
    // Missing signature_mldsa65 (REQUIRED).
    const bad = { ran: AGGREGATOR_RAN, alg: ["ML-DSA-65"], pq_kid: "deadbeef", payload: "AAAA", signed_at: "2026-05-04T00:00:00Z" };
    const r = await onRequestPost({
      env,
      request: new Request("https://x/", { method: "POST", body: JSON.stringify(bad), headers: { "Content-Type": "application/json" } }),
    } as any);
    expect(r.status).toBe(400);
  });

  it("rejects 400 when signature_mldsa65 is not valid base64 (would crash atob)", async () => {
    // Regression: previously isValidEnvelope only checked typeof === "string",
    // so a malformed base64 made fromB64()/atob() throw DOMException → 500.
    // Now caught at validation before any verifier runs (no crypto mocks needed).
    const env = { RRF_KV: makeKV() } as any;
    const env_ = makeEnvelope({ signature_mldsa65: "!!! not base64 !!!" });
    const r = await onRequestPost({
      env,
      request: new Request("https://x/", { method: "POST", body: JSON.stringify(env_), headers: { "Content-Type": "application/json" } }),
    } as any);
    expect(r.status).toBe(400);
    const body = await r.json() as any;
    expect(body.error.toLowerCase()).toContain("envelope shape invalid");
  });

  it("rejects 400 when signature_ed25519 present but kid missing", async () => {
    // dependentRequired: {signature_ed25519: ["kid"]} — schema-level invariant.
    const env = { RRF_KV: makeKV() } as any;
    const env_ = makeEnvelope();
    delete (env_ as any).kid;
    const r = await onRequestPost({
      env,
      request: new Request("https://x/", { method: "POST", body: JSON.stringify(env_), headers: { "Content-Type": "application/json" } }),
    } as any);
    expect(r.status).toBe(400);  // schema violation
  });

  it("returns 500 when authority KV record is malformed JSON", async () => {
    // Defensive: KV could hold malformed JSON from manual edit or partial write
    // during migration. Endpoint must return 500 with a generic error, not
    // crash the worker with an unhandled SyntaxError.
    const env = { RRF_KV: makeKV({ [`authority:${AGGREGATOR_RAN}`]: "not json{" }) } as any;
    const r = await onRequestPost({
      env,
      request: new Request("https://x/", { method: "POST", body: JSON.stringify(makeEnvelope()), headers: { "Content-Type": "application/json" } }),
    } as any);
    expect(r.status).toBe(500);
    const body = await r.json() as any;
    expect(body.error.toLowerCase()).toContain("authority record corrupted");
  });

  it("rejects 401 when ran does not resolve to a registered authority", async () => {
    const env = { RRF_KV: makeKV() } as any;  // empty KV — RAN not found
    const r = await onRequestPost({
      env,
      request: new Request("https://x/", { method: "POST", body: JSON.stringify(makeEnvelope()), headers: { "Content-Type": "application/json" } }),
    } as any);
    expect(r.status).toBe(401);
  });

  it("rejects 401 when authority purpose != compatibility-matrix-aggregate", async () => {
    const auth = makeAuthority({ purpose: "release-signing" });
    const env = { RRF_KV: makeKV({ [`authority:${AGGREGATOR_RAN}`]: JSON.stringify(auth) }) } as any;
    const r = await onRequestPost({
      env,
      request: new Request("https://x/", { method: "POST", body: JSON.stringify(makeEnvelope()), headers: { "Content-Type": "application/json" } }),
    } as any);
    expect(r.status).toBe(401);
  });

  it("rejects 401 when pq_kid does not match authority.pq_kid", async () => {
    const auth = makeAuthority({ pq_kid: "deadbeef" });
    const env = { RRF_KV: makeKV({ [`authority:${AGGREGATOR_RAN}`]: JSON.stringify(auth) }) } as any;
    const r = await onRequestPost({
      env,
      request: new Request("https://x/", { method: "POST", body: JSON.stringify(makeEnvelope()), headers: { "Content-Type": "application/json" } }),
    } as any);
    expect(r.status).toBe(401);
  });

  it("rejects 401 when authority status is revoked", async () => {
    const auth = makeAuthority({ status: "revoked", revoked_at: "2026-05-03T00:00:00Z" });
    const env = { RRF_KV: makeKV({ [`authority:${AGGREGATOR_RAN}`]: JSON.stringify(auth) }) } as any;
    const r = await onRequestPost({
      env,
      request: new Request("https://x/", { method: "POST", body: JSON.stringify(makeEnvelope()), headers: { "Content-Type": "application/json" } }),
    } as any);
    expect(r.status).toBe(401);
  });

  it("rejects 401 when verifyEnvelope returns false", async () => {
    const auth = makeAuthority();
    const env = { RRF_KV: makeKV({ [`authority:${AGGREGATOR_RAN}`]: JSON.stringify(auth) }) } as any;
    __setVerifyEnvelopeForTests(async () => false);
    const r = await onRequestPost({
      env,
      request: new Request("https://x/", { method: "POST", body: JSON.stringify(makeEnvelope()), headers: { "Content-Type": "application/json" } }),
    } as any);
    expect(r.status).toBe(401);
  });

  it("stores envelope under both `:latest` and `:<YYYY-MM-DD>` on success", async () => {
    const auth = makeAuthority();
    const kv = makeKV({ [`authority:${AGGREGATOR_RAN}`]: JSON.stringify(auth) });
    const env = { RRF_KV: kv } as any;
    const verifyFn = vi.fn().mockResolvedValue(true);
    __setVerifyEnvelopeForTests(verifyFn);
    const env_ = makeEnvelope({ signed_at: "2026-05-04T14:21:42Z" });
    const r = await onRequestPost({
      env,
      request: new Request("https://x/", { method: "POST", body: JSON.stringify(env_), headers: { "Content-Type": "application/json" } }),
    } as any);
    expect(r.status).toBe(201);
    expect(verifyFn).toHaveBeenCalledTimes(1);
    expect(kv._store.has("compatibility-matrix:latest")).toBe(true);
    expect(kv._store.has("compatibility-matrix:2026-05-04")).toBe(true);
    const out = await r.json() as any;
    expect(out.stored).toBe(true);
    expect(out.ran).toBe(AGGREGATOR_RAN);
    expect(out.pq_kid).toBe(AGGREGATOR_PQ_KID);
    expect(out.date).toBe("2026-05-04");
  });

  it("accepts envelope with only signature_mldsa65 (Ed25519 optional)", async () => {
    const auth = makeAuthority();
    const env = { RRF_KV: makeKV({ [`authority:${AGGREGATOR_RAN}`]: JSON.stringify(auth) }) } as any;
    __setVerifyEnvelopeForTests(async () => true);
    const env_ = makeEnvelope({ alg: ["ML-DSA-65"] });
    delete (env_ as any).kid;
    delete (env_ as any).signature_ed25519;
    const r = await onRequestPost({
      env,
      request: new Request("https://x/", { method: "POST", body: JSON.stringify(env_), headers: { "Content-Type": "application/json" } }),
    } as any);
    expect(r.status).toBe(201);
  });
});
