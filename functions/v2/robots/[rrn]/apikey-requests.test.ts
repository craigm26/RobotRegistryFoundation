import { describe, it, expect, vi } from "vitest";
import { onRequest } from "./apikey-requests.js";
import { makeTestKeypair, signComplianceBody, makeRobotRecord } from "../../_lib/test-helpers.js";

const RRN = "RRN-000000000001";
const REQUEST_SCHEMA = "rcan-apikey-request-v1";

function makeEnv(init: Record<string, string> = {}) {
  const store: Record<string, string> = { ...init };
  return {
    RRF_KV: {
      get: vi.fn(async (k: string) => store[k] ?? null),
      put: vi.fn(async (k: string, v: string) => { store[k] = v; }),
      list: vi.fn(), delete: vi.fn(),
    } as unknown as KVNamespace,
    __store: store,
  };
}

function req(method: string, body?: unknown, rrn = RRN): Request {
  return new Request(`https://x/v2/robots/${rrn}/apikey-requests`, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
}

function freshRequest(rrn: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schema: REQUEST_SCHEMA,
    rrn,
    operation: "reissue",
    generated_at: new Date().toISOString(),
    nonce: "00000000-0000-4000-8000-000000000001",
    reason: "lost original apikey",
    ...overrides,
  };
}

describe("POST /v2/robots/[rrn]/apikey-requests", () => {
  it("happy path: returns 201 with fresh apikey and updates robot record", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const signed = await signComplianceBody(freshRequest(RRN), kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(201);
    const body = await res.json() as Record<string, unknown>;
    expect(body.rrn).toBe(RRN);
    expect(typeof body.api_key).toBe("string");
    expect((body.api_key as string).startsWith("rrf_")).toBe(true);
    expect((body.api_key as string).length).toBeGreaterThanOrEqual(40);
    expect(body.operation).toBe("reissue");
    expect(body.prior_key_exists).toBe(false);
    expect(body.api_key_reissue_count).toBe(1);
    const stored = JSON.parse(env.__store[`robot:${RRN}`]);
    expect(stored.api_key).toBe(body.api_key);
    expect(stored.api_key_issued_at).toBe(body.issued_at);
    expect(stored.api_key_reissue_count).toBe(1);
  });

  it("flags prior_key_exists when reissuing over an existing apikey", async () => {
    const kp = await makeTestKeypair();
    const baseRecord = JSON.parse(makeRobotRecord(RRN, kp));
    baseRecord.api_key = "rrf_old";
    baseRecord.api_key_reissue_count = 2;
    const env = makeEnv({ [`robot:${RRN}`]: JSON.stringify(baseRecord) });
    const signed = await signComplianceBody(freshRequest(RRN), kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(201);
    const body = await res.json() as Record<string, unknown>;
    expect(body.prior_key_exists).toBe(true);
    expect(body.api_key_reissue_count).toBe(3);
    const stored = JSON.parse(env.__store[`robot:${RRN}`]);
    expect(stored.api_key).not.toBe("rrf_old");
  });

  it("400 on missing sig fields", async () => {
    const env = makeEnv({ [`robot:${RRN}`]: "{}" });
    const res = await onRequest({ request: req("POST", { schema: REQUEST_SCHEMA, rrn: RRN, pq_kid: "x" }), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(400);
  });

  it("400 on wrong schema", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const signed = await signComplianceBody(freshRequest(RRN, { schema: "rcan-ifu-v1" }), kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(400);
    const body = await res.json() as Record<string, unknown>;
    expect((body.error as string).toLowerCase()).toContain("schema");
  });

  it("400 on rrn mismatch between body and URL", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const signed = await signComplianceBody(freshRequest("RRN-000000000099"), kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(400);
    const body = await res.json() as Record<string, unknown>;
    expect((body.error as string).toLowerCase()).toContain("rrn");
  });

  it("400 on operation='new' (multi-key not supported in v1)", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const signed = await signComplianceBody(freshRequest(RRN, { operation: "new" }), kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(400);
    const body = await res.json() as Record<string, unknown>;
    expect((body.error as string).toLowerCase()).toContain("multi-key");
  });

  it("400 on unknown operation value", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const signed = await signComplianceBody(freshRequest(RRN, { operation: "delete" }), kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(400);
  });

  it("400 on stale generated_at (15 min old)", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const stale = new Date(Date.now() - 15 * 60 * 1000).toISOString();
    const signed = await signComplianceBody(freshRequest(RRN, { generated_at: stale }), kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(400);
    const body = await res.json() as Record<string, unknown>;
    expect((body.error as string).toLowerCase()).toMatch(/stale|window|timestamp/);
  });

  it("400 on far-future generated_at (15 min ahead)", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const future = new Date(Date.now() + 15 * 60 * 1000).toISOString();
    const signed = await signComplianceBody(freshRequest(RRN, { generated_at: future }), kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(400);
  });

  it("201 within window: 5 min in past is fine", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const recent = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    const signed = await signComplianceBody(freshRequest(RRN, { generated_at: recent }), kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(201);
  });

  it("400 on missing nonce", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const noNonce = freshRequest(RRN);
    delete (noNonce as Record<string, unknown>).nonce;
    const signed = await signComplianceBody(noNonce, kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(400);
    const body = await res.json() as Record<string, unknown>;
    expect((body.error as string).toLowerCase()).toContain("nonce");
  });

  it("401 on tampered body", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const signed = await signComplianceBody(freshRequest(RRN), kp);
    const tampered = { ...signed, reason: "tampered post-sig" };
    const res = await onRequest({ request: req("POST", tampered), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(401);
  });

  it("401 on unregistered RRN", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv();
    const signed = await signComplianceBody(freshRequest(RRN), kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(401);
  });

  it("400 on malformed URL RRN", async () => {
    const env = makeEnv();
    const res = await onRequest({ request: req("POST", {}, "bad-rrn"), env, params: { rrn: "bad-rrn" } } as any);
    expect(res.status).toBe(400);
  });

  it("400 on invalid JSON body", async () => {
    const env = makeEnv({ [`robot:${RRN}`]: "{}" });
    const r = new Request(`https://x/v2/robots/${RRN}/apikey-requests`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{not json",
    });
    const res = await onRequest({ request: r, env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(400);
  });

  it("405 on GET", async () => {
    const env = makeEnv();
    const res = await onRequest({ request: req("GET"), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(405);
  });

  it("405 on PUT", async () => {
    const env = makeEnv();
    const res = await onRequest({ request: req("PUT"), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(405);
  });

  it("issues distinct apikeys across two reissues", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const r1 = await onRequest({ request: req("POST", await signComplianceBody(freshRequest(RRN), kp)), env, params: { rrn: RRN } } as any);
    const k1 = ((await r1.json()) as Record<string, unknown>).api_key;
    const second = freshRequest(RRN, { nonce: "00000000-0000-4000-8000-000000000002" });
    const r2 = await onRequest({ request: req("POST", await signComplianceBody(second, kp)), env, params: { rrn: RRN } } as any);
    expect(r2.status).toBe(201);
    const k2 = ((await r2.json()) as Record<string, unknown>).api_key;
    expect(k2).not.toBe(k1);
  });
});
