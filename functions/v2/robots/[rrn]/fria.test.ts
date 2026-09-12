import { describe, it, expect, vi } from "vitest";
import { onRequest } from "./fria.js";
import { signComplianceBody, makeTestKeypair, makeRobotRecord } from "../../_lib/test-helpers.js";

const RRN = "RRN-000000000001";
const FRIA_SCHEMA = "rcan-fria-v1";
const API_KEY = "rrf_live_testkey_000000000000";

/** Minimal robot record carrying only what requireRobotApiKey reads. */
function robotWithKey(apiKey: string = API_KEY): string {
  return JSON.stringify({ rrn: RRN, api_key: apiKey });
}

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

function req(method: string, body?: unknown, headers: Record<string, string> = {}): Request {
  return new Request(`https://x/v2/robots/${RRN}/fria`, {
    method,
    headers: { "Content-Type": "application/json", ...headers },
    body: body ? JSON.stringify(body) : undefined,
  });
}

function friaDoc(systemRrn: string = RRN) {
  return {
    schema: FRIA_SCHEMA,
    generated_at: "2026-04-23T00:00:00Z",
    system: { rrn: systemRrn, robot_name: "test", rcan_version: "3.0" },
    deployment: { annex_iii_basis: "Annex III(5)(b)" },
    signing_key: { alg: "ml-dsa-65", kid: "abcd1234", public_key: "stub-base64" },
    conformance: null,
  };
}

describe("GET /v2/robots/[rrn]/fria (api_key-gated)", () => {
  it("returns 401 without Bearer header", async () => {
    const env = makeEnv({
      [`robot:${RRN}`]: robotWithKey(),
      [`compliance:fria:${RRN}`]: JSON.stringify(friaDoc()),
    });
    const res = await onRequest({ request: req("GET"), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(401);
  });

  it("returns 403 on 'Bearer junk-not-a-real-token'", async () => {
    const env = makeEnv({
      [`robot:${RRN}`]: robotWithKey(),
      [`compliance:fria:${RRN}`]: JSON.stringify(friaDoc()),
    });
    const res = await onRequest({
      request: req("GET", undefined, { Authorization: "Bearer junk-not-a-real-token" }),
      env, params: { rrn: RRN },
    } as any);
    expect(res.status).toBe(403);
    expect(await res.text()).not.toContain("annex_iii_basis");
  });

  it("does not read the artifact key at all when the token is wrong", async () => {
    const env = makeEnv({
      [`robot:${RRN}`]: robotWithKey(),
      [`compliance:fria:${RRN}`]: JSON.stringify(friaDoc()),
    });
    await onRequest({
      request: req("GET", undefined, { Authorization: "Bearer junk-not-a-real-token" }),
      env, params: { rrn: RRN },
    } as any);
    const keysRead = (env.RRF_KV.get as any).mock.calls.map((c: unknown[]) => c[0]);
    expect(keysRead).not.toContain(`compliance:fria:${RRN}`);
  });

  it("gives a junk token the same status whether or not an artifact is stored", async () => {
    const withDoc = makeEnv({ [`compliance:fria:${RRN}`]: JSON.stringify(friaDoc()) });
    const withoutDoc = makeEnv();
    const a = await onRequest({
      request: req("GET", undefined, { Authorization: "Bearer junk-not-a-real-token" }),
      env: withDoc, params: { rrn: RRN },
    } as any);
    const b = await onRequest({
      request: req("GET", undefined, { Authorization: "Bearer junk-not-a-real-token" }),
      env: withoutDoc, params: { rrn: RRN },
    } as any);
    expect(a.status).toBe(b.status);
  });

  it("returns 403 when the robot's key is revoked", async () => {
    const env = makeEnv({
      [`robot:${RRN}`]: robotWithKey(),
      [`revocation:${RRN}`]: JSON.stringify({ revoked_at: "2026-09-01T00:00:00Z", reason: "test" }),
      [`compliance:fria:${RRN}`]: JSON.stringify(friaDoc()),
    });
    const res = await onRequest({
      request: req("GET", undefined, { Authorization: `Bearer ${API_KEY}` }),
      env, params: { rrn: RRN },
    } as any);
    expect(res.status).toBe(403);
  });

  it("returns stored doc for the robot's own api_key", async () => {
    const env = makeEnv({
      [`robot:${RRN}`]: robotWithKey(),
      [`compliance:fria:${RRN}`]: JSON.stringify(friaDoc()),
    });
    const res = await onRequest({
      request: req("GET", undefined, { Authorization: `Bearer ${API_KEY}` }),
      env, params: { rrn: RRN },
    } as any);
    expect(res.status).toBe(200);
  });

  it("returns 404 when nothing submitted (with the right api_key)", async () => {
    const env = makeEnv({ [`robot:${RRN}`]: robotWithKey() });
    const res = await onRequest({
      request: req("GET", undefined, { Authorization: `Bearer ${API_KEY}` }),
      env, params: { rrn: RRN },
    } as any);
    expect(res.status).toBe(404);
  });

  it("returns 400 on invalid RRN format", async () => {
    const env = makeEnv();
    const res = await onRequest({ request: req("GET"), env, params: { rrn: "bad" } } as any);
    expect(res.status).toBe(400);
  });
});

describe("POST /v2/robots/[rrn]/fria", () => {
  it("stores and returns 201 on valid submission", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const signed = await signComplianceBody(friaDoc() as unknown as Record<string, unknown>, kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(201);
    expect(env.__store[`compliance:fria:${RRN}`]).toBeTruthy();
  });

  it("401 on tampered body", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const signed = await signComplianceBody(friaDoc() as unknown as Record<string, unknown>, kp);
    const tampered = { ...signed, generated_at: "2099-01-01T00:00:00Z" };
    const res = await onRequest({ request: req("POST", tampered), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(401);
  });

  it("401 when robot not registered", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv();
    const signed = await signComplianceBody(friaDoc() as unknown as Record<string, unknown>, kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(401);
  });

  it("400 on missing sig", async () => {
    const env = makeEnv({ [`robot:${RRN}`]: "{}" });
    const res = await onRequest({ request: req("POST", { schema: FRIA_SCHEMA, pq_kid: "x" }), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(400);
  });

  it("400 on wrong schema string", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const wrongDoc = { ...friaDoc(), schema: "rcan-ifu-v1" };
    const signed = await signComplianceBody(wrongDoc as unknown as Record<string, unknown>, kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(400);
  });

  it("400 on doc.system.rrn != URL rrn", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const signed = await signComplianceBody(friaDoc("RRN-000000000999") as unknown as Record<string, unknown>, kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(400);
  });

  it("400 on missing doc.system", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const noSystem = { schema: FRIA_SCHEMA, generated_at: "2026-04-23T00:00:00Z" };
    const signed = await signComplianceBody(noSystem, kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(400);
  });

  it("returns 405 on PUT", async () => {
    const env = makeEnv();
    const res = await onRequest({ request: req("PUT"), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(405);
  });
});
