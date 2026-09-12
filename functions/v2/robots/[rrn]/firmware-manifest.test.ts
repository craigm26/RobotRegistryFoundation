import { describe, it, expect, vi } from "vitest";
import { onRequest } from "./firmware-manifest.js";
import { signComplianceBody, makeTestKeypair, makeRobotRecord } from "../../_lib/test-helpers.js";

const RRN = "RRN-000000000001";

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
  return new Request(`https://x/v2/robots/${RRN}/firmware-manifest`, {
    method,
    headers: { "Content-Type": "application/json", ...headers },
    body: body ? JSON.stringify(body) : undefined,
  });
}

function manifestDoc(rrn: string = RRN) {
  return {
    rrn,
    firmware_version: "1.2.3",
    build_hash: "sha256:" + "a".repeat(64),
    signature: "stub-firmware-signature",
    built_at: "2026-09-01T00:00:00Z",
  };
}

/** No manifest row may exist under any of the route's write keys. */
function manifestKeys(store: Record<string, string>): string[] {
  return Object.keys(store).filter((k) => k.startsWith("firmware:"));
}

describe("POST /v2/robots/[rrn]/firmware-manifest (signature-gated)", () => {
  it("rejects 'Bearer junk-not-a-real-token' with an unsigned manifest and stores nothing", async () => {
    const env = makeEnv({ [`robot:${RRN}`]: "{}" });
    const res = await onRequest({
      request: req("POST", manifestDoc(), { Authorization: "Bearer junk-not-a-real-token" }),
      env, params: { rrn: RRN },
    } as any);
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
    expect(manifestKeys(env.__store)).toEqual([]);
    expect(env.RRF_KV.put).not.toHaveBeenCalled();
  });

  it("returns 401 when the manifest is signed by a key that is not on record", async () => {
    const onRecord = await makeTestKeypair();
    const attacker = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, onRecord) });
    const signed = await signComplianceBody(manifestDoc(), attacker);
    const res = await onRequest({
      request: req("POST", signed, { Authorization: "Bearer junk-not-a-real-token" }),
      env, params: { rrn: RRN },
    } as any);
    expect(res.status).toBe(401);
    expect(manifestKeys(env.__store)).toEqual([]);
  });

  it("returns 401 when the robot is not registered", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv();
    const signed = await signComplianceBody(manifestDoc(), kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(401);
    expect(manifestKeys(env.__store)).toEqual([]);
  });

  it("returns 401 on a tampered body", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const signed = await signComplianceBody(manifestDoc(), kp);
    const tampered = { ...signed, build_hash: "sha256:" + "b".repeat(64) };
    const res = await onRequest({ request: req("POST", tampered), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(401);
    expect(manifestKeys(env.__store)).toEqual([]);
  });

  it("returns 403 when the robot's key is revoked", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({
      [`robot:${RRN}`]: makeRobotRecord(RRN, kp),
      [`revocation:${RRN}`]: JSON.stringify({ revoked_at: "2026-09-01T00:00:00Z", reason: "test" }),
    });
    const signed = await signComplianceBody(manifestDoc(), kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(403);
    expect(manifestKeys(env.__store)).toEqual([]);
  });

  it("stores a correctly signed manifest (201)", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const signed = await signComplianceBody(manifestDoc(), kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(201);
    const stored = env.__store[`firmware:manifest:${RRN}`];
    expect(stored).toBeTruthy();
    const parsed = JSON.parse(stored);
    expect(parsed.firmware_version).toBe("1.2.3");
    // Envelope fields are stripped by verifyComplianceSubmission before storage.
    expect(parsed.sig).toBeUndefined();
    expect(parsed.pq_kid).toBeUndefined();
    expect(Object.keys(env.__store).filter((k) => k.startsWith(`firmware:history:${RRN}:`)).length).toBe(1);
  });

  it("returns 400 on a signed manifest missing required fields", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const { signature: _omitted, ...withoutSignature } = manifestDoc();
    const signed = await signComplianceBody(withoutSignature, kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(400);
    expect(manifestKeys(env.__store)).toEqual([]);
  });

  it("returns 400 when manifest.rrn does not match the URL rrn", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const signed = await signComplianceBody(manifestDoc("RRN-000000000999"), kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(400);
    expect(manifestKeys(env.__store)).toEqual([]);
  });

  it("returns 400 when build_hash is not sha256-prefixed", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const signed = await signComplianceBody({ ...manifestDoc(), build_hash: "md5:deadbeef" }, kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(400);
    expect(manifestKeys(env.__store)).toEqual([]);
  });

  it("returns 400 on invalid RRN format", async () => {
    const env = makeEnv();
    const res = await onRequest({ request: req("POST", {}), env, params: { rrn: "bad" } } as any);
    expect(res.status).toBe(400);
  });

  it("returns 405 on PUT", async () => {
    const env = makeEnv();
    const res = await onRequest({ request: req("PUT"), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(405);
  });
});

describe("GET /v2/robots/[rrn]/firmware-manifest", () => {
  it("returns the stored manifest", async () => {
    const env = makeEnv({ [`firmware:manifest:${RRN}`]: JSON.stringify(manifestDoc()) });
    const res = await onRequest({ request: req("GET"), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(200);
  });

  it("returns 404 when nothing has been submitted", async () => {
    const env = makeEnv();
    const res = await onRequest({ request: req("GET"), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(404);
  });
});
