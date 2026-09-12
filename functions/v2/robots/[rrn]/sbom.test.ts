import { describe, it, expect, vi } from "vitest";
import { onRequest } from "./sbom.js";
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
  return new Request(`https://x/v2/robots/${RRN}/sbom`, {
    method,
    headers: { "Content-Type": "application/json", ...headers },
    body: body ? JSON.stringify(body) : undefined,
  });
}

function sbomDoc(rrn: string = RRN) {
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    version: 1,
    components: [{ type: "library", name: "libtest", version: "1.0.0" }],
    "x-rcan": { rrn, rcan_version: "3.0" },
  };
}

/** No SBOM row may exist under any of the route's write keys. */
function sbomKeys(store: Record<string, string>): string[] {
  return Object.keys(store).filter((k) => k.startsWith("sbom:") || k.startsWith("compliance:sbom:"));
}

describe("POST /v2/robots/[rrn]/sbom (signature-gated)", () => {
  it("rejects 'Bearer junk-not-a-real-token' with an unsigned SBOM and stores nothing", async () => {
    const env = makeEnv({ [`robot:${RRN}`]: "{}" });
    const res = await onRequest({
      request: req("POST", sbomDoc(), { Authorization: "Bearer junk-not-a-real-token" }),
      env, params: { rrn: RRN },
    } as any);
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
    expect(sbomKeys(env.__store)).toEqual([]);
    expect(env.RRF_KV.put).not.toHaveBeenCalled();
  });

  it("returns 401 when the SBOM is signed by a key that is not on record", async () => {
    const onRecord = await makeTestKeypair();
    const attacker = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, onRecord) });
    const signed = await signComplianceBody(sbomDoc(), attacker);
    const res = await onRequest({
      request: req("POST", signed, { Authorization: "Bearer junk-not-a-real-token" }),
      env, params: { rrn: RRN },
    } as any);
    expect(res.status).toBe(401);
    expect(sbomKeys(env.__store)).toEqual([]);
  });

  it("returns 401 when the robot is not registered", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv();
    const signed = await signComplianceBody(sbomDoc(), kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(401);
    expect(sbomKeys(env.__store)).toEqual([]);
  });

  it("returns 401 on a tampered body", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const signed = await signComplianceBody(sbomDoc(), kp);
    const tampered = { ...signed, components: [{ type: "library", name: "evil", version: "9.9.9" }] };
    const res = await onRequest({ request: req("POST", tampered), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(401);
    expect(sbomKeys(env.__store)).toEqual([]);
  });

  it("returns 403 when the robot's key is revoked", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({
      [`robot:${RRN}`]: makeRobotRecord(RRN, kp),
      [`revocation:${RRN}`]: JSON.stringify({ revoked_at: "2026-09-01T00:00:00Z", reason: "test" }),
    });
    const signed = await signComplianceBody(sbomDoc(), kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(403);
    expect(sbomKeys(env.__store)).toEqual([]);
  });

  it("stores and countersigns a correctly signed SBOM (201)", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const signed = await signComplianceBody(sbomDoc(), kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(201);
    const stored = env.__store[`sbom:${RRN}`];
    expect(stored).toBeTruthy();
    const parsed = JSON.parse(stored);
    expect(parsed.bomFormat).toBe("CycloneDX");
    // Envelope fields are stripped by verifyComplianceSubmission before storage.
    expect(parsed.sig).toBeUndefined();
    expect(parsed.pq_kid).toBeUndefined();
    expect(parsed["x-rcan"].rrf_countersig).toBeTruthy();
    expect(Object.keys(env.__store).filter((k) => k.startsWith(`sbom:history:${RRN}:`)).length).toBe(1);
  });

  it("returns 400 on a signed body that is not CycloneDX", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const signed = await signComplianceBody({ ...sbomDoc(), bomFormat: "SPDX" }, kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(400);
    expect(sbomKeys(env.__store)).toEqual([]);
  });

  it("returns 400 when x-rcan.rrn does not match the URL rrn", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const signed = await signComplianceBody(sbomDoc("RRN-000000000999"), kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(400);
    expect(sbomKeys(env.__store)).toEqual([]);
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

describe("GET /v2/robots/[rrn]/sbom", () => {
  it("returns the stored countersigned SBOM", async () => {
    const env = makeEnv({ [`sbom:${RRN}`]: JSON.stringify(sbomDoc()) });
    const res = await onRequest({ request: req("GET"), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(200);
  });

  it("returns 404 when nothing has been submitted", async () => {
    const env = makeEnv();
    const res = await onRequest({ request: req("GET"), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(404);
  });
});
