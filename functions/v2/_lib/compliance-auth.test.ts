import { describe, it, expect, vi } from "vitest";
import { verifyComplianceSubmission } from "./compliance-auth.js";
import { signComplianceBody, makeTestKeypair, makeRobotRecord } from "./test-helpers.js";

const RRN = "RRN-000000000001";

function makeEnv(stored: Record<string, string> = {}) {
  return {
    RRF_KV: {
      get: vi.fn(async (k: string) => stored[k] ?? null),
      put: vi.fn(async (k: string, v: string) => { stored[k] = v; }),
      list: vi.fn(),
      delete: vi.fn(),
    } as unknown as KVNamespace,
  };
}

function makePost(body: unknown): Request {
  return new Request("https://x/v2/robots/R/ifu", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

describe("verifyComplianceSubmission", () => {
  it("returns ok with document on valid sig", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const doc = { schema: "rcan-ifu-v1", rrn: RRN, version: "1.0" };
    const signed = await signComplianceBody(doc, kp);

    const result = await verifyComplianceSubmission(makePost(signed), env, `robot:${RRN}`);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.document.schema).toBe("rcan-ifu-v1");
      expect(result.document.rrn).toBe(RRN);
      expect("sig" in result.document).toBe(false);
      expect("pq_kid" in result.document).toBe(false);
    }
  });

  it("returns 400 on invalid JSON", async () => {
    const env = makeEnv();
    const result = await verifyComplianceSubmission(makePost("not json"), env, `robot:${RRN}`);
    expect(result).toEqual({ ok: false, status: 400, error: "Invalid JSON body" });
  });

  it("returns 400 when sig is missing", async () => {
    const env = makeEnv({ [`robot:${RRN}`]: "{}" });
    const result = await verifyComplianceSubmission(
      makePost({ schema: "x", rrn: RRN, pq_kid: "k" }),
      env, `robot:${RRN}`,
    );
    expect(result).toEqual({ ok: false, status: 400, error: "Missing signature fields" });
  });

  it("returns 400 when pq_kid is missing", async () => {
    const env = makeEnv({ [`robot:${RRN}`]: "{}" });
    const result = await verifyComplianceSubmission(
      makePost({ schema: "x", sig: { ml_dsa: "a", ed25519: "b", ed25519_pub: "c" } }),
      env, `robot:${RRN}`,
    );
    expect(result).toEqual({ ok: false, status: 400, error: "Missing signature fields" });
  });

  it("returns 401 when robot not registered", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv();
    const signed = await signComplianceBody({ schema: "rcan-ifu-v1", rrn: RRN }, kp);
    const result = await verifyComplianceSubmission(makePost(signed), env, `robot:${RRN}`);
    expect(result).toEqual({ ok: false, status: 401, error: "Robot not registered" });
  });

  it("returns 401 when sig does not verify", async () => {
    const kp1 = await makeTestKeypair();
    const kp2 = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp1) });
    const signed = await signComplianceBody({ schema: "rcan-ifu-v1", rrn: RRN }, kp2);
    const result = await verifyComplianceSubmission(makePost(signed), env, `robot:${RRN}`);
    expect(result).toEqual({ ok: false, status: 401, error: "Signature verification failed" });
  });

  it("returns 401 when body tampered after sign", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const signed = await signComplianceBody({ schema: "rcan-ifu-v1", rrn: RRN }, kp);
    const tampered = { ...signed, rrn: "RRN-000000000999" };
    const result = await verifyComplianceSubmission(makePost(tampered), env, `robot:${RRN}`);
    expect(result).toEqual({ ok: false, status: 401, error: "Signature verification failed" });
  });
});
