import { describe, it, expect, vi } from "vitest";
import { onRequestPost } from "./revoke-key.js";
import { makeTestKeypair, makeRobotRecord, signComplianceBody } from "../../_lib/test-helpers.js";

const RRN = "RRN-000000000042";

function makeEnv(init: Record<string, string> = {}) {
  const store: Record<string, string> = { ...init };
  return {
    RRF_KV: {
      get: vi.fn(async (k: string) => store[k] ?? null),
      put: vi.fn(async (k: string, v: string) => { store[k] = v; }),
      delete: vi.fn(async (k: string) => { delete store[k]; }),
      list: vi.fn(),
    } as unknown as KVNamespace,
    __store: store,
  };
}

function req(body: unknown): Request {
  return new Request(`https://x/v2/robots/${RRN}/revoke-key`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("POST /v2/robots/[rrn]/revoke-key", () => {
  it("400 on invalid RRN format", async () => {
    const env = makeEnv();
    const res = await onRequestPost({ request: req({}), env, params: { rrn: "bad" } } as any);
    expect(res.status).toBe(400);
  });

  it("404 when record does not exist", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv();
    const signed = await signComplianceBody({ rrn: RRN, action: "revoke", reason: "lost laptop" }, kp);
    const res = await onRequestPost({ request: req(signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(404);
  });

  it("revokes with valid signature (204) and writes revocation entry", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const signed = await signComplianceBody({ rrn: RRN, action: "revoke", reason: "lost laptop" }, kp);
    const res = await onRequestPost({ request: req(signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(204);
    const rev = JSON.parse(env.__store[`revocation:${RRN}`]);
    expect(rev.reason).toBe("lost laptop");
    expect(rev.revoked_at).toBeTypeOf("string");
  });

  it("rejects signature from a non-current key (401)", async () => {
    const kp1 = await makeTestKeypair();
    const kp2 = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp1) });
    const signed = await signComplianceBody({ rrn: RRN, action: "revoke" }, kp2);
    const res = await onRequestPost({ request: req(signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(401);
  });

  it("rejects tampered body (401)", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const signed = await signComplianceBody({ rrn: RRN, action: "revoke" }, kp);
    const tampered = { ...signed, action: "keep" };
    const res = await onRequestPost({ request: req(tampered), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(401);
  });

  it("400 when body does not bind rrn and action:revoke", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const signed = await signComplianceBody({ rrn: "RRN-000000000999", action: "revoke" }, kp);
    const res = await onRequestPost({ request: req(signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(400);
  });

  it("409 when already revoked", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({
      [`robot:${RRN}`]: makeRobotRecord(RRN, kp),
      [`revocation:${RRN}`]: JSON.stringify({ revoked_at: "2026-04-24T00:00:00Z", reason: "first" }),
    });
    const signed = await signComplianceBody({ rrn: RRN, action: "revoke", reason: "second" }, kp);
    const res = await onRequestPost({ request: req(signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(409);
  });
});
