// functions/v2/orchestrators/[id]/consent.test.ts
import { describe, it, expect } from "vitest";
import { onRequest } from "./consent.js";
import { makeEnv, makeEdKeypair, orchestratorRecord } from "../_orch-test-helpers.js";
import {
  makeTestKeypair, makeRobotRecord, signComplianceBody,
} from "../../_lib/test-helpers.js";

const ID = "orch-testtesttest02";
const RRN_A = "RRN-000000000001";
const RRN_B = "RRN-000000000002";

function req(body: unknown, headers: Record<string, string> = {}): Request {
  return new Request(`https://x/v2/orchestrators/${ID}/consent`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

const call = (env: unknown, request: Request) =>
  onRequest({ request, env, params: { id: ID } } as any);

async function pendingEnv(extraKv: Record<string, string> = {}) {
  const orchKp = await makeEdKeypair();
  return makeEnv({
    [`orchestrator:${ID}`]: orchestratorRecord(ID, orchKp.pem, {
      status: "pending_consent",
      fleet_rrns: [RRN_A, RRN_B],
      consents: { [RRN_A]: false, [RRN_B]: false },
    }),
    ...extraKv,
  });
}

describe("POST /v2/orchestrators/[id]/consent", () => {
  it("401s a junk bearer with an unsigned body (not 404, not 200)", async () => {
    const env = await pendingEnv();
    const res = await call(env, req({ rrn: RRN_A, grant: true }, { Authorization: "Bearer junk" }));
    expect(res.status).toBe(401);
    const stored = JSON.parse((env as any).__store[`orchestrator:${ID}`]);
    expect(stored.consents[RRN_A]).toBe(false);
  });

  it("401s an unsigned body with no Authorization header at all", async () => {
    const env = await pendingEnv();
    const res = await call(env, req({ rrn: RRN_A, grant: true }));
    expect(res.status).toBe(401);
  });

  it("401s a body signed by a key that is not the named RRN's registered pq_signing_pub", async () => {
    const registered = await makeTestKeypair();
    const impostor = await makeTestKeypair();
    const env = await pendingEnv({ [`robot:${RRN_A}`]: makeRobotRecord(RRN_A, registered) });
    const signed = await signComplianceBody({ rrn: RRN_A, grant: true }, impostor);
    const res = await call(env, req(signed));
    expect(res.status).toBe(401);
    const stored = JSON.parse((env as any).__store[`orchestrator:${ID}`]);
    expect(stored.consents[RRN_A]).toBe(false);
  });

  it("401s when the named RRN is not registered at all", async () => {
    const kp = await makeTestKeypair();
    const env = await pendingEnv();
    const signed = await signComplianceBody({ rrn: RRN_A, grant: true }, kp);
    const res = await call(env, req(signed));
    expect(res.status).toBe(401);
  });

  it("403s a revoked RRN even with a valid signature", async () => {
    const kp = await makeTestKeypair();
    const env = await pendingEnv({
      [`robot:${RRN_A}`]: makeRobotRecord(RRN_A, kp),
      [`revocation:${RRN_A}`]: JSON.stringify({ revoked_at: "2026-09-01T00:00:00Z", reason: "test" }),
    });
    const signed = await signComplianceBody({ rrn: RRN_A, grant: true }, kp);
    const res = await call(env, req(signed));
    expect(res.status).toBe(403);
  });

  it("accepts a correctly signed grant and records it", async () => {
    const kp = await makeTestKeypair();
    const env = await pendingEnv({ [`robot:${RRN_A}`]: makeRobotRecord(RRN_A, kp) });
    const signed = await signComplianceBody({ rrn: RRN_A, grant: true }, kp);
    const res = await call(env, req(signed));
    expect(res.status).toBe(200);
    const out = await res.json() as any;
    expect(out.status).toBe("pending_consent");
    expect(out.remaining_consent_from).toEqual([RRN_B]);
    const stored = JSON.parse((env as any).__store[`orchestrator:${ID}`]);
    expect(stored.consents[RRN_A]).toBe(true);
  });

  it("activates once every fleet RRN has signed a grant", async () => {
    const kpA = await makeTestKeypair();
    const kpB = await makeTestKeypair();
    const env = await pendingEnv({
      [`robot:${RRN_A}`]: makeRobotRecord(RRN_A, kpA),
      [`robot:${RRN_B}`]: makeRobotRecord(RRN_B, kpB),
    });
    await call(env, req(await signComplianceBody({ rrn: RRN_A, grant: true }, kpA)));
    const res = await call(env, req(await signComplianceBody({ rrn: RRN_B, grant: true }, kpB)));
    expect(res.status).toBe(200);
    expect((await res.json() as any).status).toBe("active");
  });

  it("a signed denial revokes immediately", async () => {
    const kp = await makeTestKeypair();
    const env = await pendingEnv({ [`robot:${RRN_A}`]: makeRobotRecord(RRN_A, kp) });
    const res = await call(env, req(await signComplianceBody({ rrn: RRN_A, grant: false }, kp)));
    expect(res.status).toBe(200);
    expect((await res.json() as any).status).toBe("revoked");
    const revocations = JSON.parse((env as any).__store["revocations"]);
    expect(revocations.revoked_orchestrators).toContain(ID);
  });

  it("403s an RRN outside the orchestrator's fleet even when correctly signed", async () => {
    const kp = await makeTestKeypair();
    const OTHER = "RRN-000000000009";
    const env = await pendingEnv({ [`robot:${OTHER}`]: makeRobotRecord(OTHER, kp) });
    const res = await call(env, req(await signComplianceBody({ rrn: OTHER, grant: true }, kp)));
    expect(res.status).toBe(403);
  });
});
