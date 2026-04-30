import { describe, it, expect, vi } from "vitest";
import { generateMlDsaKeypair, verifyMlDsa } from "rcan-ts";
import { onRequest } from "./runs.js";
import { payloadBytes } from "./_lib/score-canonical.js";
import {
  makeScoreTestKeypair,
  signScore,
  makeRobotRecord,
  makeScore,
  makeRrfTestEnv,
} from "./_lib/score-test-helpers.js";

const RRN = "RRN-000000000002";

function makeEnv(init: Record<string, string> = {}, extras: Record<string, string> = {}) {
  const store: Record<string, string> = { ...init };
  return {
    RRF_KV: {
      get: vi.fn(async (k: string) => store[k] ?? null),
      put: vi.fn(async (k: string, v: string) => {
        store[k] = v;
      }),
      list: vi.fn(),
      delete: vi.fn(),
    } as unknown as KVNamespace,
    ...extras,
    __store: store,
  };
}

function req(method: string, body?: unknown, headers: Record<string, string> = {}) {
  return new Request("https://x/v1/spatial-eval/runs", {
    method,
    headers: { "Content-Type": "application/json", ...headers },
    body: body ? JSON.stringify(body) : undefined,
  });
}

describe("POST /v1/spatial-eval/runs", () => {
  it("happy path: verifies, counter-signs, stores, returns counter_signed score", async () => {
    const robotKp = makeScoreTestKeypair();
    const rrfKp = generateMlDsaKeypair();
    const env = makeEnv(
      { [`robot:${RRN}`]: makeRobotRecord(RRN, robotKp) },
      makeRrfTestEnv(rrfKp.privateKey),
    );

    const score = signScore(makeScore(RRN), robotKp);
    const res = await onRequest({ request: req("POST", { score }), env, params: {} } as any);

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.status).toBe("counter_signed");
    expect(body.submission_id).toMatch(/^sub_/);
    expect(typeof body.score.rrf_signature).toBe("string");

    // RRF's counter-signature must verify under the test RRF pubkey
    // over the SAME canonical bytes the robot signed.
    const sigBytes = Uint8Array.from(atob(body.score.rrf_signature), (c) => c.charCodeAt(0));
    expect(verifyMlDsa(rrfKp.publicKey, payloadBytes(body.score), sigBytes)).toBe(true);

    // Stored under both keys
    expect(env.__store[`compliance:spatial-eval:run:${body.submission_id}`]).toBeTruthy();
    expect(env.__store[`compliance:spatial-eval:by_rrn:${RRN}:run-1`]).toBe(body.submission_id);
  });

  it("returns 400 on invalid JSON body", async () => {
    const env = makeEnv({}, makeRrfTestEnv(generateMlDsaKeypair().privateKey));
    const res = await onRequest({
      request: new Request("https://x/v1/spatial-eval/runs", {
        method: "POST",
        body: "not-json",
        headers: { "Content-Type": "application/json" },
      }),
      env,
      params: {},
    } as any);
    expect(res.status).toBe(400);
  });

  it("returns 400 when 'score' object is missing", async () => {
    const env = makeEnv({}, makeRrfTestEnv(generateMlDsaKeypair().privateKey));
    const res = await onRequest({
      request: req("POST", { not_score: 42 }),
      env,
      params: {},
    } as any);
    expect(res.status).toBe(400);
  });

  it("returns 400 when score lacks rrn", async () => {
    const env = makeEnv({}, makeRrfTestEnv(generateMlDsaKeypair().privateKey));
    const score = makeScore(RRN);
    delete score.rrn;
    const res = await onRequest({
      request: req("POST", { score: { ...score, rcan_signature: "x" } }),
      env,
      params: {},
    } as any);
    expect(res.status).toBe(400);
  });

  it("returns 400 when score lacks rcan_signature", async () => {
    const env = makeEnv({}, makeRrfTestEnv(generateMlDsaKeypair().privateKey));
    const res = await onRequest({
      request: req("POST", { score: makeScore(RRN) }),
      env,
      params: {},
    } as any);
    expect(res.status).toBe(400);
  });

  it("returns 401 when robot is not registered", async () => {
    const robotKp = makeScoreTestKeypair();
    const env = makeEnv({}, makeRrfTestEnv(generateMlDsaKeypair().privateKey));
    const score = signScore(makeScore(RRN), robotKp);
    const res = await onRequest({ request: req("POST", { score }), env, params: {} } as any);
    expect(res.status).toBe(401);
  });

  it("returns 422 when rcan_signature does not verify (tampered score)", async () => {
    const robotKp = makeScoreTestKeypair();
    const rrfKp = generateMlDsaKeypair();
    const env = makeEnv(
      { [`robot:${RRN}`]: makeRobotRecord(RRN, robotKp) },
      makeRrfTestEnv(rrfKp.privateKey),
    );
    const score = signScore(makeScore(RRN), robotKp);
    // Tamper a non-signature field after signing
    const tampered = { ...score, run_id: "tampered-run-id" };
    const res = await onRequest({
      request: req("POST", { score: tampered }),
      env,
      params: {},
    } as any);
    expect(res.status).toBe(422);
  });

  it("returns 409 on duplicate (rrn, run_id)", async () => {
    const robotKp = makeScoreTestKeypair();
    const rrfKp = generateMlDsaKeypair();
    const env = makeEnv(
      { [`robot:${RRN}`]: makeRobotRecord(RRN, robotKp) },
      makeRrfTestEnv(rrfKp.privateKey),
    );
    const score = signScore(makeScore(RRN, "run-dup"), robotKp);
    const r1 = await onRequest({
      request: req("POST", { score }),
      env,
      params: {},
    } as any);
    expect(r1.status).toBe(200);
    const r2 = await onRequest({
      request: req("POST", { score }),
      env,
      params: {},
    } as any);
    expect(r2.status).toBe(409);
    const body = await r2.json();
    expect(body.submission_id).toMatch(/^sub_/);
  });

  it("returns 500 when RRF_SPATIAL_EVAL_PQ_PRIV secret is missing", async () => {
    const robotKp = makeScoreTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, robotKp) });
    // No RRF priv key in env
    const score = signScore(makeScore(RRN), robotKp);
    const res = await onRequest({ request: req("POST", { score }), env, params: {} } as any);
    expect(res.status).toBe(500);
  });

  it("returns 405 on non-POST", async () => {
    const env = makeEnv({}, makeRrfTestEnv(generateMlDsaKeypair().privateKey));
    const res = await onRequest({
      request: new Request("https://x/v1/spatial-eval/runs", { method: "GET" }),
      env,
      params: {},
    } as any);
    expect(res.status).toBe(405);
  });
});
