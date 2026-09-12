import { describe, it, expect, vi } from "vitest";
import { onRequest } from "./incident-report.js";
import { buildIncidentReport, INCIDENT_REPORT_SCHEMA } from "rcan-ts";
import { signComplianceBody, makeTestKeypair, makeRobotRecord } from "../../_lib/test-helpers.js";

const RRN = "RRN-000000000001";
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
  return new Request(`https://x/v2/robots/${RRN}/incident-report`, {
    method,
    headers: { "Content-Type": "application/json", ...headers },
    body: body ? JSON.stringify(body) : undefined,
  });
}

function validReportInput(rrn: string = RRN) {
  return {
    rrn,
    incidents: [
      { timestamp: "2026-04-10T12:00:00Z", severity: "other" as const, description: "minor jam" },
    ],
    generated_at: "2026-04-23T00:00:00Z",
  };
}

describe("GET /v2/robots/[rrn]/incident-report (api_key-gated)", () => {
  it("returns 401 without Bearer header", async () => {
    const env = makeEnv({
      [`robot:${RRN}`]: robotWithKey(),
      [`compliance:incident-report:${RRN}`]: "{}",
    });
    const res = await onRequest({ request: req("GET"), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(401);
  });

  it("returns 403 on 'Bearer junk-not-a-real-token'", async () => {
    const env = makeEnv({
      [`robot:${RRN}`]: robotWithKey(),
      [`compliance:incident-report:${RRN}`]: JSON.stringify({ schema: INCIDENT_REPORT_SCHEMA, rrn: RRN }),
    });
    const res = await onRequest({
      request: req("GET", undefined, { Authorization: "Bearer junk-not-a-real-token" }),
      env, params: { rrn: RRN },
    } as any);
    expect(res.status).toBe(403);
    expect(await res.text()).not.toContain(INCIDENT_REPORT_SCHEMA);
  });

  it("does not read the artifact key at all when the token is wrong", async () => {
    const env = makeEnv({
      [`robot:${RRN}`]: robotWithKey(),
      [`compliance:incident-report:${RRN}`]: "{}",
    });
    await onRequest({
      request: req("GET", undefined, { Authorization: "Bearer junk-not-a-real-token" }),
      env, params: { rrn: RRN },
    } as any);
    const keysRead = (env.RRF_KV.get as any).mock.calls.map((c: unknown[]) => c[0]);
    expect(keysRead).not.toContain(`compliance:incident-report:${RRN}`);
  });

  it("401 for an unregistered RRN is indistinguishable from a stored artifact", async () => {
    // No robot record: a junk token gets the same 401 whether or not a report exists.
    const withDoc = makeEnv({ [`compliance:incident-report:${RRN}`]: "{}" });
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
      [`compliance:incident-report:${RRN}`]: "{}",
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
      [`compliance:incident-report:${RRN}`]: JSON.stringify({ schema: INCIDENT_REPORT_SCHEMA, rrn: RRN }),
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

describe("POST /v2/robots/[rrn]/incident-report", () => {
  it("stores and returns 201 on valid submission", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const doc = buildIncidentReport(validReportInput());
    const signed = await signComplianceBody(doc as unknown as Record<string, unknown>, kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(201);
    expect(env.__store[`compliance:incident-report:${RRN}`]).toBeTruthy();
  });

  it("401 on tampered body", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const doc = buildIncidentReport(validReportInput());
    const signed = await signComplianceBody(doc as unknown as Record<string, unknown>, kp);
    const tampered = { ...signed, generated_at: "2099-01-01T00:00:00Z" };
    const res = await onRequest({ request: req("POST", tampered), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(401);
  });

  it("401 when robot not registered", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv();
    const doc = buildIncidentReport(validReportInput());
    const signed = await signComplianceBody(doc as unknown as Record<string, unknown>, kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(401);
  });

  it("400 on missing sig", async () => {
    const env = makeEnv({ [`robot:${RRN}`]: "{}" });
    const res = await onRequest({ request: req("POST", { schema: INCIDENT_REPORT_SCHEMA, rrn: RRN, pq_kid: "x" }), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(400);
  });

  it("400 on wrong schema string", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const signed = await signComplianceBody({ schema: "rcan-ifu-v1", rrn: RRN, generated_at: "x" }, kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(400);
  });

  it("400 on doc.rrn != URL rrn", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const doc = buildIncidentReport(validReportInput("RRN-000000000999"));
    const signed = await signComplianceBody(doc as unknown as Record<string, unknown>, kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(400);
  });

  it("stores history entry on successful POST", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const doc = buildIncidentReport(validReportInput());
    const signed = await signComplianceBody(doc as unknown as Record<string, unknown>, kp);
    await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(Object.keys(env.__store).filter(k => k.startsWith(`compliance:incident-report:history:${RRN}:`)).length).toBe(1);
  });

  it("returns 405 on PUT", async () => {
    const env = makeEnv();
    const res = await onRequest({ request: req("PUT"), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(405);
  });
});
