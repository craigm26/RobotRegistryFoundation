import { describe, it, expect, vi } from "vitest";
import { onRequest } from "./ifu.js";
import { buildIfu, IFU_SCHEMA } from "rcan-ts";
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

function req(method: string, body?: unknown): Request {
  return new Request(`https://x/v2/robots/${RRN}/ifu`, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
}

function validIfuInput() {
  return {
    provider_identity: { name: "Example Robotics", contact: "ops@example.com" },
    intended_purpose: { description: "SO-ARM101 pick-and-place in controlled lab environment" },
    capabilities_and_limitations: { capabilities: ["grasp", "place"], limitations: ["max payload 300g"] },
    accuracy_and_performance: { positional_accuracy_mm: 2.0 },
    human_oversight_measures: { oversight: "operator within 1m" },
    known_risks_and_misuse: { risks: ["Pinch hazard"] },
    expected_lifetime: { years: 5 },
    maintenance_requirements: { schedule: "Monthly servo calibration" },
    generated_at: "2026-04-23T00:00:00Z",
  };
}

describe("GET /v2/robots/[rrn]/ifu", () => {
  it("returns 404 when nothing submitted", async () => {
    const env = makeEnv();
    const res = await onRequest({ request: req("GET"), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(404);
  });

  it("returns 400 on invalid RRN format", async () => {
    const env = makeEnv();
    const res = await onRequest({ request: req("GET"), env, params: { rrn: "bad" } } as any);
    expect(res.status).toBe(400);
  });

  it("returns stored doc with cache header", async () => {
    const env = makeEnv({ [`compliance:ifu:${RRN}`]: JSON.stringify({ schema: IFU_SCHEMA }) });
    const res = await onRequest({ request: req("GET"), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toContain("max-age=300");
  });
});

describe("POST /v2/robots/[rrn]/ifu", () => {
  it("stores and returns 201 on valid submission", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const doc = buildIfu(validIfuInput());
    const signed = await signComplianceBody(doc as unknown as Record<string, unknown>, kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(201);
    expect(env.__store[`compliance:ifu:${RRN}`]).toBeTruthy();
    expect(Object.keys(env.__store).filter(k => k.startsWith(`compliance:ifu:history:${RRN}:`)).length).toBe(1);
  });

  it("401 on tampered body", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const doc = buildIfu(validIfuInput());
    const signed = await signComplianceBody(doc as unknown as Record<string, unknown>, kp);
    const tampered = { ...signed, generated_at: "2099-01-01T00:00:00Z" };
    const res = await onRequest({ request: req("POST", tampered), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(401);
  });

  it("401 when robot not registered", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv();
    const doc = buildIfu(validIfuInput());
    const signed = await signComplianceBody(doc as unknown as Record<string, unknown>, kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(401);
  });

  it("400 on missing sig", async () => {
    const env = makeEnv({ [`robot:${RRN}`]: "{}" });
    const res = await onRequest({ request: req("POST", { schema: IFU_SCHEMA, pq_kid: "x" }), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(400);
  });

  it("400 on wrong schema string", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const signed = await signComplianceBody({ schema: "rcan-safety-benchmark-v1", generated_at: "x" }, kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(400);
  });

  it("returns 405 on PUT", async () => {
    const env = makeEnv();
    const res = await onRequest({ request: req("PUT"), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(405);
  });
});
