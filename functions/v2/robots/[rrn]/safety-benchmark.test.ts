import { describe, it, expect, vi } from "vitest";
import { onRequest } from "./safety-benchmark.js";
import { buildSafetyBenchmark, SAFETY_BENCHMARK_SCHEMA } from "rcan-ts";
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
  return new Request(`https://x/v2/robots/${RRN}/safety-benchmark`, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
}

function validBenchmarkInput() {
  return {
    iterations: 100,
    thresholds: { "discover_p95_ms": 500, "status_p95_ms": 250 },
    results: {
      discover: { min_ms: 10, mean_ms: 50, p95_ms: 120, p99_ms: 180, max_ms: 220, pass: true },
      status:   { min_ms: 5,  mean_ms: 20, p95_ms: 40,  p99_ms: 80,  max_ms: 100, pass: true },
    },
    mode: "synthetic",
    generated_at: "2026-04-23T00:00:00Z",
    overall_pass: true,
  };
}

describe("GET /v2/robots/[rrn]/safety-benchmark", () => {
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

  it("returns stored doc with cache header when present", async () => {
    const env = makeEnv({ [`compliance:safety-benchmark:${RRN}`]: JSON.stringify({ schema: SAFETY_BENCHMARK_SCHEMA }) });
    const res = await onRequest({ request: req("GET"), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toContain("max-age=300");
  });
});

describe("POST /v2/robots/[rrn]/safety-benchmark", () => {
  it("stores and returns 201 on valid submission", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const doc = buildSafetyBenchmark(validBenchmarkInput());
    const signed = await signComplianceBody(doc as unknown as Record<string, unknown>, kp);

    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(201);

    const body = await res.json() as any;
    expect(body.ok).toBe(true);
    expect(body.rrn).toBe(RRN);

    expect(env.__store[`compliance:safety-benchmark:${RRN}`]).toBeTruthy();
    const historyKeys = Object.keys(env.__store).filter(k => k.startsWith(`compliance:safety-benchmark:history:${RRN}:`));
    expect(historyKeys.length).toBe(1);
  });

  it("401 on tampered body", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const doc = buildSafetyBenchmark(validBenchmarkInput());
    const signed = await signComplianceBody(doc as unknown as Record<string, unknown>, kp);
    const tampered = { ...signed, mode: "hardware" };  // flip a signed field
    const res = await onRequest({ request: req("POST", tampered), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(401);
  });

  it("401 when robot not registered", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv();
    const doc = buildSafetyBenchmark(validBenchmarkInput());
    const signed = await signComplianceBody(doc as unknown as Record<string, unknown>, kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(401);
  });

  it("400 on missing sig", async () => {
    const env = makeEnv({ [`robot:${RRN}`]: "{}" });
    const res = await onRequest({ request: req("POST", { schema: SAFETY_BENCHMARK_SCHEMA, pq_kid: "x" }), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(400);
  });

  it("400 on wrong schema string", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const signed = await signComplianceBody({ schema: "rcan-ifu-v1", generated_at: "x" }, kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toContain(SAFETY_BENCHMARK_SCHEMA);
  });
});

describe("EV cross-reference (RCAN Appendix C)", () => {
  it("stores ev_tests_covered and echoes it as self-reported", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const doc = { ...buildSafetyBenchmark(validBenchmarkInput()), ev_tests_covered: ["EV-05", "EV-08"] };
    const signed = await signComplianceBody(doc as unknown as Record<string, unknown>, kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(201);
    const body = await res.json() as any;
    expect(body.ev_tests_covered).toEqual(["EV-05", "EV-08"]);
    expect(body.ev_tests_basis).toMatch(/self-reported/);
    expect(body.ev_tests_basis).toMatch(/not run or checked/);
    expect(JSON.parse(env.__store[`compliance:safety-benchmark:${RRN}`]).ev_tests_covered).toEqual(["EV-05", "EV-08"]);
  });

  it("omits the EV fields when the submission has none", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const signed = await signComplianceBody(buildSafetyBenchmark(validBenchmarkInput()) as unknown as Record<string, unknown>, kp);
    const body = await (await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any)).json() as any;
    expect(body.ev_tests_covered).toBeUndefined();
  });

  it("rejects unknown or duplicate EV IDs", async () => {
    const kp = await makeTestKeypair();
    for (const bad of [["EV-10"], ["EV-01", "EV-01"], [], "EV-01"]) {
      const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
      const doc = { ...buildSafetyBenchmark(validBenchmarkInput()), ev_tests_covered: bad };
      const signed = await signComplianceBody(doc as unknown as Record<string, unknown>, kp);
      const res = await onRequest({ request: req("POST", signed), env, params: { rrn: RRN } } as any);
      expect(res.status, JSON.stringify(bad)).toBe(400);
      expect(env.__store[`compliance:safety-benchmark:${RRN}`]).toBeUndefined();
    }
  });
});

describe("method handling", () => {
  it("returns 405 on PUT", async () => {
    const env = makeEnv();
    const res = await onRequest({ request: req("PUT"), env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(405);
  });
});
