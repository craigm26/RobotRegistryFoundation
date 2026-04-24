import { describe, it, expect, vi } from "vitest";
import {
  buildSafetyBenchmark, buildIfu, buildIncidentReport, buildEuRegisterEntry,
  SAFETY_BENCHMARK_SCHEMA, IFU_SCHEMA, INCIDENT_REPORT_SCHEMA, EU_REGISTER_SCHEMA,
} from "rcan-ts";
import { onRequest as sbHandler } from "../functions/v2/robots/[rrn]/safety-benchmark.js";
import { onRequest as ifuHandler } from "../functions/v2/robots/[rrn]/ifu.js";
import { onRequest as friaHandler } from "../functions/v2/robots/[rrn]/fria.js";
import { onRequest as incHandler } from "../functions/v2/robots/[rrn]/incident-report.js";
import { signComplianceBody, makeTestKeypair, makeRobotRecord } from "../functions/v2/_lib/test-helpers.js";

const RRN = "RRN-000000000001";
const FRIA_SCHEMA = "rcan-fria-v1";

function makeSharedEnv() {
  const store: Record<string, string> = {};
  return {
    RRF_KV: {
      get: vi.fn(async (k: string) => store[k] ?? null),
      put: vi.fn(async (k: string, v: string) => { store[k] = v; }),
      list: vi.fn(), delete: vi.fn(),
    } as unknown as KVNamespace,
    __store: store,
  };
}

function mkReq(method: string, path: string, body?: unknown, headers: Record<string, string> = {}): Request {
  return new Request(`https://x${path}`, {
    method,
    headers: { "Content-Type": "application/json", ...headers },
    body: body ? JSON.stringify(body) : undefined,
  });
}

describe("compliance intake end-to-end smoke", () => {
  it("round-trips all five §22-26 endpoints with a single registered robot", async () => {
    const kp = await makeTestKeypair();
    const env = makeSharedEnv();
    env.__store[`robot:${RRN}`] = makeRobotRecord(RRN, kp);

    // §23 Safety Benchmark — public GET
    {
      const doc = buildSafetyBenchmark({
        iterations: 100,
        thresholds: { "discover_p95_ms": 500 },
        results: { discover: { min_ms: 10, mean_ms: 50, p95_ms: 120, p99_ms: 180, max_ms: 220, pass: true } },
        mode: "synthetic",
        generated_at: "2026-04-23T00:00:00Z",
        overall_pass: true,
      });
      const signed = await signComplianceBody(doc as unknown as Record<string, unknown>, kp);
      const postRes = await sbHandler({ request: mkReq("POST", `/v2/robots/${RRN}/safety-benchmark`, signed), env, params: { rrn: RRN } } as any);
      expect(postRes.status).toBe(201);
      const getRes = await sbHandler({ request: mkReq("GET", `/v2/robots/${RRN}/safety-benchmark`), env, params: { rrn: RRN } } as any);
      expect(getRes.status).toBe(200);
      const retrieved = await getRes.json() as any;
      expect(retrieved.schema).toBe(SAFETY_BENCHMARK_SCHEMA);
      expect(retrieved.overall_pass).toBe(true);
    }

    // §24 IFU — public GET
    {
      const doc = buildIfu({
        provider_identity: { name: "Smoke Test Provider" },
        intended_purpose: { description: "smoke" },
        capabilities_and_limitations: { capabilities: ["x"] },
        accuracy_and_performance: { positional_accuracy_mm: 1.0 },
        human_oversight_measures: { oversight: "present" },
        known_risks_and_misuse: { risks: [] },
        expected_lifetime: { years: 5 },
        maintenance_requirements: { schedule: "monthly" },
        generated_at: "2026-04-23T00:00:00Z",
      });
      const signed = await signComplianceBody(doc as unknown as Record<string, unknown>, kp);
      const postRes = await ifuHandler({ request: mkReq("POST", `/v2/robots/${RRN}/ifu`, signed), env, params: { rrn: RRN } } as any);
      expect(postRes.status).toBe(201);
      const getRes = await ifuHandler({ request: mkReq("GET", `/v2/robots/${RRN}/ifu`), env, params: { rrn: RRN } } as any);
      expect(getRes.status).toBe(200);
      expect(((await getRes.json()) as any).schema).toBe(IFU_SCHEMA);
    }

    // §22 FRIA — Bearer-gated GET
    {
      const friaDoc = {
        schema: FRIA_SCHEMA,
        generated_at: "2026-04-23T00:00:00Z",
        system: { rrn: RRN, robot_name: "smoke", rcan_version: "3.0" },
        deployment: { annex_iii_basis: "Annex III(5)(b)" },
        signing_key: { alg: "ml-dsa-65", kid: "abcd1234", public_key: "stub-base64" },
        conformance: null,
      };
      const signed = await signComplianceBody(friaDoc, kp);
      const postRes = await friaHandler({ request: mkReq("POST", `/v2/robots/${RRN}/fria`, signed), env, params: { rrn: RRN } } as any);
      expect(postRes.status).toBe(201);

      const noAuth = await friaHandler({ request: mkReq("GET", `/v2/robots/${RRN}/fria`), env, params: { rrn: RRN } } as any);
      expect(noAuth.status).toBe(401);

      const getRes = await friaHandler({ request: mkReq("GET", `/v2/robots/${RRN}/fria`, undefined, { Authorization: "Bearer t" }), env, params: { rrn: RRN } } as any);
      expect(getRes.status).toBe(200);
    }

    // §25 Incident Report — Bearer-gated GET
    {
      const doc = buildIncidentReport({
        rrn: RRN,
        incidents: [{ timestamp: "2026-04-10T12:00:00Z", severity: "other", description: "jam" }],
        generated_at: "2026-04-23T00:00:00Z",
      });
      const signed = await signComplianceBody(doc as unknown as Record<string, unknown>, kp);
      const postRes = await incHandler({ request: mkReq("POST", `/v2/robots/${RRN}/incident-report`, signed), env, params: { rrn: RRN } } as any);
      expect(postRes.status).toBe(201);

      const getRes = await incHandler({ request: mkReq("GET", `/v2/robots/${RRN}/incident-report`, undefined, { Authorization: "Bearer t" }), env, params: { rrn: RRN } } as any);
      expect(getRes.status).toBe(200);
      expect(((await getRes.json()) as any).schema).toBe(INCIDENT_REPORT_SCHEMA);
    }

    // §26 EU Register — public GET, X-Submitter-RRN header, per-model route
    {
      const { onRequest: euHandler } = await import("../functions/v2/models/[rmn]/eu-register.js");
      const RMN = "RMN-000000000007";
      const doc = buildEuRegisterEntry({
        rmn: RMN,
        fria_ref: "bob-fria-v1.json",
        provider: { name: "smoke", contact: "smoke@example.com" },
        system: { rrn: RRN, robot_name: "smoke", rcan_version: "3.1" },
        annex_iii_basis: "Annex III §5(b)",
        generated_at: "2026-04-24T00:00:00Z",
      });
      const signed = await signComplianceBody(doc as unknown as Record<string, unknown>, kp);
      const postRes = await euHandler({
        request: mkReq("POST", `/v2/models/${RMN}/eu-register`, signed, { "X-Submitter-RRN": RRN }),
        env, params: { rmn: RMN },
      } as any);
      expect(postRes.status).toBe(201);
      const getRes = await euHandler({ request: mkReq("GET", `/v2/models/${RMN}/eu-register`), env, params: { rmn: RMN } } as any);
      expect(getRes.status).toBe(200);
      const retrieved = await getRes.json() as any;
      expect(retrieved.schema).toBe(EU_REGISTER_SCHEMA);
      expect(retrieved.rmn).toBe(RMN);
      expect(retrieved._submitted_by_rrn).toBe(RRN);
    }
  });
});
