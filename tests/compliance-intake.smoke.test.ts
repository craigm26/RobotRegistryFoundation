import { describe, it, expect, vi } from "vitest";
import {
  buildSafetyBenchmark, buildIfu, buildIncidentReport, buildEuRegisterEntry,
  SAFETY_BENCHMARK_SCHEMA, IFU_SCHEMA, INCIDENT_REPORT_SCHEMA, EU_REGISTER_SCHEMA,
  canonicalJson, signMlDsa,
} from "rcan-ts";
import { ed25519 } from "@noble/curves/ed25519.js";
import { onRequest as sbHandler } from "../functions/v2/robots/[rrn]/safety-benchmark.js";
import { onRequest as ifuHandler } from "../functions/v2/robots/[rrn]/ifu.js";
import { onRequest as friaHandler } from "../functions/v2/robots/[rrn]/fria.js";
import { onRequest as incHandler } from "../functions/v2/robots/[rrn]/incident-report.js";
import { onRequestPost as bundlePostHandler } from "../functions/v2/compliance-bundle/index.js";
import { onRequestGet as bundleProofHandler } from "../functions/v2/compliance-bundle/[bundle_id]/proof.js";
import { onRequestGet as bundleFullHandler } from "../functions/v2/compliance-bundle/[bundle_id]/index.js";
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

// ---------------------------------------------------------------------------
// /v2/compliance-bundle round-trip (Plan 4 Task 14)
//
// Independent describe block (separate from §22-26 smoke). Exercises the full
// hybrid-signed bundle intake: POST 201, POST again 409, GET /proof unauth
// 200, GET full no-auth 401, GET full with M2M_TRUSTED JWT 200.
//
// Hybrid sign manually (canonicalJson + ed25519.sign + signMlDsa) to mirror
// what opencastor-ops Phase A `_Signer` produces. Using rcan-ts.signBody would
// inject pq_signing_pub + pq_kid into the canonical bytes that the Phase A
// aggregator (and Task 8 verifier) do NOT include — third deviation in this
// branch, after Tasks 6 and 8.
// ---------------------------------------------------------------------------

function makeBundleEnv() {
  const store: Record<string, string> = {};
  return {
    RRF_KV: {
      get: vi.fn(async (k: string) => store[k] ?? null),
      put: vi.fn(async (k: string, v: string) => { store[k] = v; }),
      list: vi.fn(async ({ prefix }: { prefix: string; cursor?: string }) => {
        // Single-page mock — sufficient for tests that create 1-2 bundles.
        const keys = Object.keys(store)
          .filter(k => k.startsWith(prefix))
          .map(name => ({ name }));
        return { keys, list_complete: true, cursor: undefined };
      }),
      delete: vi.fn(),
    } as unknown as KVNamespace,
    __store: store,
  };
}

describe("compliance-bundle intake end-to-end smoke", () => {
  it("rounds-trips a hybrid-signed bundle through POST + GET-full + GET-proof", async () => {
    const kp = await makeTestKeypair();
    const env = makeBundleEnv();
    const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));

    // 1. Pre-populate KV: authority record (carries the verifier's trust anchors).
    const RAN = "RAN-000000000001";
    const BUNDLE_RRN = "RRN-000000000002";
    const KID = "ops-aggregator-test";
    env.__store[`authority:${RAN}`] = JSON.stringify({
      ran: RAN,
      organization: "OpenCastor Ops",
      signing_pub: b64(kp.ed25519Public),
      pq_signing_pub: b64(kp.mlDsa.publicKey),
    });
    env.__store[`kid:${KID}:2026-01-01T00:00:00Z`] = JSON.stringify({
      ran: RAN,
      valid_from: "2026-01-01T00:00:00Z",
      registered_at: "2026-01-01T00:00:00Z",
      registered_by: RAN,
    });
    env.__store[`aggregator-scope:${RAN}/${BUNDLE_RRN}`] = JSON.stringify({
      ran: RAN, rrn: BUNDLE_RRN,
      authorized_at: "2026-01-01T00:00:00Z",
      authorized_by: RAN,
    });

    // 2. RRF root keypair (mint inline; for proof signing + JWT verify).
    const rrfKp = await crypto.subtle.generateKey(
      { name: "Ed25519" }, true, ["sign", "verify"],
    ) as CryptoKeyPair;
    const rrfPrivDer = await crypto.subtle.exportKey("pkcs8", rrfKp.privateKey);
    const rrfPubDer = await crypto.subtle.exportKey("spki", rrfKp.publicKey);
    const bufB64 = (buf: ArrayBuffer) =>
      btoa(String.fromCharCode(...new Uint8Array(buf)));
    env.__store["rrf:root:privkey"] = bufB64(rrfPrivDer);
    env.__store["rrf:root:pubkey"] =
      `-----BEGIN PUBLIC KEY-----\n${bufB64(rrfPubDer)}\n-----END PUBLIC KEY-----\n`;

    // 3. Build the bundle (without bundle_signature). Sign canonical bytes.
    const bundleId = "bundle_smoke_test_001";
    const bundle: Record<string, unknown> = {
      schema_version: "1.0",
      bundle_id: bundleId,
      rrn: BUNDLE_RRN,
      signed_at: "2026-05-04T12:00:00Z",
      robot_md_sha256: "deadbeef",
      matrix_version: "1.0",
      artifacts: [
        { artifact_type: "cert-gateway-authority", payload: {} },
        { artifact_type: "eu-act-fria", payload: {} },
        { artifact_type: "version-matrix-snapshot", payload: {} },
      ],
    };
    const canon = canonicalJson(bundle);
    const ed25519Sig = ed25519.sign(canon, kp.ed25519Secret);
    const mlDsaSig = signMlDsa(kp.mlDsa.privateKey, canon);
    bundle["bundle_signature"] = {
      kid: KID,
      alg: ["Ed25519", "ML-DSA-65"],
      sig: {
        ed25519: b64(ed25519Sig),
        ml_dsa: b64(mlDsaSig),
        ed25519_pub: b64(kp.ed25519Public),
      },
    };

    // 4. POST -> 201.
    const postRes = await bundlePostHandler({
      env, request: new Request("https://x/v2/compliance-bundle", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(bundle),
      }),
    } as any);
    if (postRes.status !== 201) {
      const errBody = await postRes.text();
      throw new Error(`Expected 201, got ${postRes.status}: ${errBody}`);
    }
    const postBody = await postRes.json() as any;
    expect(postBody.bundle_id).toBe(bundleId);
    expect(postBody.rrn).toBe(BUNDLE_RRN);
    expect(typeof postBody.transparency_log_index).toBe("number");

    // 5. POST again -> 409.
    const dupRes = await bundlePostHandler({
      env, request: new Request("https://x/v2/compliance-bundle", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(bundle),
      }),
    } as any);
    expect(dupRes.status).toBe(409);

    // 6. GET /proof unauthenticated -> 200, returns rrf_log_signature.
    const proofRes = await bundleProofHandler({
      env, request: new Request(`https://x/v2/compliance-bundle/${bundleId}/proof`),
      params: { bundle_id: bundleId },
    } as any);
    expect(proofRes.status).toBe(200);
    const proof = await proofRes.json() as any;
    expect(proof.bundle_id).toBe(bundleId);
    expect(proof.rrf_log_signature).toBeDefined();
    expect(proof.rrf_log_signature.kid).toBe("rrf-root");

    // 7. GET full WITHOUT JWT -> 401.
    const noAuthRes = await bundleFullHandler({
      env, request: new Request(`https://x/v2/compliance-bundle/${bundleId}`),
      params: { bundle_id: bundleId },
    } as any);
    expect(noAuthRes.status).toBe(401);

    // 8. Mint M2M_TRUSTED JWT (matches the production mint at
    //    functions/v2/orchestrators/[id]/token.ts:80-110).
    //    Signing input = b64u(header).b64u(payload-MINUS-rrf_sig); the emitted
    //    JWT's parts[1] embeds rrf_sig back. jwt-verify reconstructs by
    //    stripping rrf_sig before recomputing the signing input.
    const jwtHeader = { alg: "EdDSA", typ: "JWT" };
    const jwtPayloadCore = {
      sub: "test-orch",
      iss: "rrf.rcan.dev",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      rcan_role: "m2m_trusted",
      rcan_scopes: ["fleet.trusted"],
      fleet_rrns: [BUNDLE_RRN],
    };
    const b64url = (s: string) =>
      btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    const signingInput =
      `${b64url(JSON.stringify(jwtHeader))}.${b64url(JSON.stringify(jwtPayloadCore))}`;
    const enc = new TextEncoder();
    const sigBuf = await crypto.subtle.sign(
      "Ed25519", rrfKp.privateKey, enc.encode(signingInput),
    );
    const jwtSig = btoa(String.fromCharCode(...new Uint8Array(sigBuf)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    const jwtPayloadWithSig = { ...jwtPayloadCore, rrf_sig: jwtSig };
    const jwt =
      `${b64url(JSON.stringify(jwtHeader))}.${b64url(JSON.stringify(jwtPayloadWithSig))}.${jwtSig}`;

    // 9. GET full WITH JWT -> 200, returns full payload incl artifacts.
    const authRes = await bundleFullHandler({
      env, request: new Request(`https://x/v2/compliance-bundle/${bundleId}`, {
        headers: { Authorization: `Bearer ${jwt}` },
      }),
      params: { bundle_id: bundleId },
    } as any);
    if (authRes.status !== 200) {
      const errBody = await authRes.text();
      throw new Error(
        `Expected GET-full 200 with JWT, got ${authRes.status}: ${errBody}`,
      );
    }
    const fullBundle = await authRes.json() as any;
    expect(fullBundle.bundle_id).toBe(bundleId);
    expect(fullBundle.artifacts).toHaveLength(3);
  });
});
