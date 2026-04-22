import { describe, it, expect, vi } from "vitest";
import { onRequestGet, onRequestPatch } from "./index.js";

const RRN = "RRN-000000000042";
const API_KEY = "test-apikey-xyz";
const UNSIGNED_RECORD = {
  rrn: RRN, name: "x", manufacturer: "y", model: "z",
  firmware_version: "1.0", rcan_version: "3.0",
  api_key: API_KEY, registered_at: "2026-04-01T00:00:00Z",
};

function makeEnv(stored: any = UNSIGNED_RECORD) {
  const store: Record<string, string> = stored ? { [`robot:${RRN}`]: JSON.stringify(stored) } : {};
  return {
    RRF_KV: {
      get: vi.fn(async (k: string) => store[k] ?? null),
      put: vi.fn(async (k: string, v: string) => { store[k] = v; }),
      list: vi.fn(),
      delete: vi.fn(),
    },
    __store: store,
  };
}

function makePatchRequest(body: unknown, apiKey = API_KEY): Request {
  return new Request(`https://x/v2/robots/${RRN}`, {
    method: "PATCH",
    headers: { "Authorization": `Bearer ${apiKey}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

// Stand-in body shape — uses real-looking base64 but doesn't need to verify
// (happy-path sig-verify lands in Task 5). Just exercises shape + auth paths.
const STUB_PATCH_BODY = {
  pq_signing_pub: "stub-pub-base64",
  pq_kid: "abcd1234",
  sig: {
    ml_dsa: "stub-ml-dsa-sig",
    ed25519: "stub-ed25519-sig",
    ed25519_pub: "stub-ed25519-pub",
  },
};

describe("PATCH /v2/robots/[rrn]", () => {
  it("rejects missing bearer token (401)", async () => {
    const env = makeEnv();
    const req = new Request(`https://x/v2/robots/${RRN}`, {
      method: "PATCH", body: JSON.stringify(STUB_PATCH_BODY),
    });
    const res = await onRequestPatch({ request: req, env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(401);
  });

  it("rejects wrong bearer token (403)", async () => {
    const env = makeEnv();
    const res = await onRequestPatch({
      request: makePatchRequest(STUB_PATCH_BODY, "wrong-key"),
      env, params: { rrn: RRN },
    } as any);
    expect(res.status).toBe(403);
  });

  it("returns 404 when RRN does not exist", async () => {
    const env = makeEnv(null);
    const res = await onRequestPatch({
      request: makePatchRequest(STUB_PATCH_BODY),
      env, params: { rrn: RRN },
    } as any);
    expect(res.status).toBe(404);
  });

  it("returns 409 when record already has pq_signing_pub (rotation not supported)", async () => {
    const alreadySigned = { ...UNSIGNED_RECORD, pq_signing_pub: "existing-key", pq_kid: "abcd1234" };
    const env = makeEnv(alreadySigned);
    const res = await onRequestPatch({
      request: makePatchRequest(STUB_PATCH_BODY),
      env, params: { rrn: RRN },
    } as any);
    expect(res.status).toBe(409);
  });

  it("returns 400 when body is missing pq_signing_pub / pq_kid / sig", async () => {
    const env = makeEnv();
    const res = await onRequestPatch({
      request: makePatchRequest({ pq_kid: "xx" }),
      env, params: { rrn: RRN },
    } as any);
    expect(res.status).toBe(400);
  });

  it("returns 400 when sig has bogus (unverifiable) bytes", async () => {
    // Stub base64 strings don't decode to valid sig bytes — verify returns false
    const env = makeEnv();
    const res = await onRequestPatch({
      request: makePatchRequest(STUB_PATCH_BODY),
      env, params: { rrn: RRN },
    } as any);
    expect(res.status).toBe(400);
  });
});

describe("GET /v2/robots/[rrn]", () => {
  it("returns the record by RRN", async () => {
    const env = makeEnv();
    const res = await onRequestGet({ env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.rrn).toBe(RRN);
  });

  it("returns 404 for unknown RRN", async () => {
    const env = makeEnv(null);
    const res = await onRequestGet({ env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(404);
  });
});
