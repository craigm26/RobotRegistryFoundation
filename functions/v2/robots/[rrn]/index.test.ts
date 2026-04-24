import { describe, it, expect, vi } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve, dirname } from "node:path";
import { onRequestDelete, onRequestGet, onRequestPatch } from "./index.js";

const RRN = "RRN-000000000042";
const API_KEY = "test-apikey-xyz";
const UNSIGNED_RECORD = {
  rrn: RRN, name: "x", manufacturer: "y", model: "z",
  firmware_version: "1.0", rcan_version: "3.0",
  api_key: API_KEY, registered_at: "2026-04-01T00:00:00Z",
};

const __dirname = dirname(fileURLToPath(import.meta.url));
const patchFx = JSON.parse(
  readFileSync(resolve(__dirname, "../../../_lib/fixtures/patch-fixture.json"), "utf8"),
);

function makeEnv(stored: any = UNSIGNED_RECORD) {
  const store: Record<string, string> = stored ? { [`robot:${RRN}`]: JSON.stringify(stored) } : {};
  return {
    RRF_KV: {
      get: vi.fn(async (k: string) => store[k] ?? null),
      put: vi.fn(async (k: string, v: string) => { store[k] = v; }),
      list: vi.fn(),
      delete: vi.fn(async (k: string) => { delete store[k]; }),
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

  it("returns 403 when record is revoked", async () => {
    const env = makeEnv();
    env.__store[`revocation:${RRN}`] = JSON.stringify({ revoked_at: "2026-04-24T00:00:00Z", reason: "test" });
    const res = await onRequestPatch({
      request: makePatchRequest(STUB_PATCH_BODY),
      env, params: { rrn: RRN },
    } as any);
    expect(res.status).toBe(403);
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

  it("surfaces revoked flag + revoked_at when a revocation entry exists", async () => {
    const env = makeEnv();
    env.__store[`revocation:${RRN}`] = JSON.stringify({ revoked_at: "2026-04-24T00:00:00Z", reason: "test" });
    const res = await onRequestGet({ env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.revoked).toBe(true);
    expect(json.revoked_at).toBe("2026-04-24T00:00:00Z");
  });

  it("omits revoked flag when no revocation entry", async () => {
    const env = makeEnv();
    const res = await onRequestGet({ env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.revoked).toBeUndefined();
    expect(json.revoked_at).toBeUndefined();
  });
});

describe("DELETE /v2/robots/[rrn]", () => {
  function makeDeleteRequest(apiKey: string | null): Request {
    const headers: Record<string, string> = { "Accept": "application/json" };
    if (apiKey !== null) headers["Authorization"] = `Bearer ${apiKey}`;
    return new Request(`https://x/v2/robots/${RRN}`, { method: "DELETE", headers });
  }

  it("rejects missing bearer token (401)", async () => {
    const env = makeEnv();
    const res = await onRequestDelete({
      request: makeDeleteRequest(null),
      env, params: { rrn: RRN },
    } as any);
    expect(res.status).toBe(401);
  });

  it("rejects wrong bearer token (403) and keeps record intact", async () => {
    const env = makeEnv();
    const res = await onRequestDelete({
      request: makeDeleteRequest("wrong-key"),
      env, params: { rrn: RRN },
    } as any);
    expect(res.status).toBe(403);
    expect(env.__store[`robot:${RRN}`]).toBeDefined();
  });

  it("returns 404 when RRN does not exist", async () => {
    const env = makeEnv(null);
    const res = await onRequestDelete({
      request: makeDeleteRequest(API_KEY),
      env, params: { rrn: RRN },
    } as any);
    expect(res.status).toBe(404);
  });

  it("returns 400 for invalid RRN format", async () => {
    const env = makeEnv();
    const res = await onRequestDelete({
      request: makeDeleteRequest(API_KEY),
      env, params: { rrn: "not-an-rrn" },
    } as any);
    expect(res.status).toBe(400);
  });

  it("deletes the record on valid auth (204) and removes it from KV", async () => {
    const env = makeEnv();
    const res = await onRequestDelete({
      request: makeDeleteRequest(API_KEY),
      env, params: { rrn: RRN },
    } as any);
    expect(res.status).toBe(204);
    expect(env.__store[`robot:${RRN}`]).toBeUndefined();
    expect(env.RRF_KV.delete).toHaveBeenCalledWith(`robot:${RRN}`);
  });

  it("second delete returns 404 (not idempotent silent-success)", async () => {
    const env = makeEnv();
    await onRequestDelete({
      request: makeDeleteRequest(API_KEY),
      env, params: { rrn: RRN },
    } as any);
    const res = await onRequestDelete({
      request: makeDeleteRequest(API_KEY),
      env, params: { rrn: RRN },
    } as any);
    expect(res.status).toBe(404);
  });
});

describe("PATCH /v2/robots/[rrn] — whitelisted field updates (no pq_signing_pub in body)", () => {
  const SIGNED_RECORD = {
    ...UNSIGNED_RECORD,
    pq_signing_pub: "existing-key-base64",
    pq_kid: "abcd1234",
  };

  it("updates rcan_version on a signed record (200)", async () => {
    const env = makeEnv(SIGNED_RECORD);
    const res = await onRequestPatch({
      request: makePatchRequest({ rcan_version: "3.2" }),
      env, params: { rrn: RRN },
    } as any);
    expect(res.status).toBe(200);
    const updated = await res.json();
    expect(updated.rcan_version).toBe("3.2");
    expect(updated.updated_at).toBeDefined();
    const stored = JSON.parse(env.__store[`robot:${RRN}`]);
    expect(stored.rcan_version).toBe("3.2");
  });

  it("updates firmware_version", async () => {
    const env = makeEnv(SIGNED_RECORD);
    const res = await onRequestPatch({
      request: makePatchRequest({ firmware_version: "1.2.3" }),
      env, params: { rrn: RRN },
    } as any);
    expect(res.status).toBe(200);
    expect(JSON.parse(env.__store[`robot:${RRN}`]).firmware_version).toBe("1.2.3");
  });

  it("updates ruri", async () => {
    const env = makeEnv(SIGNED_RECORD);
    const res = await onRequestPatch({
      request: makePatchRequest({ ruri: "rcan://new-host:7400/bob" }),
      env, params: { rrn: RRN },
    } as any);
    expect(res.status).toBe(200);
    expect(JSON.parse(env.__store[`robot:${RRN}`]).ruri).toBe("rcan://new-host:7400/bob");
  });

  it("updates multiple whitelisted fields in one PATCH", async () => {
    const env = makeEnv(SIGNED_RECORD);
    const res = await onRequestPatch({
      request: makePatchRequest({ rcan_version: "3.2", firmware_version: "2.0.0" }),
      env, params: { rrn: RRN },
    } as any);
    expect(res.status).toBe(200);
    const stored = JSON.parse(env.__store[`robot:${RRN}`]);
    expect(stored.rcan_version).toBe("3.2");
    expect(stored.firmware_version).toBe("2.0.0");
  });

  it("works on an unsigned record too (no pq_signing_pub gate for field updates)", async () => {
    const env = makeEnv();  // UNSIGNED_RECORD
    const res = await onRequestPatch({
      request: makePatchRequest({ rcan_version: "3.2" }),
      env, params: { rrn: RRN },
    } as any);
    expect(res.status).toBe(200);
  });

  it("rejects unknown / non-whitelisted fields (400)", async () => {
    const env = makeEnv(SIGNED_RECORD);
    const res = await onRequestPatch({
      request: makePatchRequest({ name: "evil-rename" }),
      env, params: { rrn: RRN },
    } as any);
    expect(res.status).toBe(400);
    const body = await res.json();
    expect((body.error as string).toLowerCase()).toMatch(/whitelist|allowed|field/);
    expect(env.__store[`robot:${RRN}`]).toBe(JSON.stringify(SIGNED_RECORD));
  });

  it("rejects non-string field values (400)", async () => {
    const env = makeEnv(SIGNED_RECORD);
    const res = await onRequestPatch({
      request: makePatchRequest({ rcan_version: 123 }),
      env, params: { rrn: RRN },
    } as any);
    expect(res.status).toBe(400);
  });

  it("rejects empty body (400 — must have at least one field)", async () => {
    const env = makeEnv(SIGNED_RECORD);
    const res = await onRequestPatch({
      request: makePatchRequest({}),
      env, params: { rrn: RRN },
    } as any);
    expect(res.status).toBe(400);
  });

  it("preserves existing pq_signing_pub when updating other fields", async () => {
    const env = makeEnv(SIGNED_RECORD);
    await onRequestPatch({
      request: makePatchRequest({ rcan_version: "3.2" }),
      env, params: { rrn: RRN },
    } as any);
    const stored = JSON.parse(env.__store[`robot:${RRN}`]);
    expect(stored.pq_signing_pub).toBe("existing-key-base64");
    expect(stored.pq_kid).toBe("abcd1234");
  });

  it("still requires bearer auth (401 without)", async () => {
    const env = makeEnv(SIGNED_RECORD);
    const req = new Request(`https://x/v2/robots/${RRN}`, {
      method: "PATCH", body: JSON.stringify({ rcan_version: "3.2" }),
    });
    const res = await onRequestPatch({ request: req, env, params: { rrn: RRN } } as any);
    expect(res.status).toBe(401);
  });

  it("still rejects wrong bearer (403)", async () => {
    const env = makeEnv(SIGNED_RECORD);
    const res = await onRequestPatch({
      request: makePatchRequest({ rcan_version: "3.2" }, "wrong-key"),
      env, params: { rrn: RRN },
    } as any);
    expect(res.status).toBe(403);
  });
});

describe("PATCH /v2/robots/[rrn] — happy path (real sig verify)", () => {
  it("accepts a valid Python-signed PATCH and updates the record", async () => {
    const env = makeEnv();  // fresh UNSIGNED_RECORD at RRN-000000000042 (matches fixture)
    const body = {
      pq_signing_pub: patchFx.pq_signing_pub,
      pq_kid: patchFx.pq_kid,
      sig: patchFx.sig,
    };
    const res = await onRequestPatch({
      request: makePatchRequest(body),
      env, params: { rrn: RRN },
    } as any);
    expect(res.status).toBe(200);
    const updated = await res.json();
    expect(updated.pq_signing_pub).toBe(patchFx.pq_signing_pub);
    expect(updated.pq_kid).toBe(patchFx.pq_kid);
    expect(updated.updated_at).toBeDefined();
  });

  it("rejects a PATCH with tampered ml_dsa signature (400)", async () => {
    const env = makeEnv();
    const badSig = { ...patchFx.sig, ml_dsa: "AAAA" + patchFx.sig.ml_dsa.slice(4) };
    const body = {
      pq_signing_pub: patchFx.pq_signing_pub,
      pq_kid: patchFx.pq_kid,
      sig: badSig,
    };
    const res = await onRequestPatch({
      request: makePatchRequest(body),
      env, params: { rrn: RRN },
    } as any);
    expect(res.status).toBe(400);
  });
});
