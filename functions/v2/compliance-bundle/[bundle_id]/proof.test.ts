// functions/v2/compliance-bundle/[bundle_id]/proof.test.ts
import { describe, it, expect, vi } from "vitest";
import { onRequestGet } from "./proof.js";

function makeEnv(initial: Record<string, string> = {}) {
  const store = { ...initial };
  return {
    RRF_KV: {
      get: vi.fn(async (k: string) => store[k] ?? null),
      put: vi.fn(),
      list: vi.fn(async ({ prefix }: { prefix: string }) => ({
        keys: Object.keys(store).filter(k => k.startsWith(prefix)).map(name => ({ name })),
        list_complete: true,
      })),
      delete: vi.fn(),
    } as unknown as KVNamespace,
  };
}

describe("GET /v2/compliance-bundle/{id}/proof", () => {
  it("returns 404 when bundle is not in the log", async () => {
    const env = { RRF_KV: makeEnv().RRF_KV };
    const res = await onRequestGet({
      env,
      request: new Request("https://x"),
      params: { bundle_id: "bundle_nonexistent" },
    } as any);
    expect(res.status).toBe(404);
  });

  it("returns 400 when bundle_id is malformed", async () => {
    const env = { RRF_KV: makeEnv().RRF_KV };
    const res = await onRequestGet({
      env,
      request: new Request("https://x"),
      params: { bundle_id: "not-a-bundle" },
    } as any);
    expect(res.status).toBe(400);
  });

  it("returns 200 + entry shape when bundle is in the log", async () => {
    const entry = {
      bundle_id: "bundle_test",
      rrn: "RRN-000000000002",
      schema_version: "1.0",
      signed_at: "2026-05-04T12:00:00Z",
      transparency_log_index: 42,
      bundle_signature: { kid: "k", alg: ["Ed25519", "ML-DSA-65"], sig: { ed25519: "x", ml_dsa: "y", ed25519_pub: "z" } },
      rrf_log_signature: { kid: "rrf-root", alg: "Ed25519", sig: "abc" },
    };
    const env = { RRF_KV: makeEnv({
      "compliance-bundle-log:000000000042": JSON.stringify(entry),
    }).RRF_KV };
    const res = await onRequestGet({
      env,
      request: new Request("https://x"),
      params: { bundle_id: "bundle_test" },
    } as any);
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.bundle_id).toBe("bundle_test");
    expect(body.transparency_log_index).toBe(42);
  });
});
