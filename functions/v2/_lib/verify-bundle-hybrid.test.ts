import { describe, it, expect, vi } from "vitest";
import { verifyBundleHybrid } from "./verify-bundle-hybrid.js";

function makeEnv(initial: Record<string, string> = {}) {
  const store = { ...initial };
  return {
    RRF_KV: {
      get: vi.fn(async (k: string) => store[k] ?? null),
      put: vi.fn(),
      list: vi.fn(async ({ prefix }: { prefix: string }) => ({
        keys: Object.keys(store).filter(k => k.startsWith(prefix)).map(name => ({ name })),
      })),
      delete: vi.fn(),
    } as unknown as KVNamespace,
  };
}

describe("verifyBundleHybrid", () => {
  it("returns 403 when kid does not resolve to any authority", async () => {
    const env = makeEnv();
    const payload = {
      schema_version: "1.0",
      bundle_id: "b1",
      rrn: "RRN-000000000002",
      signed_at: "2026-05-04T12:00:00Z",
      bundle_signature: { kid: "missing-kid", alg: ["Ed25519", "ML-DSA-65"], sig: { ed25519: "x", ml_dsa: "y", ed25519_pub: "z" } },
    };
    const r = await verifyBundleHybrid(env, payload);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.status).toBe(403);
  });

  it("returns 400 when bundle_signature is missing", async () => {
    const env = makeEnv();
    const r = await verifyBundleHybrid(env, { schema_version: "1.0", rrn: "RRN-000000000002", signed_at: "2026-05-04T12:00:00Z" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.status).toBe(400);
  });

  it("returns 400 when signed_at is not a string", async () => {
    const env = makeEnv();
    const payload = {
      schema_version: "1.0",
      rrn: "RRN-000000000002",
      signed_at: 12345,
      bundle_signature: { kid: "ops-aggregator-2026-05", alg: ["Ed25519", "ML-DSA-65"], sig: { ed25519: "x", ml_dsa: "y", ed25519_pub: "z" } },
    };
    const r = await verifyBundleHybrid(env, payload);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.status).toBe(400);
  });

  it("returns 400 when bundle_signature.sig is missing required fields", async () => {
    const env = makeEnv();
    const payload = {
      schema_version: "1.0",
      rrn: "RRN-000000000002",
      signed_at: "2026-05-04T12:00:00Z",
      bundle_signature: { kid: "ops-aggregator-2026-05", alg: ["Ed25519", "ML-DSA-65"], sig: { ed25519: "x" } },
    };
    const r = await verifyBundleHybrid(env, payload);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.status).toBe(400);
  });

  // Happy-path hybrid verification is exercised end-to-end in Task 14's
  // smoke test (which mints real test keypairs + signs + posts + verifies).
});
