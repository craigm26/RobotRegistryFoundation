import { describe, it, expect, vi } from "vitest";
import { isRevoked, markRevoked } from "./revocation.js";

const RRN = "RRN-000000000042";

function makeEnv() {
  const store: Record<string, string> = {};
  return {
    RRF_KV: {
      get: vi.fn(async (k: string) => store[k] ?? null),
      put: vi.fn(async (k: string, v: string) => { store[k] = v; }),
      delete: vi.fn(async (k: string) => { delete store[k]; }),
      list: vi.fn(),
    } as unknown as KVNamespace,
    __store: store,
  };
}

describe("revocation helper", () => {
  it("isRevoked returns false when no revocation entry", async () => {
    const env = makeEnv();
    expect(await isRevoked(env, RRN)).toBe(false);
  });

  it("markRevoked writes a revocation entry that isRevoked observes", async () => {
    const env = makeEnv();
    await markRevoked(env, RRN, "operator request");
    expect(await isRevoked(env, RRN)).toBe(true);
    const raw = JSON.parse(env.__store[`revocation:${RRN}`]);
    expect(raw.reason).toBe("operator request");
    expect(raw.revoked_at).toBeTypeOf("string");
  });

  it("isRevoked tolerates malformed revocation blobs (treat as revoked)", async () => {
    const env = makeEnv();
    env.__store[`revocation:${RRN}`] = "not-json";
    expect(await isRevoked(env, RRN)).toBe(true);
  });
});
