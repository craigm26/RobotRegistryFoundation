import { describe, it, expect, vi } from "vitest";
import { assertAggregatorScopedFor } from "./aggregator-scope.js";
import type { AggregatorScope } from "./types.js";

function makeEnv(initial: Record<string, string> = {}) {
  const store: Record<string, string> = { ...initial };
  return {
    RRF_KV: {
      get: vi.fn(async (k: string) => store[k] ?? null),
      put: vi.fn(), list: vi.fn(), delete: vi.fn(),
    } as unknown as KVNamespace,
  };
}

describe("assertAggregatorScopedFor", () => {
  it("returns ok when scope mapping exists and is not expired", async () => {
    const scope: AggregatorScope = {
      ran: "RAN-000000000001",
      rrn: "RRN-000000000002",
      authorized_at: "2026-05-04T00:00:00Z",
      authorized_by: "RAN-000000000001",
    };
    const env = makeEnv({
      "aggregator-scope:RAN-000000000001/RRN-000000000002": JSON.stringify(scope),
    });
    const r = await assertAggregatorScopedFor(env, "RAN-000000000001", "RRN-000000000002");
    expect(r.ok).toBe(true);
  });

  it("returns 403 when no scope mapping exists", async () => {
    const env = makeEnv();
    const r = await assertAggregatorScopedFor(env, "RAN-000000000001", "RRN-000000000999");
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.status).toBe(403);
      expect(r.error).toMatch(/not authorized/i);
    }
  });

  it("returns 403 when scope is expired", async () => {
    const scope: AggregatorScope = {
      ran: "RAN-000000000001",
      rrn: "RRN-000000000002",
      authorized_at: "2025-01-01T00:00:00Z",
      authorized_by: "RAN-000000000001",
      valid_until: "2025-12-31T23:59:59Z",
    };
    const env = makeEnv({
      "aggregator-scope:RAN-000000000001/RRN-000000000002": JSON.stringify(scope),
    });
    const r = await assertAggregatorScopedFor(env, "RAN-000000000001", "RRN-000000000002");
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.status).toBe(403);
      expect(r.error).toMatch(/expired/i);
    }
  });
});
