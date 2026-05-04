import { describe, it, expect, vi } from "vitest";
import { resolveKidToAuthority } from "./kid-resolve.js";
import type { KidMapping } from "./types.js";

function makeEnv(initial: Record<string, string> = {}) {
  const store: Record<string, string> = { ...initial };
  return {
    RRF_KV: {
      get: vi.fn(async (k: string) => store[k] ?? null),
      put: vi.fn(async (k: string, v: string) => { store[k] = v; }),
      list: vi.fn(async ({ prefix }: { prefix: string }) => ({
        keys: Object.keys(store)
          .filter(k => k.startsWith(prefix))
          .map(name => ({ name })),
      })),
      delete: vi.fn(),
    } as unknown as KVNamespace,
    __store: store,
  };
}

describe("resolveKidToAuthority", () => {
  it("returns null when no kid:* entries match", async () => {
    const { RRF_KV } = makeEnv();
    const result = await resolveKidToAuthority(
      { RRF_KV } as { RRF_KV: KVNamespace },
      "missing-kid",
      "2026-05-04T12:00:00Z",
    );
    expect(result).toBeNull();
  });

  it("returns the active mapping when signed_at falls in [valid_from, valid_until)", async () => {
    const mapping: KidMapping = {
      ran: "RAN-000000000001",
      valid_from: "2026-01-01T00:00:00Z",
      valid_until: "2027-01-01T00:00:00Z",
      registered_at: "2026-01-01T00:00:00Z",
      registered_by: "RAN-000000000001",
    };
    const authority = {
      ran: "RAN-000000000001",
      organization: "OpenCastor Ops",
      signing_pub: "FAKE-ED25519-PUB",
      pq_signing_pub: "FAKE-ML-DSA-PUB",
    };
    const { RRF_KV } = makeEnv({
      "kid:ops-aggregator-2026-05:2026-01-01T00:00:00Z": JSON.stringify(mapping),
      "authority:RAN-000000000001": JSON.stringify(authority),
    });
    const result = await resolveKidToAuthority(
      { RRF_KV } as { RRF_KV: KVNamespace },
      "ops-aggregator-2026-05",
      "2026-05-04T12:00:00Z",
    );
    expect(result).not.toBeNull();
    expect(result!.ran).toBe("RAN-000000000001");
    expect(result!.signing_pub).toBe("FAKE-ED25519-PUB");
  });

  it("rejects mappings where signed_at predates valid_from", async () => {
    const mapping: KidMapping = {
      ran: "RAN-000000000001",
      valid_from: "2026-06-01T00:00:00Z",
      registered_at: "2026-06-01T00:00:00Z",
      registered_by: "RAN-000000000001",
    };
    const authority = { ran: "RAN-000000000001", signing_pub: "X", pq_signing_pub: "Y" };
    const { RRF_KV } = makeEnv({
      "kid:k:2026-06-01T00:00:00Z": JSON.stringify(mapping),
      "authority:RAN-000000000001": JSON.stringify(authority),
    });
    const result = await resolveKidToAuthority(
      { RRF_KV } as { RRF_KV: KVNamespace },
      "k",
      "2026-05-04T12:00:00Z",
    );
    expect(result).toBeNull();
  });

  it("rejects mappings where signed_at >= valid_until", async () => {
    const mapping: KidMapping = {
      ran: "RAN-000000000001",
      valid_from: "2026-01-01T00:00:00Z",
      valid_until: "2026-04-01T00:00:00Z",
      registered_at: "2026-01-01T00:00:00Z",
      registered_by: "RAN-000000000001",
    };
    const authority = { ran: "RAN-000000000001", signing_pub: "X", pq_signing_pub: "Y" };
    const { RRF_KV } = makeEnv({
      "kid:k:2026-01-01T00:00:00Z": JSON.stringify(mapping),
      "authority:RAN-000000000001": JSON.stringify(authority),
    });
    const result = await resolveKidToAuthority(
      { RRF_KV } as { RRF_KV: KVNamespace },
      "k",
      "2026-05-04T12:00:00Z",
    );
    expect(result).toBeNull();
  });

  it("picks the most-recent valid mapping when multiple match (rotation overlap)", async () => {
    const m1: KidMapping = {
      ran: "RAN-000000000001",
      valid_from: "2026-01-01T00:00:00Z",
      valid_until: "2026-06-01T00:00:00Z",
      registered_at: "2026-01-01T00:00:00Z",
      registered_by: "RAN-000000000001",
    };
    const m2: KidMapping = {
      ran: "RAN-000000000002",
      valid_from: "2026-05-15T00:00:00Z",
      registered_at: "2026-05-15T00:00:00Z",
      registered_by: "RAN-000000000002",
    };
    const a1 = { ran: "RAN-000000000001", signing_pub: "X1", pq_signing_pub: "Y1" };
    const a2 = { ran: "RAN-000000000002", signing_pub: "X2", pq_signing_pub: "Y2" };
    const { RRF_KV } = makeEnv({
      "kid:k:2026-01-01T00:00:00Z": JSON.stringify(m1),
      "kid:k:2026-05-15T00:00:00Z": JSON.stringify(m2),
      "authority:RAN-000000000001": JSON.stringify(a1),
      "authority:RAN-000000000002": JSON.stringify(a2),
    });
    // signed_at falls in BOTH windows; resolver picks the most-recent registered_at.
    const result = await resolveKidToAuthority(
      { RRF_KV } as { RRF_KV: KVNamespace },
      "k",
      "2026-05-20T12:00:00Z",
    );
    expect(result).not.toBeNull();
    expect(result!.ran).toBe("RAN-000000000002");
  });
});
