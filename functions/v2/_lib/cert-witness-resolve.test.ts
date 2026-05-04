import { describe, it, expect, vi } from "vitest";
import { resolveWitnessKid } from "./cert-witness-resolve.js";
import type { WitnessKidMapping } from "./types.js";

function makeEnv(initial: Record<string, string> = {}) {
  const store: Record<string, string> = { ...initial };
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

const baseMapping = (overrides: Partial<WitnessKidMapping> = {}): WitnessKidMapping => ({
  witness_id: "craigm",
  rig_id: "bob",
  signing_pub: "PeTWtnHxB5YhnZRPrbuLkgO5CI3PcaYO//zpUh4Nv6M=",
  valid_from: "2026-05-04T00:00:00Z",
  registered_at: "2026-05-04T00:00:00Z",
  ...overrides,
});

describe("resolveWitnessKid", () => {
  it("returns the registered mapping when ran_at falls within validity window", async () => {
    const env = makeEnv({
      "cert-witness:witness-bob-craigm:2026-05-04T00:00:00Z": JSON.stringify(baseMapping()),
    });
    const result = await resolveWitnessKid(env, "witness-bob-craigm", "2026-06-01T00:00:00Z");
    expect(result?.witness_id).toBe("craigm");
    expect(result?.rig_id).toBe("bob");
  });

  it("returns null when kid is not registered", async () => {
    const env = makeEnv({});
    const result = await resolveWitnessKid(env, "nonexistent-witness", "2026-06-01T00:00:00Z");
    expect(result).toBeNull();
  });

  it("excludes mappings whose valid_until has passed", async () => {
    const env = makeEnv({
      "cert-witness:witness-bob-craigm:2026-05-04T00:00:00Z": JSON.stringify(baseMapping({
        valid_until: "2026-05-10T00:00:00Z",
      })),
    });
    const result = await resolveWitnessKid(env, "witness-bob-craigm", "2026-06-01T00:00:00Z");
    expect(result).toBeNull();
  });

  it("picks the most-recent registered_at on rotation overlap", async () => {
    const env = makeEnv({
      "cert-witness:witness-bob-craigm:2026-05-04T00:00:00Z": JSON.stringify(baseMapping({
        witness_id: "craigm-old",
      })),
      "cert-witness:witness-bob-craigm:2026-05-15T00:00:00Z": JSON.stringify(baseMapping({
        witness_id: "craigm-new",
        registered_at: "2026-05-15T00:00:00Z",
      })),
    });
    const result = await resolveWitnessKid(env, "witness-bob-craigm", "2026-06-01T00:00:00Z");
    expect(result?.witness_id).toBe("craigm-new");
  });
});
