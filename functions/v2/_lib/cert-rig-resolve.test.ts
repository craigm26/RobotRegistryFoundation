import { describe, it, expect, vi } from "vitest";
import { resolveRigKid } from "./cert-rig-resolve.js";
import type { RigKidMapping } from "./types.js";

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

const baseMapping = (overrides: Partial<RigKidMapping> = {}): RigKidMapping => ({
  rig_id: "bob",
  rrn: "RRN-000000000002",
  signing_pub: "htSRgObFeBjjB6JIBW9XlNfivlVbQwFJcKWn+n0flvg=",
  valid_from: "2026-05-04T00:00:00Z",
  registered_at: "2026-05-04T00:00:00Z",
  ...overrides,
});

describe("resolveRigKid", () => {
  it("returns the registered mapping when ran_at falls within validity window", async () => {
    const env = makeEnv({
      "cert-rig:bob-rig-2026:2026-05-04T00:00:00Z": JSON.stringify(baseMapping()),
    });
    const result = await resolveRigKid(env, "bob-rig-2026", "2026-06-01T00:00:00Z");
    expect(result?.rrn).toBe("RRN-000000000002");
    expect(result?.signing_pub).toBe("htSRgObFeBjjB6JIBW9XlNfivlVbQwFJcKWn+n0flvg=");
  });

  it("returns null when kid is not registered", async () => {
    const env = makeEnv({});
    const result = await resolveRigKid(env, "nonexistent-kid", "2026-06-01T00:00:00Z");
    expect(result).toBeNull();
  });

  it("excludes mappings whose valid_until has passed", async () => {
    const env = makeEnv({
      "cert-rig:bob-rig-2026:2026-05-04T00:00:00Z": JSON.stringify(baseMapping({
        valid_until: "2026-05-10T00:00:00Z",
      })),
    });
    const result = await resolveRigKid(env, "bob-rig-2026", "2026-06-01T00:00:00Z");
    expect(result).toBeNull();
  });

  it("picks the most-recent registered_at when multiple mappings are valid (rotation overlap)", async () => {
    const env = makeEnv({
      "cert-rig:bob-rig-2026:2026-05-04T00:00:00Z": JSON.stringify(baseMapping({
        rrn: "RRN-000000000002",
      })),
      "cert-rig:bob-rig-2026:2026-05-15T00:00:00Z": JSON.stringify(baseMapping({
        rrn: "RRN-000000000999",
        registered_at: "2026-05-15T00:00:00Z",
      })),
    });
    const result = await resolveRigKid(env, "bob-rig-2026", "2026-06-01T00:00:00Z");
    expect(result?.rrn).toBe("RRN-000000000999");
  });
});
