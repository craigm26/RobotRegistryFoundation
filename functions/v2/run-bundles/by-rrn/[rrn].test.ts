// functions/v2/run-bundles/by-rrn/[rrn].test.ts
import { describe, it, expect, vi } from "vitest";
import { onRequestGet } from "./[rrn].js";

function makeEnv(seed: Record<string, string> = {}) {
  return {
    RRF_KV: {
      get: vi.fn(async (k: string) => seed[k] ?? null),
      put: vi.fn(), list: vi.fn(), delete: vi.fn(),
    },
  };
}

function makeGet(rrn: string) {
  return {
    request: new Request(`https://x/v2/run-bundles/by-rrn/${rrn}`),
    params: { rrn },
  };
}

describe("GET /v2/run-bundles/by-rrn/{rrn}", () => {
  it("400 on malformed RRN", async () => {
    const env = makeEnv();
    const res = await onRequestGet({ ...makeGet("not-an-rrn"), env } as any);
    expect(res.status).toBe(400);
  });

  it("200 with empty list for absent back-ref key", async () => {
    const env = makeEnv();
    const res = await onRequestGet({ ...makeGet("RRN-000000000001"), env } as any);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ run_ids: [], count: 0 });
  });

  it("200 with parsed list for present back-ref", async () => {
    const env = makeEnv({
      "run-bundles-by-rrn:RRN-000000000001": "runbundle_aaaaaaaaaaaa\nrunbundle_bbbbbbbbbbbb",
    });
    const res = await onRequestGet({ ...makeGet("RRN-000000000001"), env } as any);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      run_ids: ["runbundle_aaaaaaaaaaaa", "runbundle_bbbbbbbbbbbb"],
      count: 2,
    });
  });
});
