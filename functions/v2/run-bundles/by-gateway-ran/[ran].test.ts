// functions/v2/run-bundles/by-gateway-ran/[ran].test.ts
import { describe, it, expect, vi } from "vitest";
import { onRequestGet } from "./[ran].js";

function makeEnv(seed: Record<string, string> = {}) {
  return {
    RRF_KV: {
      get: vi.fn(async (k: string) => seed[k] ?? null),
      put: vi.fn(), list: vi.fn(), delete: vi.fn(),
    },
  };
}

function makeGet(ran: string) {
  return {
    request: new Request(`https://x/v2/run-bundles/by-gateway-ran/${ran}`),
    params: { ran },
  };
}

describe("GET /v2/run-bundles/by-gateway-ran/{ran}", () => {
  it("400 on malformed RAN", async () => {
    const env = makeEnv();
    const res = await onRequestGet({ ...makeGet("not-a-ran"), env } as any);
    expect(res.status).toBe(400);
  });

  it("200 with empty list for absent back-ref key", async () => {
    const env = makeEnv();
    const res = await onRequestGet({ ...makeGet("RAN-000000000019"), env } as any);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ run_ids: [], count: 0 });
  });

  it("200 with parsed list for present back-ref", async () => {
    const env = makeEnv({
      "run-bundles-by-gateway-ran:RAN-000000000019": "runbundle_aaaaaaaaaaaa\nrunbundle_bbbbbbbbbbbb",
    });
    const res = await onRequestGet({ ...makeGet("RAN-000000000019"), env } as any);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      run_ids: ["runbundle_aaaaaaaaaaaa", "runbundle_bbbbbbbbbbbb"],
      count: 2,
    });
  });
});
