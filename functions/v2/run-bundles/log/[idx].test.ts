// functions/v2/run-bundles/log/[idx].test.ts
import { describe, it, expect, vi } from "vitest";
import { onRequestGet } from "./[idx].js";

function makeEnv(seed: Record<string, string> = {}) {
  return {
    RRF_KV: {
      get: vi.fn(async (k: string) => seed[k] ?? null),
      put: vi.fn(), list: vi.fn(), delete: vi.fn(),
    },
  };
}

function makeGet(idx: string) {
  return {
    request: new Request(`https://x/v2/run-bundles/log/${idx}`),
    params: { idx },
  };
}

describe("GET /v2/run-bundles/log/{idx}", () => {
  it("400 on non-digit idx", async () => {
    const env = makeEnv();
    const res = await onRequestGet({ ...makeGet("abc"), env } as any);
    expect(res.status).toBe(400);
  });

  it("404 when log entry absent", async () => {
    const env = makeEnv();
    const res = await onRequestGet({ ...makeGet("1"), env } as any);
    expect(res.status).toBe(404);
  });

  it("200 returns log entry shape", async () => {
    const entry = { run_id: "runbundle_aaaaaaaaaaaa", transparency_log_index: 1, rrf_log_signature: "sig..." };
    const env = makeEnv({ "run-bundle-log:000000000001": JSON.stringify(entry) });
    const res = await onRequestGet({ ...makeGet("1"), env } as any);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual(entry);
  });
});
