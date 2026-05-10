// functions/v2/run-bundles/[run_id]/index.test.ts
import { describe, it, expect, vi } from "vitest";
import { onRequestGet } from "./index.js";

function makeEnv(seed: Record<string, string> = {}) {
  return {
    RRF_KV: {
      get: vi.fn(async (k: string) => seed[k] ?? null),
      put: vi.fn(),
      list: vi.fn(),
      delete: vi.fn(),
    },
  };
}

function makeGet(runId: string): { request: Request; params: Record<string, string> } {
  return {
    request: new Request(`https://x/v2/run-bundles/${runId}`),
    params: { run_id: runId },
  };
}

describe("GET /v2/run-bundles/{run_id}", () => {
  it("400 on malformed run_id", async () => {
    const env = makeEnv();
    const ctx = { ...makeGet("not_a_run_id"), env };
    const res = await onRequestGet(ctx as any);
    expect(res.status).toBe(400);
  });

  it("404 when run_id absent in KV", async () => {
    const env = makeEnv();
    const ctx = { ...makeGet("runbundle_aaaaaaaaaaaa"), env };
    const res = await onRequestGet(ctx as any);
    expect(res.status).toBe(404);
  });

  it("200 with wrapper shape when present", async () => {
    const wrapper = { record: { schema_version: "1.0", sig: { ml_dsa: "x", ed25519: "y", ed25519_pub: "z" } }, transparency_log_index: 1, logged_at: "2026-05-09T20:00:00Z", rrf_log_signature: "..." };
    const env = makeEnv({ "run-bundle:runbundle_aaaaaaaaaaaa": JSON.stringify(wrapper) });
    const ctx = { ...makeGet("runbundle_aaaaaaaaaaaa"), env };
    const res = await onRequestGet(ctx as any);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toEqual(wrapper);
    expect(body.record.sig).toBeDefined();   // sig is intact (not stripped)
  });
});
