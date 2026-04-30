import { describe, it, expect, vi } from "vitest";
import { onRequest } from "./[submission_id].js";

function makeEnv(init: Record<string, string> = {}) {
  const store: Record<string, string> = { ...init };
  return {
    RRF_KV: {
      get: vi.fn(async (k: string) => store[k] ?? null),
      put: vi.fn(),
      list: vi.fn(),
      delete: vi.fn(),
    } as unknown as KVNamespace,
    __store: store,
  };
}

function req(method: string, headers: Record<string, string> = {}) {
  return new Request("https://x/v1/spatial-eval/runs/sub_abc", { method, headers });
}

describe("GET /v1/spatial-eval/runs/[submission_id]", () => {
  it("returns 401 without Bearer header", async () => {
    const env = makeEnv({
      "compliance:spatial-eval:run:sub_abc": JSON.stringify({ submission_id: "sub_abc" }),
    });
    const res = await onRequest({
      request: req("GET"),
      env,
      params: { submission_id: "sub_abc" },
    } as any);
    expect(res.status).toBe(401);
  });

  it("returns stored submission with Bearer header", async () => {
    const stored = {
      submission_id: "sub_abc",
      rrn: "RRN-000000000002",
      status: "counter_signed",
      score: { rrf_signature: "rrf-sig" },
    };
    const env = makeEnv({
      "compliance:spatial-eval:run:sub_abc": JSON.stringify(stored),
    });
    const res = await onRequest({
      request: req("GET", { Authorization: "Bearer x" }),
      env,
      params: { submission_id: "sub_abc" },
    } as any);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.submission_id).toBe("sub_abc");
    expect(body.score.rrf_signature).toBe("rrf-sig");
  });

  it("returns 404 when submission_id unknown", async () => {
    const env = makeEnv();
    const res = await onRequest({
      request: req("GET", { Authorization: "Bearer x" }),
      env,
      params: { submission_id: "sub_unknown" },
    } as any);
    expect(res.status).toBe(404);
  });

  it("returns 400 on malformed submission_id", async () => {
    const env = makeEnv();
    const res = await onRequest({
      request: req("GET", { Authorization: "Bearer x" }),
      env,
      params: { submission_id: "not-a-sub" },
    } as any);
    expect(res.status).toBe(400);
  });

  it("returns 405 on non-GET method", async () => {
    const env = makeEnv();
    const res = await onRequest({
      request: req("DELETE", { Authorization: "Bearer x" }),
      env,
      params: { submission_id: "sub_abc" },
    } as any);
    expect(res.status).toBe(405);
  });
});
