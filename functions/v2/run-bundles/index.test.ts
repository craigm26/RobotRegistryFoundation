import { describe, it, expect, vi } from "vitest";
import { onRequestPost } from "./index.js";

function makeEnv() {
  const store: Record<string, string> = {};
  return {
    RRF_KV: {
      get: vi.fn(async (k: string) => store[k] ?? null),
      put: vi.fn(async (k: string, v: string) => { store[k] = v; }),
      list: vi.fn(),
      delete: vi.fn(),
    },
  };
}

function makePost(body: unknown): Request {
  return new Request("https://x/v2/run-bundles", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

describe("POST /v2/run-bundles dispatch", () => {
  it("400 on invalid JSON", async () => {
    const env = makeEnv();
    const res = await onRequestPost({ request: makePost("not json{"), env } as any);
    expect(res.status).toBe(400);
  });

  it("400 when schema_version missing", async () => {
    const env = makeEnv();
    const res = await onRequestPost({ request: makePost({}), env } as any);
    expect(res.status).toBe(400);
  });

  it("415 on unsupported schema_version", async () => {
    const env = makeEnv();
    const res = await onRequestPost({ request: makePost({ schema_version: "9.9" }), env } as any);
    expect(res.status).toBe(415);
  });
});
