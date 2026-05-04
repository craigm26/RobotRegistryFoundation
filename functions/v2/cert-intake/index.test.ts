import { describe, it, expect, vi } from "vitest";
import { onRequestPost } from "./index.js";

function makeEnv() {
  const store: Record<string, string> = {};
  return {
    env: {
      RRF_KV: {
        get: vi.fn(async (k: string) => store[k] ?? null),
        put: vi.fn(async (k: string, v: string) => { store[k] = v; }),
        list: vi.fn(async () => ({ keys: [], list_complete: true })),
        delete: vi.fn(),
      } as unknown as KVNamespace,
    },
    store,
  };
}

function mkReq(body: unknown): Request {
  return new Request("https://x/v2/cert-intake", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

describe("POST /v2/cert-intake", () => {
  it("returns 400 on invalid JSON body", async () => {
    const { env } = makeEnv();
    const res = await onRequestPost({ env, request: mkReq("not-json") } as unknown as Parameters<typeof onRequestPost>[0]);
    expect(res.status).toBe(400);
  });

  it("returns 400 when schema_version missing", async () => {
    const { env } = makeEnv();
    const res = await onRequestPost({ env, request: mkReq({ no: "version" }) } as unknown as Parameters<typeof onRequestPost>[0]);
    expect(res.status).toBe(400);
  });

  it("returns 415 on unsupported schema_version", async () => {
    const { env } = makeEnv();
    const res = await onRequestPost({ env, request: mkReq({ schema_version: "99.99" }) } as unknown as Parameters<typeof onRequestPost>[0]);
    expect(res.status).toBe(415);
  });
});
