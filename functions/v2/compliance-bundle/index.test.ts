// functions/v2/compliance-bundle/index.test.ts
import { describe, it, expect, vi } from "vitest";
import { onRequestPost } from "./index.js";

function makeEnv(initial: Record<string, string> = {}) {
  const store: Record<string, string> = { ...initial };
  return {
    env: {
      RRF_KV: {
        get: vi.fn(async (k: string) => store[k] ?? null),
        put: vi.fn(async (k: string, v: string) => { store[k] = v; }),
        list: vi.fn(async ({ prefix }: { prefix: string }) => ({
          keys: Object.keys(store).filter(k => k.startsWith(prefix)).map(name => ({ name })),
          list_complete: true,
        })),
        delete: vi.fn(),
      } as unknown as KVNamespace,
    },
    store,
  };
}

function mkReq(body: unknown): Request {
  return new Request("https://x/v2/compliance-bundle", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("POST /v2/compliance-bundle", () => {
  it("returns 400 on invalid JSON body", async () => {
    const { env } = makeEnv();
    const req = new Request("https://x/v2/compliance-bundle", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "not json",
    });
    const res = await onRequestPost({ env, request: req } as any);
    expect(res.status).toBe(400);
  });

  it("returns 400 when schema_version is missing", async () => {
    const { env } = makeEnv();
    const res = await onRequestPost({ env, request: mkReq({ rrn: "RRN-000000000002" }) } as any);
    expect(res.status).toBe(400);
  });

  it("returns 415 on unsupported schema_version", async () => {
    const { env } = makeEnv();
    const res = await onRequestPost({
      env,
      request: mkReq({ schema_version: "9.99", rrn: "RRN-000000000002" }),
    } as any);
    expect(res.status).toBe(415);
  });

  // Happy-path 201 + 409 idempotency + 403 (kid not registered, scope missing)
  // are covered by the smoke test in Task 14, which mints real keys and
  // exercises the full flow including handlers/v10.
});
