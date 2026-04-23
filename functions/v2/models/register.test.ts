import { describe, it, expect, vi } from "vitest";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { onRequestPost } from "./register.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fx = JSON.parse(
  readFileSync(resolve(__dirname, "../../_lib/fixtures/model-fixture.json"), "utf8"),
);

function makeEnv() {
  const store: Record<string, string> = {};
  store["counter:RMN"] = "0";
  return {
    RRF_KV: {
      get: vi.fn(async (k: string) => store[k] ?? null),
      put: vi.fn(async (k: string, v: string) => { store[k] = v; }),
      list: vi.fn(),
      delete: vi.fn(),
    },
    __store: store,
  };
}

function makePost(body: unknown): Request {
  return new Request("https://x/v2/models/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("POST /v2/models/register — signing enforcement (RCAN 3.0 §2.2)", () => {
  it("rejects unsigned body (400)", async () => {
    const env = makeEnv();
    const res = await onRequestPost({
      request: makePost({ name: "x", version: "1", model_family: "language" }),
      env,
    } as any);
    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error).toMatch(/unsigned/i);
  });

  it("rejects tampered body field (400)", async () => {
    const env = makeEnv();
    const body = { ...fx.http_body, provider: "evil-provider" };
    const res = await onRequestPost({ request: makePost(body), env } as any);
    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error).toMatch(/verification/i);
  });

  it("accepts a valid signed body and mints RMN (201)", async () => {
    const env = makeEnv();
    const res = await onRequestPost({ request: makePost(fx.http_body), env } as any);
    expect(res.status).toBe(201);
    const json = await res.json();
    expect(json.rmn).toMatch(/^RMN-\d{12}$/);
    expect(json.record_url).toContain("robotregistryfoundation.org/v2/models/");
  });
});
