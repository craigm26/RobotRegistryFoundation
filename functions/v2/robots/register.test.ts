import { describe, it, expect, vi } from "vitest";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { onRequestPost } from "./register.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fx = JSON.parse(
  readFileSync(resolve(__dirname, "../../_lib/fixtures/register-fixture.json"), "utf8"),
);

function makeEnv() {
  const store: Record<string, string> = {};
  // nextId counter — incremented by nextId() helper. Start at 41 so next mint is RRN-000000000042.
  store["counter:RRN"] = "41";
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
  return new Request("https://x/v2/robots/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("POST /v2/robots/register — signing enforcement (RCAN 3.0 §2.2)", () => {
  it("rejects unsigned body (400)", async () => {
    const env = makeEnv();
    const res = await onRequestPost({
      request: makePost({
        name: "x", manufacturer: "y", model: "z",
        firmware_version: "1.0", rcan_version: "3.0",
      }),
      env,
    } as any);
    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error).toMatch(/unsigned/i);
  });

  it("rejects missing sig.ml_dsa (400)", async () => {
    const env = makeEnv();
    const body = { ...fx.http_body, sig: { ed25519: "x", ed25519_pub: "y" } };
    const res = await onRequestPost({ request: makePost(body), env } as any);
    expect(res.status).toBe(400);
  });

  it("rejects tampered ml_dsa signature (400)", async () => {
    const env = makeEnv();
    const body = {
      ...fx.http_body,
      sig: { ...fx.http_body.sig, ml_dsa: "AAAA" + fx.http_body.sig.ml_dsa.slice(4) },
    };
    const res = await onRequestPost({ request: makePost(body), env } as any);
    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error).toMatch(/verification/i);
  });

  it("rejects tampered body field (400) — sig valid over original body only", async () => {
    const env = makeEnv();
    const body = { ...fx.http_body, manufacturer: "evil-corp" };
    const res = await onRequestPost({ request: makePost(body), env } as any);
    expect(res.status).toBe(400);
  });

  it("accepts a valid signed body and mints RRN (201)", async () => {
    const env = makeEnv();
    const res = await onRequestPost({ request: makePost(fx.http_body), env } as any);
    expect(res.status).toBe(201);
    const json = await res.json();
    expect(json.rrn).toMatch(/^RRN-\d{12}$/);
    expect(json.record_url).toContain("robotregistryfoundation.org");
  });
});
