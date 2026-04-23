import { describe, it, expect, vi } from "vitest";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { onRequestPost } from "./register.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fx = JSON.parse(
  readFileSync(resolve(__dirname, "../../_lib/fixtures/component-fixture.json"), "utf8"),
);

function makeEnv() {
  const store: Record<string, string> = {};
  store["counter:RCN"] = "0";
  // Parent robot must exist; fixture's parent_rrn is RRN-000000000042.
  store[`robot:${fx.http_body.parent_rrn}`] = JSON.stringify({
    rrn: fx.http_body.parent_rrn,
    name: "parent-bot",
  });
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
  return new Request("https://x/v2/components/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("POST /v2/components/register — signing enforcement (RCAN 3.0 §2.2)", () => {
  it("rejects unsigned body (400)", async () => {
    const env = makeEnv();
    const res = await onRequestPost({
      request: makePost({
        parent_rrn: fx.http_body.parent_rrn,
        type: "camera", model: "oak-d", manufacturer: "luxonis",
      }),
      env,
    } as any);
    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error).toMatch(/unsigned/i);
  });

  it("rejects missing sig.ed25519_pub (400)", async () => {
    const env = makeEnv();
    const body = { ...fx.http_body, sig: { ml_dsa: "x", ed25519: "y" } };
    const res = await onRequestPost({ request: makePost(body), env } as any);
    expect(res.status).toBe(400);
  });

  it("rejects tampered body field (400)", async () => {
    const env = makeEnv();
    const body = { ...fx.http_body, manufacturer: "evil-corp" };
    const res = await onRequestPost({ request: makePost(body), env } as any);
    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error).toMatch(/verification/i);
  });

  it("rejects when parent robot missing (404)", async () => {
    const env = makeEnv();
    delete env.__store[`robot:${fx.http_body.parent_rrn}`];
    const res = await onRequestPost({ request: makePost(fx.http_body), env } as any);
    expect(res.status).toBe(404);
  });

  it("accepts a valid signed body and mints RCN (201)", async () => {
    const env = makeEnv();
    const res = await onRequestPost({ request: makePost(fx.http_body), env } as any);
    expect(res.status).toBe(201);
    const json = await res.json();
    expect(json.rcn).toMatch(/^RCN-\d{12}$/);
    expect(json.record_url).toContain("robotregistryfoundation.org/v2/components/");
  });
});
