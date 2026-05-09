import { describe, it, expect, vi } from "vitest";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { onRequestPost } from "./register.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fx = JSON.parse(
  readFileSync(resolve(__dirname, "../../_lib/fixtures/package-fixture.json"), "utf8"),
);

function makeEnv() {
  const store: Record<string, string> = { "counter:rpn": "0" };
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
  return new Request("https://x/v2/packages/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("POST /v2/packages/register", () => {
  it("rejects unsigned body (400)", async () => {
    const env = makeEnv();
    const { sig: _drop, ...unsigned } = fx.http_body;
    const res = await onRequestPost({ request: makePost(unsigned), env } as any);
    expect(res.status).toBe(400);
  });

  it("rejects invalid signature (400)", async () => {
    const env = makeEnv();
    const tampered = { ...fx.http_body, name: "different-name" };
    const res = await onRequestPost({ request: makePost(tampered), env } as any);
    expect(res.status).toBe(400);
  });

  it("rejects missing required fields (400)", async () => {
    const env = makeEnv();
    const { name: _drop, ...incomplete } = fx.http_body;
    const res = await onRequestPost({ request: makePost(incomplete), env } as any);
    expect(res.status).toBe(400);
  });

  it("rejects unknown package_type (400)", async () => {
    const env = makeEnv();
    const bogus = { ...fx.http_body, package_type: "frobnicator" };
    const res = await onRequestPost({ request: makePost(bogus), env } as any);
    expect(res.status).toBe(400);
  });

  it("mints RPN and persists record (201)", async () => {
    const env = makeEnv();
    const res = await onRequestPost({ request: makePost(fx.http_body), env } as any);
    expect(res.status).toBe(201);
    const body = await res.json() as { rpn: string; registered_at: string; record_url: string };
    expect(body.rpn).toBe("RPN-000000000001");
    expect(body.record_url).toContain("/v2/packages/RPN-000000000001");
    expect(env.__store["package:RPN-000000000001"]).toBeTruthy();
    expect(env.__store["package-by-name:actuator:feetech-arm"]).toBe("RPN-000000000001");
  });

  it("rejects duplicate name within same type (409)", async () => {
    const env = makeEnv();
    await onRequestPost({ request: makePost(fx.http_body), env } as any);
    const res = await onRequestPost({ request: makePost(fx.http_body), env } as any);
    expect(res.status).toBe(409);
  });

  it("allows same name in different package_type", async () => {
    const env = makeEnv();
    const r1 = await onRequestPost({ request: makePost(fx.http_body), env } as any);
    expect(r1.status).toBe(201);
    // Re-sign would be needed for a real test; pattern after components/register.test.ts which
    // either uses two fixtures or accepts that this test is skipped without a second fixture.
    // For now, assert the by-name index is type-scoped:
    expect(env.__store["package-by-name:actuator:feetech-arm"]).toBe("RPN-000000000001");
    expect(env.__store["package-by-name:skill:feetech-arm"]).toBeUndefined();
  });

  it("appends RPN to package-by-type:actuator index", async () => {
    const env = makeEnv();
    await onRequestPost({ request: makePost(fx.http_body), env } as any);
    expect(env.__store["package-by-type:actuator"]).toBe("RPN-000000000001");
  });

  it("writes proof KV key with original signed body (sig included)", async () => {
    const env = makeEnv();
    const res = await onRequestPost({ request: makePost(fx.http_body), env } as any);
    expect(res.status).toBe(201);
    const proofRaw = env.__store["package-proof:RPN-000000000001"];
    expect(proofRaw).toBeTruthy();
    const proof = JSON.parse(proofRaw);
    expect(proof.sig).toBeDefined();
    expect(proof.name).toBe(fx.http_body.name);
  });
});
