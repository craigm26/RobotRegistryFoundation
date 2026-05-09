import { describe, it, expect, vi } from "vitest";
import { onRequestPost } from "./revoke.js";
import { signBodyWithFixtureKp, fixturePublisher } from "./_test-helpers.js";

function makeEnv() {
  const record = {
    rpn: "RPN-000000000001",
    package_type: "actuator",
    name: "feetech-arm",
    versions: [{ version: "1.0.0", released_at: "2026-05-09T00:00:00Z" }],
    publisher: fixturePublisher,
    registered_at: "2026-05-09T00:00:00Z",
    status: "active",
  };
  const store: Record<string, string> = {
    "package:RPN-000000000001": JSON.stringify(record),
  };
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

async function signedRevokePost(reason: string): Promise<Request> {
  const body = await signBodyWithFixtureKp({ reason });
  return new Request("https://x/v2/packages/RPN-000000000001/revoke", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("POST /v2/packages/[rpn]/revoke", () => {
  it("404 when RPN doesn't exist", async () => {
    const env = makeEnv();
    delete env.__store["package:RPN-000000000001"];
    const req = await signedRevokePost("test");
    const res = await onRequestPost({ request: req, env, params: { rpn: "RPN-000000000001" } } as any);
    expect(res.status).toBe(404);
  });

  it("400 on unsigned body", async () => {
    const env = makeEnv();
    const req = new Request("https://x/v2/packages/RPN-000000000001/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason: "test" }),
    });
    const res = await onRequestPost({ request: req, env, params: { rpn: "RPN-000000000001" } } as any);
    expect(res.status).toBe(400);
  });

  it("flips status=revoked + records reason + timestamp", async () => {
    const env = makeEnv();
    const req = await signedRevokePost("abandoned");
    const res = await onRequestPost({ request: req, env, params: { rpn: "RPN-000000000001" } } as any);
    expect(res.status).toBe(200);
    const stored = JSON.parse(env.__store["package:RPN-000000000001"]);
    expect(stored.status).toBe("revoked");
    expect(stored.revocation_reason).toBe("abandoned");
    expect(stored.revoked_at).toBeTruthy();
  });

  it("400 if already revoked", async () => {
    const env = makeEnv();
    const rec = JSON.parse(env.__store["package:RPN-000000000001"]);
    rec.status = "revoked";
    env.__store["package:RPN-000000000001"] = JSON.stringify(rec);
    const req = await signedRevokePost("again");
    const res = await onRequestPost({ request: req, env, params: { rpn: "RPN-000000000001" } } as any);
    expect(res.status).toBe(400);
  });
});
