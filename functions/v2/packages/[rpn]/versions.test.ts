import { describe, it, expect, vi } from "vitest";
import { onRequestPost } from "./versions.js";
import { signBodyWithFixtureKp, fixturePublisher } from "./_test-helpers.js";

function makeEnvWithRecord() {
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

async function makeSignedVersionPost(version: string): Promise<Request> {
  const body = await signBodyWithFixtureKp({ version });
  return new Request("https://x/v2/packages/RPN-000000000001/versions", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("POST /v2/packages/[rpn]/versions", () => {
  it("404 when RPN doesn't exist", async () => {
    const env = makeEnvWithRecord();
    delete env.__store["package:RPN-000000000001"];
    const req = await makeSignedVersionPost("1.1.0");
    const res = await onRequestPost({ request: req, env, params: { rpn: "RPN-000000000001" } } as any);
    expect(res.status).toBe(404);
  });

  it("400 on unsigned body", async () => {
    const env = makeEnvWithRecord();
    const req = new Request("https://x/v2/packages/RPN-000000000001/versions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ version: "1.1.0" }),
    });
    const res = await onRequestPost({ request: req, env, params: { rpn: "RPN-000000000001" } } as any);
    expect(res.status).toBe(400);
  });

  it("appends version + returns 200", async () => {
    const env = makeEnvWithRecord();
    const req = await makeSignedVersionPost("1.1.0");
    const res = await onRequestPost({ request: req, env, params: { rpn: "RPN-000000000001" } } as any);
    expect(res.status).toBe(200);
    const stored = JSON.parse(env.__store["package:RPN-000000000001"]);
    expect(stored.versions.map((v: any) => v.version)).toEqual(["1.0.0", "1.1.0"]);
  });

  it("rejects duplicate version (409)", async () => {
    const env = makeEnvWithRecord();
    const req = await makeSignedVersionPost("1.0.0"); // already present
    const res = await onRequestPost({ request: req, env, params: { rpn: "RPN-000000000001" } } as any);
    expect(res.status).toBe(409);
  });

  it("400 on revoked package", async () => {
    const env = makeEnvWithRecord();
    const rec = JSON.parse(env.__store["package:RPN-000000000001"]);
    rec.status = "revoked";
    env.__store["package:RPN-000000000001"] = JSON.stringify(rec);
    const req = await makeSignedVersionPost("1.1.0");
    const res = await onRequestPost({ request: req, env, params: { rpn: "RPN-000000000001" } } as any);
    expect(res.status).toBe(400);
  });
});
