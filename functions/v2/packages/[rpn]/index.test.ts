import { describe, it, expect, vi } from "vitest";
import { onRequestGet } from "./index.js";

function makeEnv(seed: Record<string, string> = {}) {
  return {
    RRF_KV: {
      get: vi.fn(async (k: string) => seed[k] ?? null),
      put: vi.fn(),
      list: vi.fn(),
      delete: vi.fn(),
    },
  };
}

describe("GET /v2/packages/[rpn]", () => {
  it("returns 200 with the record when RPN exists", async () => {
    const record = {
      rpn: "RPN-000000000001",
      package_type: "actuator",
      name: "x",
      versions: [],
      publisher: {},
      registered_at: "2026-05-09T00:00:00Z",
      status: "active",
    };
    const env = makeEnv({ "package:RPN-000000000001": JSON.stringify(record) });
    const res = await onRequestGet({
      request: new Request("https://x/v2/packages/RPN-000000000001"),
      env,
      params: { rpn: "RPN-000000000001" },
    } as any);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual(record);
  });

  it("returns 404 when RPN does not exist", async () => {
    const env = makeEnv();
    const res = await onRequestGet({
      request: new Request("https://x/v2/packages/RPN-000000000099"),
      env,
      params: { rpn: "RPN-000000000099" },
    } as any);
    expect(res.status).toBe(404);
  });

  it("returns 400 when path RPN is malformed", async () => {
    const env = makeEnv();
    const res = await onRequestGet({
      request: new Request("https://x/v2/packages/garbage"),
      env,
      params: { rpn: "garbage" },
    } as any);
    expect(res.status).toBe(400);
  });
});
