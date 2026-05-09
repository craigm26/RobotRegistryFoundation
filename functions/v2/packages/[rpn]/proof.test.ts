import { describe, it, expect, vi } from "vitest";
import { onRequestGet } from "./proof.js";

function makeEnv(stored: string | null) {
  return {
    RRF_KV: {
      get: vi.fn(async (key: string) => {
        if (key.startsWith("package-proof:")) return stored;
        return null;
      }),
      put: vi.fn(),
      list: vi.fn(),
      delete: vi.fn(),
    },
  };
}

describe("GET /v2/packages/[rpn]/proof", () => {
  it("returns the stored signed body when present", async () => {
    const stored = JSON.stringify({
      name: "robot-md-example-actuator",
      version: "0.1.0",
      pq_signing_pub: "BASE64",
      pq_kid: "publisher-x",
      ed25519_pub: "BASE64",
      sig: { ml_dsa: "...", ed25519: "...", ed25519_pub: "..." },
    });
    const env = makeEnv(stored);
    const res = await onRequestGet({
      env,
      params: { rpn: "RPN-000000000001" },
    } as any);
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toContain("application/json");
    expect(await res.json()).toEqual(JSON.parse(stored));
  });

  it("returns 404 when no proof exists", async () => {
    const env = makeEnv(null);
    const res = await onRequestGet({
      env,
      params: { rpn: "RPN-000000000999" },
    } as any);
    expect(res.status).toBe(404);
  });

  it("returns 400 on malformed RPN", async () => {
    const env = makeEnv(null);
    const res = await onRequestGet({
      env,
      params: { rpn: "garbage" },
    } as any);
    expect(res.status).toBe(400);
  });
});
