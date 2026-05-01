import { describe, it, expect } from "vitest";
import { onRequest } from "./[version].js";

function req(version: string) {
  return new Request(`https://x/v1/spatial-eval/spec/${version}`, { method: "GET" });
}

describe("GET /v1/spatial-eval/spec/[version]", () => {
  it("returns the registered v1.0.0 RRF pubkey", async () => {
    const res = await onRequest({
      request: req("1.0.0"),
      params: { version: "1.0.0" },
    } as any);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.spec_version).toBe("1.0.0");
    expect(body.rrf_pubkey_alg).toBe("ml-dsa-65");
    expect(typeof body.rrf_pubkey).toBe("string");
    expect(body.rrf_pubkey.length).toBeGreaterThan(100); // ML-DSA-65 pubkey is 1952 bytes ≈ 2604 b64 chars
    expect(body.leaderboard_url).toContain("/leaderboard/spatial-eval/1.0.0");
  });

  it("returns 404 for unknown spec version", async () => {
    const res = await onRequest({
      request: req("9.9.9"),
      params: { version: "9.9.9" },
    } as any);
    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body.available).toContain("1.0.0");
  });

  it("returns 400 on malformed version", async () => {
    const res = await onRequest({
      request: req("not-semver"),
      params: { version: "not-semver" },
    } as any);
    expect(res.status).toBe(400);
  });

  it("returns 405 on non-GET", async () => {
    const res = await onRequest({
      request: new Request("https://x/v1/spatial-eval/spec/1.0.0", { method: "POST" }),
      params: { version: "1.0.0" },
    } as any);
    expect(res.status).toBe(405);
  });
});
