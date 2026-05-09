import { describe, it, expect, vi } from "vitest";
import { onRequestGet } from "./index.js";

function record(rpn: string, name: string, type = "actuator", status: "active" | "revoked" = "active", tags: string[] = []) {
  return {
    rpn, package_type: type, name, hardware_tags: tags,
    versions: [{ version: "1.0.0", released_at: "2026-05-09T00:00:00Z" }],
    publisher: {}, registered_at: "2026-05-09T00:00:00Z", status,
  };
}

function makeEnv(records: ReturnType<typeof record>[]) {
  const store: Record<string, string> = {};
  for (const r of records) {
    store[`package:${r.rpn}`] = JSON.stringify(r);
  }
  // by-type indexes
  const byType: Record<string, string[]> = {};
  for (const r of records) {
    (byType[r.package_type] ??= []).push(r.rpn);
  }
  for (const [type, rpns] of Object.entries(byType)) {
    store[`package-by-type:${type}`] = rpns.join("\n");
  }
  return {
    RRF_KV: {
      get: vi.fn(async (k: string) => store[k] ?? null),
      put: vi.fn(),
      list: vi.fn(),
      delete: vi.fn(),
    },
  };
}

function urlGet(query: string): Request {
  return new Request(`https://x/v2/packages${query}`);
}

describe("GET /v2/packages", () => {
  it("returns all active actuator packages by default", async () => {
    const env = makeEnv([
      record("RPN-000000000001", "feetech-arm"),
      record("RPN-000000000002", "rpi-camera"),
      record("RPN-000000000003", "skill-x", "skill"),
    ]);
    const res = await onRequestGet({ request: urlGet(""), env } as any);
    expect(res.status).toBe(200);
    const body = await res.json() as { packages: any[] };
    expect(body.packages.length).toBe(2);
    expect(body.packages.map((p) => p.name).sort()).toEqual(["feetech-arm", "rpi-camera"]);
  });

  it("filters by ?type=skill", async () => {
    const env = makeEnv([
      record("RPN-000000000001", "feetech-arm", "actuator"),
      record("RPN-000000000002", "skill-x", "skill"),
    ]);
    const res = await onRequestGet({ request: urlGet("?type=skill"), env } as any);
    const body = await res.json() as { packages: any[] };
    expect(body.packages.length).toBe(1);
    expect(body.packages[0].name).toBe("skill-x");
  });

  it("excludes revoked by default", async () => {
    const env = makeEnv([
      record("RPN-000000000001", "active-pkg", "actuator", "active"),
      record("RPN-000000000002", "dead-pkg", "actuator", "revoked"),
    ]);
    const res = await onRequestGet({ request: urlGet(""), env } as any);
    const body = await res.json() as { packages: any[] };
    expect(body.packages.map((p) => p.name)).toEqual(["active-pkg"]);
  });

  it("?include_revoked=1 includes revoked", async () => {
    const env = makeEnv([
      record("RPN-000000000001", "active-pkg", "actuator", "active"),
      record("RPN-000000000002", "dead-pkg", "actuator", "revoked"),
    ]);
    const res = await onRequestGet({ request: urlGet("?include_revoked=1"), env } as any);
    const body = await res.json() as { packages: any[] };
    expect(body.packages.length).toBe(2);
  });

  it("?tag=arm filters by hardware_tag overlap", async () => {
    const env = makeEnv([
      record("RPN-000000000001", "arm-pkg", "actuator", "active", ["arm", "feetech"]),
      record("RPN-000000000002", "cam-pkg", "actuator", "active", ["camera"]),
    ]);
    const res = await onRequestGet({ request: urlGet("?tag=arm"), env } as any);
    const body = await res.json() as { packages: any[] };
    expect(body.packages.length).toBe(1);
    expect(body.packages[0].name).toBe("arm-pkg");
  });
});
