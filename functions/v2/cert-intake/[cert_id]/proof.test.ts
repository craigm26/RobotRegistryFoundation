import { describe, it, expect, vi } from "vitest";
import { onRequestGet } from "./proof.js";

function makeEnv(initial: Record<string, string> = {}) {
  const store: Record<string, string> = { ...initial };
  return {
    env: {
      RRF_KV: {
        get: vi.fn(async (k: string) => store[k] ?? null),
        put: vi.fn(),
        list: vi.fn(async ({ prefix, cursor }: { prefix: string; cursor?: string }) => {
          const allKeys = Object.keys(store).filter(k => k.startsWith(prefix)).sort();
          const start = cursor ? allKeys.indexOf(cursor) + 1 : 0;
          const slice = allKeys.slice(start, start + 1000);
          const nextCursor = (start + 1000) < allKeys.length ? slice[slice.length - 1] : undefined;
          return {
            keys: slice.map(name => ({ name })),
            list_complete: !nextCursor,
            cursor: nextCursor,
          };
        }),
        delete: vi.fn(),
      } as unknown as KVNamespace,
    },
    store,
  };
}

describe("GET /v2/cert-intake/{cert_id}/proof", () => {
  it("returns 200 with the log entry when found", async () => {
    const certId = "cert_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const { env } = makeEnv({
      "cert-intake-log:000000000001": JSON.stringify({
        cert_id: certId,
        rrn: "RRN-000000000002",
        property_id: "SF-001",
        transparency_log_index: 1,
        rrf_log_signature: { kid: "rrf-root", alg: "Ed25519", sig: "x" },
      }),
    });
    const res = await onRequestGet({ env, params: { cert_id: certId } } as unknown as Parameters<typeof onRequestGet>[0]);
    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;
    expect(body.cert_id).toBe(certId);
    expect(body.transparency_log_index).toBe(1);
  });

  it("returns 404 when cert_id is not found", async () => {
    const { env } = makeEnv();
    const res = await onRequestGet({ env, params: { cert_id: "cert_nonexistent" } } as unknown as Parameters<typeof onRequestGet>[0]);
    expect(res.status).toBe(404);
  });

  it("returns 400 on malformed cert_id (no cert_ prefix)", async () => {
    const { env } = makeEnv();
    const res = await onRequestGet({ env, params: { cert_id: "garbage-no-prefix" } } as unknown as Parameters<typeof onRequestGet>[0]);
    expect(res.status).toBe(400);
  });

  it("paginates over >1000 log entries (Plan 4 fix-loop)", async () => {
    const targetId = "cert_target";
    const initial: Record<string, string> = {};
    for (let i = 1; i <= 1500; i++) {
      const id = i === 1500 ? targetId : `cert_${i.toString().padStart(32, "0")}`;
      initial[`cert-intake-log:${i.toString().padStart(12, "0")}`] = JSON.stringify({
        cert_id: id,
        transparency_log_index: i,
      });
    }
    const { env } = makeEnv(initial);
    const res = await onRequestGet({ env, params: { cert_id: targetId } } as unknown as Parameters<typeof onRequestGet>[0]);
    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;
    expect(body.cert_id).toBe(targetId);
    expect(body.transparency_log_index).toBe(1500);
  });
});
