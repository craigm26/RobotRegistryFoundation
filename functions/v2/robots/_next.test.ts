import { describe, expect, it, vi } from "vitest";

import { onRequestGet } from "./_next.js";
import { RESERVED_FLOORS } from "../_lib/id.js";

function makeFakeKv(seed: Record<string, string> = {}) {
  const store: Record<string, string> = { ...seed };
  return {
    get: vi.fn(async (k: string, _opts?: unknown) => store[k] ?? null),
    put: vi.fn(async (k: string, v: string) => {
      store[k] = v;
    }),
    list: vi.fn(),
    delete: vi.fn(async (k: string) => {
      delete store[k];
    }),
  };
}

function ctx(kv: ReturnType<typeof makeFakeKv>) {
  return {
    env: { RRF_KV: kv as unknown as KVNamespace },
  } as unknown as Parameters<typeof onRequestGet>[0];
}

describe("GET /v2/robots/_next", () => {
  const FLOOR = RESERVED_FLOORS.RRN ?? 10;

  it("returns the reserved floor on a fresh counter", async () => {
    const kv = makeFakeKv({});
    const res = await onRequestGet(ctx(kv));
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.next_rrn).toBe(`RRN-${String(FLOOR).padStart(12, "0")}`);
    expect(body.reserved_floor).toBe(FLOOR);
  });

  it("returns the live next-seq when counter is above the floor", async () => {
    const kv = makeFakeKv({ "counter:rrn": String(FLOOR + 7) });
    const res = await onRequestGet(ctx(kv));
    const body = await res.json();
    expect(body.next_rrn).toBe(`RRN-${String(FLOOR + 8).padStart(12, "0")}`);
  });

  it("never advances the counter (read-only)", async () => {
    const kv = makeFakeKv({ "counter:rrn": "5" });
    await onRequestGet(ctx(kv));
    expect(kv.put).not.toHaveBeenCalled();
  });

  it("sets Cache-Control: no-store so previews are never stale", async () => {
    const kv = makeFakeKv({});
    const res = await onRequestGet(ctx(kv));
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });
});
