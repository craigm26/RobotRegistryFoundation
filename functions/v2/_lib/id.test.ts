import { describe, it, expect, vi } from "vitest";

import {
  EntityPrefix,
  extractPrefix,
  formatId,
  isValidId,
  nextId,
  peekNextSeq,
  prefixToCounterKey,
  RESERVED_FLOORS,
} from "./id.js";

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

describe("id helpers", () => {
  it("formatId zero-pads to 12 digits per prefix", () => {
    expect(formatId("RRN", 1)).toBe("RRN-000000000001");
    expect(formatId("RCN", 42)).toBe("RCN-000000000042");
  });

  it("isValidId accepts canonical IDs and rejects malformed ones", () => {
    expect(isValidId("RRN-000000000001")).toBe(true);
    expect(isValidId("RRN-1")).toBe(false);
    expect(isValidId("garbage")).toBe(false);
  });

  it("extractPrefix returns the prefix or null", () => {
    expect(extractPrefix("RRN-000000000001")).toBe("RRN");
    expect(extractPrefix("garbage")).toBeNull();
  });

  it("prefixToCounterKey maps to lowercase counter", () => {
    expect(prefixToCounterKey("RRN")).toBe("counter:rrn");
    expect(prefixToCounterKey("RPN")).toBe("counter:rpn");
  });
});

describe("RPN prefix", () => {
  it("formats RPN-padded-12-digits", () => {
    expect(formatId("RPN", 1)).toBe("RPN-000000000001");
    expect(formatId("RPN", 9999)).toBe("RPN-000000009999");
  });

  it("isValidId accepts well-formed RPNs and rejects mismatches", () => {
    expect(isValidId("RPN-000000000001", "RPN")).toBe(true);
    expect(isValidId("RPN-000000000001")).toBe(true);
    expect(isValidId("RPN-1", "RPN")).toBe(false);
    expect(isValidId("RRN-000000000001", "RPN")).toBe(false);
  });

  it("nextId allocates monotonically under the rpn counter", async () => {
    const kv = makeFakeKv({ "counter:rpn": "0" });
    expect(await nextId(kv as unknown as KVNamespace, "RPN")).toBe("RPN-000000000001");
    expect(await nextId(kv as unknown as KVNamespace, "RPN")).toBe("RPN-000000000002");
  });

  it("extractPrefix recognizes RPN", () => {
    expect(extractPrefix("RPN-000000000007")).toBe("RPN");
  });
});

describe("RRN reserved floor", () => {
  const FLOOR = RESERVED_FLOORS.RRN ?? 10;

  it("declares a non-trivial floor for RRN", () => {
    expect(FLOOR).toBeGreaterThanOrEqual(2);
  });

  it("nextId on a fresh counter jumps to the reserved floor", async () => {
    const kv = makeFakeKv({});
    expect(await nextId(kv as unknown as KVNamespace, "RRN")).toBe(formatId("RRN", FLOOR));
  });

  it("nextId on a low counter (post-reset) jumps to the reserved floor", async () => {
    // Simulates the post-RRF-reset state where the counter has restarted at 0
    // and would otherwise mint RRN-1, RRN-2, ... and collide with canonical
    // robots Bob (RRN-1) / Alex (RRN-5).
    const kv = makeFakeKv({ "counter:rrn": "0" });
    expect(await nextId(kv as unknown as KVNamespace, "RRN")).toBe(formatId("RRN", FLOOR));
    expect(await nextId(kv as unknown as KVNamespace, "RRN")).toBe(formatId("RRN", FLOOR + 1));
  });

  it("nextId above the floor increments normally", async () => {
    const kv = makeFakeKv({ "counter:rrn": String(FLOOR + 5) });
    expect(await nextId(kv as unknown as KVNamespace, "RRN")).toBe(formatId("RRN", FLOOR + 6));
  });

  it("RPN has no floor and increments from 1", async () => {
    expect(RESERVED_FLOORS.RPN).toBeUndefined();
    const kv = makeFakeKv({});
    expect(await nextId(kv as unknown as KVNamespace, "RPN")).toBe(formatId("RPN", 1));
  });

  it("peekNextSeq reports the floor without incrementing", async () => {
    const kv = makeFakeKv({});
    expect(await peekNextSeq(kv as unknown as KVNamespace, "RRN")).toBe(FLOOR);
    // counter:rrn must not have been written
    expect(kv.put).not.toHaveBeenCalled();
  });

  it("peekNextSeq tracks the live counter when above the floor", async () => {
    const kv = makeFakeKv({ "counter:rrn": String(FLOOR + 3) });
    expect(await peekNextSeq(kv as unknown as KVNamespace, "RRN")).toBe(FLOOR + 4);
  });
});
