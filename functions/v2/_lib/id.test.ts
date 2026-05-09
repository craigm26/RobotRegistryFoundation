import { describe, it, expect, vi } from "vitest";

import {
  EntityPrefix,
  extractPrefix,
  formatId,
  isValidId,
  nextId,
  prefixToCounterKey,
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
