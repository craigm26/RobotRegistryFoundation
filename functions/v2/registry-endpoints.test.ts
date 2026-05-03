/**
 * Tests for Plan 6 Task 5 — R1/R2/R3/R7 registry endpoints.
 */

import { describe, it, expect } from "vitest";
import { onRequest as onVersions } from "./versions.js";
import { onRequest as onMessageTypes } from "./message-types.js";
import { onRequest as onCryptoProfiles } from "./crypto-profiles.js";
import { onRequest as onP66Schemas } from "./p66-schemas.js";

function makeReq(method: string = "GET"): Parameters<PagesFunction>[0] {
  return {
    request: new Request("https://robotregistryfoundation.org/v2/versions", { method }),
  } as unknown as Parameters<PagesFunction>[0];
}

describe("R1 /v2/versions", () => {
  it("returns matrix_version + protocol_versions[]", async () => {
    const r = await onVersions(makeReq());
    expect(r.status).toBe(200);
    const body = await r.json();
    expect(body.matrix_version).toBeDefined();
    expect(Array.isArray(body.protocol_versions)).toBe(true);
    expect(body.protocol_versions.length).toBeGreaterThan(0);
    expect(body.protocol_versions[0]).toHaveProperty("version");
  });

  it("405s on POST", async () => {
    const r = await onVersions(makeReq("POST"));
    expect(r.status).toBe(405);
  });
});

describe("R2 /v2/message-types", () => {
  it("returns message_types with name + since_version", async () => {
    const r = await onMessageTypes(makeReq());
    expect(r.status).toBe(200);
    const body = await r.json();
    expect(Array.isArray(body.message_types)).toBe(true);
    for (const m of body.message_types) {
      expect(m).toHaveProperty("name");
      expect(m).toHaveProperty("since_version");
    }
  });
});

describe("R3 /v2/crypto-profiles", () => {
  it("returns profiles including ed25519", async () => {
    const r = await onCryptoProfiles(makeReq());
    expect(r.status).toBe(200);
    const body = await r.json();
    expect(Array.isArray(body.profiles)).toBe(true);
    expect(body.profiles.some((p: { name: string }) => p.name === "ed25519")).toBe(true);
  });
});

describe("R7 /v2/p66-schemas", () => {
  it("returns named JSON schemas", async () => {
    const r = await onP66Schemas(makeReq());
    expect(r.status).toBe(200);
    const body = await r.json();
    expect(Array.isArray(body.schemas)).toBe(true);
    expect(body.schemas.length).toBeGreaterThan(0);
    expect(body.schemas[0]).toHaveProperty("id");
  });
});
