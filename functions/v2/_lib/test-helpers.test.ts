import { describe, it, expect } from "vitest";
import { verifyBody } from "rcan-ts";
import { signComplianceBody, makeTestKeypair } from "./test-helpers.js";

describe("signComplianceBody", () => {
  it("produces a body that verifyBody accepts", async () => {
    const kp = await makeTestKeypair();
    const doc = { schema: "rcan-safety-benchmark-v1", rrn: "RRN-000000000001", version: "1.0" };
    const signed = await signComplianceBody(doc, kp);

    expect(signed.pq_signing_pub).toBeTypeOf("string");
    expect(signed.pq_kid).toBeTypeOf("string");
    expect((signed.sig as any).ml_dsa).toBeTypeOf("string");
    expect((signed.sig as any).ed25519).toBeTypeOf("string");
    expect((signed.sig as any).ed25519_pub).toBeTypeOf("string");

    const pqPub = Uint8Array.from(atob(signed.pq_signing_pub as string), c => c.charCodeAt(0));
    const ok = await verifyBody(signed, pqPub);
    expect(ok).toBe(true);
  });

  it("round-trip fails if body is tampered", async () => {
    const kp = await makeTestKeypair();
    const doc = { schema: "rcan-safety-benchmark-v1", rrn: "RRN-000000000001" };
    const signed = await signComplianceBody(doc, kp);
    const tampered = { ...signed, rrn: "RRN-000000000002" };

    const pqPub = Uint8Array.from(atob(tampered.pq_signing_pub as string), c => c.charCodeAt(0));
    const ok = await verifyBody(tampered, pqPub);
    expect(ok).toBe(false);
  });
});
