/**
 * Test-only helpers. Do NOT import from production handler code.
 */

import { signBody, generateMlDsaKeypair } from "rcan-ts";
import { ed25519 } from "@noble/curves/ed25519.js";

export interface TestKeypair {
  mlDsa: { publicKey: Uint8Array; privateKey: Uint8Array };
  ed25519Secret: Uint8Array;
  ed25519Public: Uint8Array;
}

export async function makeTestKeypair(): Promise<TestKeypair> {
  const mlDsa = generateMlDsaKeypair();  // sync
  const ed25519Secret = crypto.getRandomValues(new Uint8Array(32));
  const ed25519Public = ed25519.getPublicKey(ed25519Secret);
  return { mlDsa, ed25519Secret, ed25519Public };
}

export async function signComplianceBody(
  doc: Record<string, unknown>,
  kp: TestKeypair,
): Promise<Record<string, unknown>> {
  return signBody(kp.mlDsa, doc, {
    ed25519Secret: kp.ed25519Secret,
    ed25519Public: kp.ed25519Public,
  });
}

export function makeRobotRecord(rrn: string, kp: TestKeypair): string {
  const pq_signing_pub = btoa(String.fromCharCode(...kp.mlDsa.publicKey));
  return JSON.stringify({
    rrn, name: "test", manufacturer: "test", model: "test",
    firmware_version: "1.0", rcan_version: "3.0",
    pq_signing_pub,
    pq_kid: "testkid1",
    registered_at: "2026-04-23T00:00:00Z",
  });
}
