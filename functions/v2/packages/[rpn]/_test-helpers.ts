/**
 * Test helper — re-signs a body dict with the package fixture keypair.
 *
 * Used by versions.test.ts, revoke.test.ts, and transfer.test.ts so each
 * file imports one function instead of repeating keypair-decode boilerplate.
 */

import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { signBody } from "rcan-ts";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fx = JSON.parse(
  readFileSync(resolve(__dirname, "../../../_lib/fixtures/package-fixture.json"), "utf8"),
);

function b64Decode(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

const kp = {
  privateKey: b64Decode(fx.keypair.pq_signing_sec_b64),
  publicKey:  b64Decode(fx.keypair.pq_signing_pub_b64),
};
const opts = {
  ed25519Secret: b64Decode(fx.keypair.ed25519_sec_b64),
  ed25519Public: b64Decode(fx.keypair.ed25519_pub_b64),
};

/**
 * Sign `body` with the fixture publisher keypair.
 * Returns the signed dict ready to JSON-stringify into a request body.
 */
export async function signBodyWithFixtureKp(
  body: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  return signBody(kp, body, opts);
}

/** Fixture publisher block — stored on PackageRecord.publisher in tests. */
export const fixturePublisher = {
  pq_signing_pub: fx.keypair.pq_signing_pub_b64,
  pq_kid:         fx.keypair.pq_kid,
  ed25519_pub:    fx.keypair.ed25519_pub_b64,
};
