import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const PY = "/home/craigm26/rcan-py/.venv/bin/python";
const MINT = resolve(__dirname, "..", "scripts", "mint-attestation-kid.py");
const REGISTER = resolve(__dirname, "..", "scripts", "register-operator-kid.ts");

// Reproduces the runbook's register step: mint → feed manifest values into
// register-operator-kid.ts → assert the wrangler-kv-bulk-put pair is well-formed.
describe("U1b runbook — register-operator-kid.ts emits the attestation KV pair", () => {
  it("produces kid:<kid>:<ts> + authority:<ran> with purpose=attestation, org=OpenCastor", () => {
    const dir = mkdtempSync(join(tmpdir(), "u1b-"));
    execFileSync(PY, [MINT, "--organization", "OpenCastor", "--display-name",
      "Bob gateway attestation signer", "--out-dir", dir], { encoding: "utf-8" });
    const m = JSON.parse(readFileSync(join(dir, "mint-manifest.json"), "utf-8"));

    const kid = "bob-gw-attest-2026";
    const ran = "RAN-000000000021";
    const stdout = execFileSync("npx", ["tsx", REGISTER,
      "--kid", kid,
      "--ran", ran,
      "--signing-pub-b64", m.signing_pub_b64,
      "--pq-signing-pub-b64", m.pq_signing_pub_b64,
      "--pq-kid", m.pq_kid,
      "--organization", "OpenCastor",
      "--display-name", "Bob gateway attestation signer",
      "--purpose", "attestation",
      "--registered-by", "RAN-000000000018",
      "--valid-from", "2026-06-06T00:00:00.000Z",
    ], { encoding: "utf-8" });

    const bulk = JSON.parse(stdout) as Array<{ key: string; value: string }>;
    expect(bulk).toHaveLength(2);
    const kidRec = bulk.find((r) => r.key.startsWith(`kid:${kid}:`));
    const authRec = bulk.find((r) => r.key === `authority:${ran}`);
    expect(kidRec).toBeDefined();
    expect(authRec).toBeDefined();
    const auth = JSON.parse(authRec!.value);
    expect(auth.ran).toBe(ran);
    expect(auth.organization).toBe("OpenCastor");
    expect(auth.purpose).toBe("attestation");
    expect(auth.signing_alg).toEqual(["Ed25519", "ML-DSA-65"]);
    expect(auth.pq_kid).toBe(m.pq_kid);
    expect(Buffer.from(auth.signing_pub, "base64").length).toBe(32);
    expect(Buffer.from(auth.pq_signing_pub, "base64").length).toBe(1952);
    const kidVal = JSON.parse(kidRec!.value);
    expect(kidVal.ran).toBe(ran);
    expect(kidVal.valid_from).toBe("2026-06-06T00:00:00.000Z");
  });
});
