import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";

const SCRIPT = resolve(__dirname, "..", "scripts", "register-operator-kid.ts");

function runOk(args: string[]): { kvBulk: Array<{ key: string; value: string }> } {
  const stdout = execFileSync("npx", ["tsx", SCRIPT, ...args], { encoding: "utf-8" });
  const kvBulk = JSON.parse(stdout);
  return { kvBulk };
}

function runFail(args: string[]): { stderr: string; status: number } {
  try {
    execFileSync("npx", ["tsx", SCRIPT, ...args], { encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] });
    return { stderr: "", status: 0 };
  } catch (e: unknown) {
    const err = e as { stderr?: Buffer; status?: number };
    return { stderr: err.stderr?.toString() ?? "", status: err.status ?? 1 };
  }
}

const VALID_ARGS = [
  "--kid", "bob-operator-2026",
  "--ran", "RAN-000000000019",
  "--signing-pub-b64", Buffer.from(new Uint8Array(32)).toString("base64"),
  "--pq-signing-pub-b64", Buffer.from(new Uint8Array(1952)).toString("base64"),
  "--pq-kid", "deadbeef",
  "--organization", "OpenCastor",
  "--display-name", "bob-operator-2026 — Phase 5 INVOKE signer for Bob",
  "--purpose", "operator-envelope",
  "--registered-by", "RAN-000000000018",
  "--valid-from", "2026-05-04T15:00:00.000Z",
];

describe("register-operator-kid.ts", () => {
  it("emits a kid:<kid>:<ts> + authority:<ran> bulk-put pair on valid args", () => {
    const { kvBulk } = runOk(VALID_ARGS);
    expect(kvBulk).toHaveLength(2);
    const kidRecord = kvBulk.find(r => r.key.startsWith("kid:bob-operator-2026:"));
    const authRecord = kvBulk.find(r => r.key === "authority:RAN-000000000019");
    expect(kidRecord).toBeDefined();
    expect(authRecord).toBeDefined();
    const kidVal = JSON.parse(kidRecord!.value);
    expect(kidVal.ran).toBe("RAN-000000000019");
    expect(kidVal.valid_from).toBe("2026-05-04T15:00:00.000Z");
    expect(kidVal.registered_by).toBe("RAN-000000000018");
    const authVal = JSON.parse(authRecord!.value);
    expect(authVal.ran).toBe("RAN-000000000019");
    expect(authVal.organization).toBe("OpenCastor");
    expect(authVal.purpose).toBe("operator-envelope");
    expect(authVal.signing_alg).toEqual(["Ed25519", "ML-DSA-65"]);
    expect(authVal.status).toBe("active");
    expect(authVal.signing_pub.length).toBeGreaterThan(0);
    expect(authVal.pq_signing_pub.length).toBeGreaterThan(0);
    expect(authVal.pq_kid).toBe("deadbeef");
  });

  it("rejects an Ed25519 pubkey that doesn't decode to 32 bytes", () => {
    const args = [...VALID_ARGS];
    const idx = args.indexOf("--signing-pub-b64");
    args[idx + 1] = Buffer.from(new Uint8Array(31)).toString("base64");
    const { stderr, status } = runFail(args);
    expect(status).not.toBe(0);
    expect(stderr).toMatch(/32 bytes/);
  });

  it("rejects an ML-DSA-65 pubkey that doesn't decode to 1952 bytes", () => {
    const args = [...VALID_ARGS];
    const idx = args.indexOf("--pq-signing-pub-b64");
    args[idx + 1] = Buffer.from(new Uint8Array(100)).toString("base64");
    const { stderr, status } = runFail(args);
    expect(status).not.toBe(0);
    expect(stderr).toMatch(/1952 bytes/);
  });

  it("rejects a malformed RAN", () => {
    const args = [...VALID_ARGS];
    const idx = args.indexOf("--ran");
    args[idx + 1] = "not-a-ran";
    const { stderr, status } = runFail(args);
    expect(status).not.toBe(0);
    expect(stderr).toMatch(/RAN-/);
  });

  it("rejects an 8-hex pq_kid that's not 8 hex chars", () => {
    const args = [...VALID_ARGS];
    const idx = args.indexOf("--pq-kid");
    args[idx + 1] = "deadbeef99";
    const { stderr, status } = runFail(args);
    expect(status).not.toBe(0);
    expect(stderr).toMatch(/pq-kid/);
  });
});
