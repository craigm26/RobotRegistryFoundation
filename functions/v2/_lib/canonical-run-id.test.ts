import { describe, it, expect } from "vitest";
import { computeRunId } from "./canonical-run-id.js";

describe("computeRunId", () => {
  const baseBody = {
    schema_version: "1.0",
    gateway_ran: "RAN-000000000019",
    started_at: "2026-05-09T20:00:00Z",
    finished_at: "2026-05-09T20:00:01Z",
    outcome_kind: "no_op",
    outcome_detail: "stub",
    skill_manifest_sha256: "a".repeat(64),
    actuator_name: "robot-md-example-actuator",
    tier: "L0",
    pq_signing_pub: "BASE64==",
    pq_kid: "k1",
    ed25519_pub: "BASE64==",
  };

  it("returns runbundle_<12-hex>", async () => {
    const id = await computeRunId(baseBody);
    expect(id).toMatch(/^runbundle_[0-9a-f]{12}$/);
  });

  it("is stable across calls for identical input", async () => {
    const id1 = await computeRunId(baseBody);
    const id2 = await computeRunId(baseBody);
    expect(id1).toBe(id2);
  });

  it("changes when any non-excluded field changes", async () => {
    const id1 = await computeRunId(baseBody);
    const id2 = await computeRunId({ ...baseBody, outcome_kind: "success" });
    expect(id1).not.toBe(id2);
  });

  it("ignores `sig` field (excluded from hash input)", async () => {
    const id1 = await computeRunId(baseBody);
    const id2 = await computeRunId({ ...baseBody, sig: { ml_dsa: "x", ed25519: "y", ed25519_pub: "z" } });
    expect(id1).toBe(id2);
  });

  it("ignores existing `run_id` field (excluded from hash input)", async () => {
    const id1 = await computeRunId(baseBody);
    const id2 = await computeRunId({ ...baseBody, run_id: "runbundle_aaaaaaaaaaaa" });
    expect(id1).toBe(id2);
  });
});
