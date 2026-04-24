import { describe, it, expect } from "vitest";
import { redactRobotRecord } from "./redact.js";

describe("redactRobotRecord", () => {
  it("strips api_key", () => {
    const input = { rrn: "RRN-000000000001", api_key: "secret", name: "bob" };
    expect(redactRobotRecord(input)).toEqual({ rrn: "RRN-000000000001", name: "bob" });
  });

  it("returns a new object (does not mutate input)", () => {
    const input = { rrn: "RRN-000000000001", api_key: "secret" };
    redactRobotRecord(input);
    expect(input.api_key).toBe("secret");
  });

  it("handles records without api_key (no-op)", () => {
    const input = { rrn: "RRN-000000000001", name: "bob" };
    expect(redactRobotRecord(input)).toEqual(input);
  });
});
