import { describe, it, expect, vi } from "vitest";
import { onRequest } from "./eu-register.js";
import { buildEuRegisterEntry, EU_REGISTER_SCHEMA } from "rcan-ts";
import { signComplianceBody, makeTestKeypair, makeRobotRecord } from "../../_lib/test-helpers.js";

const RRN = "RRN-000000000001";
const RMN = "RMN-000000000007";

function makeEnv(init: Record<string, string> = {}) {
  const store: Record<string, string> = { ...init };
  return {
    RRF_KV: {
      get: vi.fn(async (k: string) => store[k] ?? null),
      put: vi.fn(async (k: string, v: string) => { store[k] = v; }),
      list: vi.fn(), delete: vi.fn(),
    } as unknown as KVNamespace,
    __store: store,
  };
}

function req(method: string, body?: unknown, headers: Record<string, string> = {}): Request {
  return new Request(`https://x/v2/models/${RMN}/eu-register`, {
    method,
    headers: { "Content-Type": "application/json", ...headers },
    body: body ? JSON.stringify(body) : undefined,
  });
}

function validEntryInput(rmn: string = RMN) {
  return {
    rmn,
    fria_ref: "bob-fria-v1.json",
    provider: { name: "craigm26", contact: "craigm26@gmail.com" },
    system: {
      rrn: RRN,
      rrn_uri: "rrn://craigm26/robot/opencastor-rpi5-hailo-soarm101/bob-001",
      robot_name: "Bob",
      rcan_version: "3.1",
      opencastor_version: "2026.4.24.0",
    },
    annex_iii_basis: "Annex III §5(b)",
    generated_at: "2026-04-24T00:00:00Z",
  };
}

describe("GET /v2/models/[rmn]/eu-register (public)", () => {
  it("returns 404 when nothing submitted", async () => {
    const env = makeEnv();
    const res = await onRequest({ request: req("GET"), env, params: { rmn: RMN } } as any);
    expect(res.status).toBe(404);
  });

  it("returns 400 on invalid RMN format", async () => {
    const env = makeEnv();
    const res = await onRequest({ request: req("GET"), env, params: { rmn: "bad" } } as any);
    expect(res.status).toBe(400);
  });

  it("returns stored doc with cache header", async () => {
    const env = makeEnv({ [`compliance:eu-register:${RMN}`]: JSON.stringify({ schema: EU_REGISTER_SCHEMA, rmn: RMN }) });
    const res = await onRequest({ request: req("GET"), env, params: { rmn: RMN } } as any);
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toContain("max-age=300");
  });
});

describe("POST /v2/models/[rmn]/eu-register", () => {
  it("derives submitter from signed doc.system.rrn (no header needed) and returns 201", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const doc = buildEuRegisterEntry(validEntryInput());
    const signed = await signComplianceBody(doc as unknown as Record<string, unknown>, kp);
    const res = await onRequest({
      request: req("POST", signed),  // no X-Submitter-RRN
      env, params: { rmn: RMN },
    } as any);
    expect(res.status).toBe(201);

    const stored = JSON.parse(env.__store[`compliance:eu-register:${RMN}`]);
    expect(stored.rmn).toBe(RMN);
    expect(stored._submitted_by_rrn).toBe(RRN);
    expect(stored._received_at).toBeTypeOf("string");
    expect(Object.keys(env.__store).filter(k => k.startsWith(`compliance:eu-register:history:${RMN}:`)).length).toBe(1);
  });

  it("ignores X-Submitter-RRN header; submitter comes from signed payload", async () => {
    // Attacker sends a doc signed by RRN-A but claims RRN-B via header.
    // The server must trust the signed doc.system.rrn, not the header.
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const doc = buildEuRegisterEntry(validEntryInput());
    const signed = await signComplianceBody(doc as unknown as Record<string, unknown>, kp);
    const res = await onRequest({
      request: req("POST", signed, { "X-Submitter-RRN": "RRN-000000009999" }),
      env, params: { rmn: RMN },
    } as any);
    expect(res.status).toBe(201);

    const stored = JSON.parse(env.__store[`compliance:eu-register:${RMN}`]);
    expect(stored._submitted_by_rrn).toBe(RRN);  // from signed doc, NOT from header
  });

  it("400 when signed doc is missing system.rrn", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const malformed = { schema: EU_REGISTER_SCHEMA, rmn: RMN, generated_at: "2026-04-24T00:00:00Z" };
    const signed = await signComplianceBody(malformed, kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rmn: RMN } } as any);
    expect(res.status).toBe(400);
  });

  it("400 when doc.system.rrn format is invalid", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const malformed = {
      schema: EU_REGISTER_SCHEMA, rmn: RMN,
      system: { rrn: "not-a-valid-rrn" }, generated_at: "2026-04-24T00:00:00Z",
    };
    const signed = await signComplianceBody(malformed, kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rmn: RMN } } as any);
    expect(res.status).toBe(400);
  });

  it("401 when submitter robot (from signed doc) not registered", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv();  // no robot record
    const doc = buildEuRegisterEntry(validEntryInput());
    const signed = await signComplianceBody(doc as unknown as Record<string, unknown>, kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rmn: RMN } } as any);
    expect(res.status).toBe(401);
  });

  it("401 on tampered body", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const doc = buildEuRegisterEntry(validEntryInput());
    const signed = await signComplianceBody(doc as unknown as Record<string, unknown>, kp);
    const tampered = { ...signed, annex_iii_basis: "modified after signing" };
    const res = await onRequest({ request: req("POST", tampered), env, params: { rmn: RMN } } as any);
    expect(res.status).toBe(401);
  });

  it("400 on wrong schema string", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const signed = await signComplianceBody(
      { schema: "rcan-ifu-v1", rmn: RMN, system: { rrn: RRN }, generated_at: "x" }, kp,
    );
    const res = await onRequest({ request: req("POST", signed), env, params: { rmn: RMN } } as any);
    expect(res.status).toBe(400);
  });

  it("400 on doc.rmn != URL rmn", async () => {
    const kp = await makeTestKeypair();
    const env = makeEnv({ [`robot:${RRN}`]: makeRobotRecord(RRN, kp) });
    const doc = buildEuRegisterEntry(validEntryInput("RMN-000000000999"));
    const signed = await signComplianceBody(doc as unknown as Record<string, unknown>, kp);
    const res = await onRequest({ request: req("POST", signed), env, params: { rmn: RMN } } as any);
    expect(res.status).toBe(400);
  });

  it("returns 405 on PUT", async () => {
    const env = makeEnv();
    const res = await onRequest({ request: req("PUT"), env, params: { rmn: RMN } } as any);
    expect(res.status).toBe(405);
  });
});
