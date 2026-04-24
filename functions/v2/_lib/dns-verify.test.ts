// functions/v2/_lib/dns-verify.test.ts
import { describe, it, expect, vi } from "vitest";
import { verifyDnsTxt } from "./dns-verify.js";

const RRN = "RRN-000000000042";
const MODEL = "turtlebot3_burger";
const DOMAIN = "robotis.com";
const EXPECTED_TXT = `rrn=${RRN};model=${MODEL}`;

function dohAnswer(txts: string[], status = 0) {
  return new Response(
    JSON.stringify({
      Status: status,
      Answer: txts.map((t) => ({ name: `_rcan-verify.${DOMAIN}`, type: 16, TTL: 60, data: `"${t}"` })),
    }),
    { status: 200, headers: { "Content-Type": "application/dns-json" } },
  );
}

describe("verifyDnsTxt", () => {
  it("accepts a valid TXT record matching rrn;model", async () => {
    const fetchFn = vi.fn(async () => dohAnswer([EXPECTED_TXT]));
    const res = await verifyDnsTxt(DOMAIN, RRN, MODEL, fetchFn);
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.evidence).toBe(EXPECTED_TXT);
    // Sanity: fetch URL must include the DoH host and TXT type.
    expect(fetchFn).toHaveBeenCalledTimes(1);
    const url = (fetchFn.mock.calls[0]?.[0] as string) ?? "";
    expect(url).toMatch(/^https:\/\/cloudflare-dns\.com\/dns-query\?/);
    expect(url).toContain(`name=_rcan-verify.${DOMAIN}`);
    expect(url).toContain("type=TXT");
  });

  it("returns error when no TXT record exists (empty Answer, Status=0)", async () => {
    const fetchFn = vi.fn(async () => new Response(
      JSON.stringify({ Status: 0 }),
      { status: 200, headers: { "Content-Type": "application/dns-json" } },
    ));
    const res = await verifyDnsTxt(DOMAIN, RRN, MODEL, fetchFn);
    expect(res.ok).toBe(false);
  });

  it("returns error when TXT exists but rrn field does not match", async () => {
    const wrongRrn = `rrn=RRN-000000000999;model=${MODEL}`;
    const fetchFn = vi.fn(async () => dohAnswer([wrongRrn]));
    const res = await verifyDnsTxt(DOMAIN, RRN, MODEL, fetchFn);
    expect(res.ok).toBe(false);
  });

  it("returns error when TXT exists but model field does not match", async () => {
    const wrongModel = `rrn=${RRN};model=some-other-model`;
    const fetchFn = vi.fn(async () => dohAnswer([wrongModel]));
    const res = await verifyDnsTxt(DOMAIN, RRN, MODEL, fetchFn);
    expect(res.ok).toBe(false);
  });

  it("accepts when multiple TXT records are returned and one matches", async () => {
    const fetchFn = vi.fn(async () => dohAnswer([
      "rrn=RRN-000000000999;model=other-model",
      "some-unrelated=record",
      EXPECTED_TXT,
    ]));
    const res = await verifyDnsTxt(DOMAIN, RRN, MODEL, fetchFn);
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.evidence).toBe(EXPECTED_TXT);
  });

  it("returns error on DoH 5xx (never throws)", async () => {
    const fetchFn = vi.fn(async () => new Response("server error", { status: 503 }));
    const res = await verifyDnsTxt(DOMAIN, RRN, MODEL, fetchFn);
    expect(res.ok).toBe(false);
  });

  it("returns error on network failure (fetch throws, never rethrown)", async () => {
    const fetchFn = vi.fn(async () => { throw new TypeError("fetch failed"); });
    const res = await verifyDnsTxt(DOMAIN, RRN, MODEL, fetchFn);
    expect(res.ok).toBe(false);
  });

  it("rejects domain with newline injection attempt", async () => {
    const fetchFn = vi.fn();
    const res = await verifyDnsTxt("evil.com\nattacker.com", RRN, MODEL, fetchFn);
    expect(res.ok).toBe(false);
    // Critically, the verifier must NOT attempt the DoH request with a bogus domain.
    expect(fetchFn).not.toHaveBeenCalled();
  });
});
