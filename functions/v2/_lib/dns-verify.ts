// functions/v2/_lib/dns-verify.ts
/**
 * Server-side DoH-based DNS TXT verifier for the manufacturer_claimed tier.
 *
 * Looks up `_rcan-verify.<domain>` via Cloudflare's DoH endpoint and confirms
 * there is a TXT record of the form `rrn=<rrn>;model=<model>`. The expected
 * format is defined in rcan-spec/docs/verification/manufacturer-verification.md.
 *
 * The verifier:
 *   - Validates `domain` to prevent DoH query injection (no whitespace, no
 *     semicolons, no leading/trailing dots).
 *   - Uses a caller-injectable `fetchFn` for testability.
 *   - Never throws: any DoH non-2xx / network error returns {ok:false, error:...}.
 *
 * The lookup is authoritative for the moment of verification only (one-shot).
 * Long-lived re-verification is a future task.
 */

export interface VerifyDnsTxtResult { ok: true; evidence: string }
export interface VerifyDnsTxtError { ok: false; error: string }
export type VerifyDnsTxtOutcome = VerifyDnsTxtResult | VerifyDnsTxtError;

const DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query";
const INVALID_DOMAIN_CHARS = /[\s;\x00-\x1f\x7f]/;

function isValidDomain(domain: string): boolean {
  if (typeof domain !== "string" || domain.length === 0 || domain.length > 253) return false;
  if (INVALID_DOMAIN_CHARS.test(domain)) return false;
  if (domain.startsWith(".") || domain.endsWith(".")) return false;
  return true;
}

interface DohAnswer { name?: string; type?: number; TTL?: number; data?: string }
interface DohResponse { Status?: number; Answer?: DohAnswer[] }

function stripTxtQuotes(raw: string): string {
  // DoH JSON wraps TXT data in surrounding double quotes. Strip once.
  if (raw.length >= 2 && raw[0] === '"' && raw[raw.length - 1] === '"') {
    return raw.slice(1, -1);
  }
  return raw;
}

export async function verifyDnsTxt(
  domain: string,
  expectedRrn: string,
  expectedModel: string,
  fetchFn: typeof fetch = fetch,
): Promise<VerifyDnsTxtOutcome> {
  if (!isValidDomain(domain)) return { ok: false, error: "Invalid domain" };

  const name = `_rcan-verify.${domain}`;
  const url = `${DOH_ENDPOINT}?name=${encodeURIComponent(name)}&type=TXT`;

  let response: Response;
  try {
    response = await fetchFn(url, { headers: { "Accept": "application/dns-json" } });
  } catch (e: any) {
    return { ok: false, error: `DoH unreachable: ${e?.message ?? "unknown"}` };
  }

  if (!response.ok) {
    return { ok: false, error: `DoH returned ${response.status}` };
  }

  let doh: DohResponse;
  try {
    doh = (await response.json()) as DohResponse;
  } catch {
    return { ok: false, error: "DoH response was not valid JSON" };
  }

  if (doh.Status !== 0 || !Array.isArray(doh.Answer) || doh.Answer.length === 0) {
    return { ok: false, error: "No TXT record" };
  }

  const expected = `rrn=${expectedRrn};model=${expectedModel}`;
  for (const answer of doh.Answer) {
    if (answer.type !== 16 || typeof answer.data !== "string") continue;
    const raw = stripTxtQuotes(answer.data);
    if (raw === expected) return { ok: true, evidence: raw };
  }

  return { ok: false, error: "TXT record format did not match" };
}
