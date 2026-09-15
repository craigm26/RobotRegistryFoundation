/**
 * The one hostname this registry hands out in a response body.
 *
 * Every `*_url` a v2 route returns in a submission receipt must point at a host
 * that actually answers. Until 2026-09-14 the seven compliance submission
 * routes returned receipts against an `api.` subdomain of the registry's
 * `rcan.dev` name, and neither that subdomain nor its parent has ever had a DNS
 * record. A third party following a link out of an RRF response reached
 * nothing. `robotregistryfoundation.org` is the host the Pages project is
 * actually attached to, so that is what goes in a receipt.
 *
 * If that subdomain is ever attached as a custom domain on the
 * robot-registry-foundation Pages project, change this constant and record the
 * hostname in tests/dead-hostname-allowlist.json with `attached: true`. Do not
 * scatter the literal back through the handlers.
 *
 * This constant does NOT govern the JWT `iss` claim. `iss` is an opaque issuer
 * identifier that is compared for equality and never dereferenced, and it is
 * asserted by verifiers outside this repository. See
 * tests/dead-hostname-allowlist.json for the reason it is unchanged.
 */
export const API_BASE = "https://robotregistryfoundation.org";
