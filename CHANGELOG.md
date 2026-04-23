# Changelog

All notable changes to the Robot Registry Foundation are documented here.

---

## [1.10.0] - 2026-04-23

### Added
- `POST /v2/robots/register` now accepts optional operator-declared
  `rcn_ids[]`, `rmn`, `rhn_ids[]` fields in the body. When present,
  they are included in the signed-fields block, verified, and
  persisted on the `RobotRecord`. These capture what the operator
  SAYS the robot is made of (at register time) — independent of the
  server-side `components[]` field, which tracks RCNs minted via
  `/v2/components/register` pointing back at this RRN.
- `RobotRecord.rcn_ids` / `rmn` / `rhn_ids` (all optional) in
  `functions/v2/_lib/types.ts`.

### Migration
- Fully backward compatible. Existing v1.9.0 clients that don't send
  these fields continue to work. Pairs with `robot-md@0.9.7`, which
  populates them from `ROBOT.md` `metadata.{rcn_ids,rmn,rhn_ids}`.

---

## [1.9.0] - 2026-04-23

### Changed (BREAKING)
- `POST /v2/components/register`, `POST /v2/models/register`,
  `POST /v2/harnesses/register` — all three now require the same
  hybrid signing pattern as `/v2/robots/register` (shipped in 1.8.0).
  Body MUST include `pq_signing_pub`, `pq_kid`, and `sig{ml_dsa,
  ed25519, ed25519_pub}` over the canonical signed-fields block.
  Unsigned POSTs return `400 Unsigned registration not permitted
  (RCAN 3.0 §2.2)`. Closes the v0.9.x ecosystem gap where robot-md
  v0.9.6 accepts RCN/RMN/RHN references pointing at entities that
  could have been registered without a signature.

### Added
- `ComponentRecord`, `ModelRecord`, `HarnessRecord` now persist
  `pq_signing_pub` + `pq_kid` so downstream queries can verify the
  register-time identity of each entity.
- `functions/v2/{components,models,harnesses}/register.test.ts` —
  vitest suites covering unsigned rejection, tampered-body rejection,
  missing-sig-subfield rejection, and happy-path minting. Uses
  Python-signed cross-language fixtures at
  `functions/_lib/fixtures/{component,model,harness}-fixture.json`.
- `scripts/gen-{component,model,harness}-fixture.py` — regenerators.

### Migration
- Existing records already minted under 1.6.0–1.8.0 remain valid.
  No record migration needed; only the `register` endpoints tighten.
- Any tooling that POSTs to `/v2/{components,models,harnesses}/register`
  must now sign via `rcan.crypto.sign_hybrid` (same shape as robots).

---

## [1.8.0] - 2026-04-22

### Added
- `PATCH /v2/robots/[rrn]` — upgrade an unsigned record to signed by submitting
  `{pq_signing_pub, pq_kid, sig}` with a valid hybrid signature over canonical
  `{rrn, pq_signing_pub, pq_kid}` bytes. Bearer-authed via the robot's API key.
  Returns 409 if the record is already signed (key rotation is a later release).
- `GET /v2/robots/[rrn]` — fetch a single robot record by RRN (existing handler
  preserved; now colocated with PATCH in the dynamic route).
- Shared `functions/_lib/verify.ts` — ML-DSA-65 + Ed25519 hybrid verification
  using `@noble/post-quantum@0.6.1` (FIPS 204) and WebCrypto Ed25519.
- `vitest` test suite (21 tests); cross-language fixtures (Python-signed via
  `rcan.crypto`, TS-verified) at `functions/_lib/fixtures/hybrid-fixture.json`
  (register-style), `patch-fixture.json` (PATCH-style),
  `register-fixture.json` (signed POST body).
- `scripts/gen-patch-fixture.py`, `scripts/gen-register-fixture.py` —
  regenerators for the cross-language fixtures.

### Changed (BREAKING)
- `POST /v2/robots/register` now requires `pq_signing_pub`, `pq_kid`, and a
  valid ML-DSA-65 + Ed25519 hybrid signature over the canonical signed-fields
  block. Unsigned registration returns 400 per RCAN 3.0 §2.2. Prod registry
  had 1 existing robot (RRN-000000000001, already signed) — no migration.

### Dependencies
- Added: `@noble/post-quantum@^0.6.1`, `vitest@^2`, `@types/node`.

### Coordinated release
- Pairs with `robot-md@0.9.1` (in-flight at time of RRF 1.8.0 deploy). See
  `robot-md/docs/superpowers/specs/2026-04-22-v0.9.1-hybrid-signing-design.md`
  for the cross-repo design.

---

## [1.7.0] - 2026-03-28

### Added
- RCAN v2.2 multi-type entity registry: RRN / RCN / RMN / RHN
- `POST/GET /v2/robots/register` — full v2 registration with ML-DSA-65 support
- `POST /v2/components/register`, `/v2/models/register`, `/v2/harnesses/register`
- `GET /v2/registry` — unified entity listing (all types, client-side rendered)
- `GET /v2/robots/:rrn` — individual robot lookup
- `/registry/entity/?type=&id=` query-param entity detail page
- Live registry page — client-side fetch from `/v2/registry` API
- KV key patterns: `counter:rrn|rcn|rmn|rhn`, `robot:{RRN}`, `component:{RCN}`, `model:{RMN}`, `harness:{RHN}`
- Entity type color system: RRN=accent, RCN=cyan, RMN=purple, RHN=yellow
- Stitch-generated navbar redesign

### Changed
- **API v1 fully deprecated** — all `/v1/*` endpoints return `410 Gone` (sunset: 2026-03-27)
- All pages updated to RCAN v2.2 content (spec version, entity numbers, PQ signing)
- Registry seed data removed — all display data served from live KV
- Comprehensive UX + data accuracy pass (15 issues)
- `entity_types_count` uses live KV `get()` (not stale list keys)

### Fixed
- No double `v` prefix in model/harness display names
- Registry `summarize` — only prepend `v` prefix if version starts with a digit
- Removed temporary admin endpoints (wipe, clear)

## [1.6.0] - 2026-03-18

- Initial RCAN v2.1 Cloudflare Pages Functions release
- Orchestrator registry, firmware manifests, SBOM, revocation endpoints
