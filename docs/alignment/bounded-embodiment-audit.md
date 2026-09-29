# Bounded Embodiment alignment audit: Robot Registry Foundation site and registry

**Date:** 2026-09-29
**Branch:** `align/bounded-embodiment`
**Companion:** RobotRegistryFoundation/rcan-spec#221 (Appendix C, schemas, EV tests,
and the spec-side audit at `docs/alignment/bounded-embodiment-audit.md` there).

Scope: this repository (apex site + `/v2` Pages Functions over KV), plus a read-only look
at `craigm26/rrf-docs` (docs.robotregistryfoundation.org), where `/governance`,
`/verification`, `/api` and `/federation` now redirect (`public/_redirects`).

---

## 1. Where R1–R5 already touch this repo

The registry does not run robots, so it implements none of R1–R5 itself. It stores
evidence about them.

| Req | What the registry holds today | Where |
|---|---|---|
| R1 Declared envelope | Nothing. `RobotRecord` has no capability or limit fields, although the README said it did (`capabilities`, `hardware_safety`). | `functions/v2/_lib/types.ts` |
| R2 Enforcement below the model | Nothing directly. | n/a |
| R3 Stop always wins | §23 safety-benchmark intake stores signed benchmark documents, which include an `estop` timing path. | `functions/v2/robots/[rrn]/safety-benchmark.ts` |
| R4 Accountable commands | Signed registration (ML-DSA-65 + Ed25519), key revocation and rotation, orchestrator revocation list, RAN authorities, run-bundle log. | `robots/register.ts`, `revoke-key.ts`, `rotate-key.ts`, `v2/revocations.ts`, `v2/authorities/*`, `v2/run-bundles/*` |
| R5 Tamper-evident evidence | Signed compliance intake, append-only KV history per artifact, signed run-bundle log with `/.well-known/rrf-root-pubkey.pem`. | `_lib/compliance-auth.ts`, `_lib/rrf-log-sign.ts`, `v2/run-bundles/log/[idx].ts` |

## 2. Gaps (addressed on this branch)

- No place to record a robot's physical assurance level, envelope hash or evidence link.
- No way for a safety-benchmark submission to say which EV tests it covers.
- No page explaining physical assurance, A1–A3 vs L1–L4, or the two stops.
- No statement anywhere of maintainer count, conflicts of interest, or AAIF status.

## 3. Naming inconsistencies

| Expansion of RCAN | Where |
|---|---|
| Robot Communication **&** Addressing Network | `src/pages/index.astro:27` |

"Robot Communication and Networking Protocol" does not occur in this repo, in
`rrf-docs`, or anywhere else under `~/projects`. If it appears on a live page, that page
is built from somewhere not checked out here. For the full cross-repo list, see the
rcan-spec audit §3.

## 4. Section-number drift and other cross-references

- RRF uses **§27 for Spatial Intelligence Eval** (`functions/v1/spatial-eval/*`), but the
  published spec (rcan-docs) titles §27 "FRIA Protocol", a duplicate of §22.
- RRF uses §22–§26 for FRIA, Safety Benchmark, IFU, Incident Report, EU Register. These
  resolve in the published spec.
- `CLAUDE.md` links `https://rcan.dev/spec/section-21/`, which now redirects to
  docs.rcan.dev. It resolves, via a redirect.
- `src/pages/about/index.astro` linked `github.com/continuonai/rcan-spec`; the repo is
  `RobotRegistryFoundation/rcan-spec` (fixed).
- `README.md` documented endpoints that do not exist (`GET /v2/robots`,
  `/v2/robots/{rrn}/revocation-status`, `/v2/robots/{rrn}/keys`) and a registration URL
  (`/register`) that does not exist (fixed).

### Verification-tier vocabulary disagrees in five places
| Source | Tiers |
|---|---|
| Code (`verify-tier.ts`, `register.ts`) | `unverified`, `community`, `manufacturer_claimed`, `manufacturer_verified` |
| `CLAUDE.md` | Community, Verified, Manufacturer-claimed, Manufacturer-verified |
| `README.md` (before this branch) | community, verified, partner ("signed partnership agreement"), certified ("passed third-party conformance test suite") |
| `src/components/VerificationBadge.astro`, `src/content/config.ts` | community, verified, certified, accredited |
| rrf-docs `verification/index.md` | Tier 3 "Certified", Tier 4 "Accredited" with an RRF-issued "signed conformance certificate", renewed annually |

README now matches the code. The badge component, content schema and rrf-docs are
listed for the consistency pass.

## 5. Public claims that conflict with the honesty rules

### Changed on this branch (before → after in the PR)
- `index.astro` "Verify" card: "full manufacturer certification and RCAN conformance
  audits. Regulators and insurers can rely on the record."
- `index.astro` footer line: "seeking co-founders and endorsements."
- `about/index.astro` status: "Identifying co-founders and endorsing organizations".
- `SiteFooter.astro`: "Board & Membership" (no board exists).
- `registry/[rrn].astro` (legacy, renders 0 pages): "Full conformance audit passed.
  RCAN L1/L2/L3 certified."
- `README.md`: "We're seeking … board members, manufacturer partnerships, and standards
  body endorsements"; "Operates trust anchors … via DNSSEC trust chains" (no DNSSEC code
  exists); "Federated architecture … RRF is the root" (one node, no delegations);
  Authoritative registries "must pass annual audit" (no audit program exists); Partner
  and Certified tier definitions.

### Not in this repo (rrf-docs, for the consistency pass)
- `governance/index.md:3` "Seeking co-founders, endorsing organizations"; `:127`
  "Endorsing organization … statement of endorsement on issue #13"; `:126` links
  `continuonai/rcan-spec/issues/13`; `:53–66` a 10-seat board described in "shall" terms.
- `verification/index.md:62–104` "Certified" and "Accredited" tiers, RRF-issued
  conformance certificates with annual renewal. None exist in the code.
- `federation/index.md:24` root "signs certificates".

### Security note (found while wiring the UI)
`src/pages/registry/entity.astro` and `registry/index.astro` build HTML with
`innerHTML` from API fields (`name`, `manufacturer`, `description`, …) without escaping.
Registration requires a valid signature, but the registrant chooses the text. The new
assurance block escapes its values and only links `https:` URLs; the existing fields are
listed for the consistency pass.

## 6. Pre-existing test failures

`tests/mint-attestation-kid.test.ts` (2) and `tests/u1b-runbook-kv-record.test.ts` (1)
fail before and after this branch: they spawn `/home/craigm26/rcan-py/.venv/bin/python`,
which does not exist on this machine (`ENOENT`). Environmental, not touched.
