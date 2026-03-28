# Changelog

All notable changes to the Robot Registry Foundation are documented here.

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
