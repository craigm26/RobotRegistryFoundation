# Robot Registry Foundation

The open registry for RCAN-compliant robots — assigns permanent global identities to robots the way ICANN assigns domain names.

[![Spec](https://img.shields.io/badge/RCAN-v1.6-blue)](https://rcan.dev/spec/)
[![License](https://img.shields.io/badge/license-CC%20BY%204.0-green)](https://creativecommons.org/licenses/by/4.0/)

🌐 **[robotregistryfoundation.org](https://robotregistryfoundation.org)**

## What RRF Does

- **Assigns RRNs** — Robot Registration Numbers: permanent, globally unique identifiers that survive hardware swaps and OS reinstalls
- **Stores capability declarations** — each robot record includes hardware specs, RCAN version, and declared capabilities
- **Provides a revocation API** — operators can revoke a robot's identity if it's compromised or decommissioned
- **Operates trust anchors** — as a root registry, RRF signs authoritative sub-registry keys via DNSSEC trust chains
- **Federated architecture** — manufacturers can run their own authoritative registry nodes; RRF is the root

## How to Register a Robot

1. Install and configure OpenCastor: `pip install opencastor==2026.4.1.0 && castor setup`
2. The setup wizard assigns an RRN and registers it automatically
3. Or register directly at [rcan.dev/registry](https://rcan.dev/registry)

## Robot Document Schema

| Field | Type | Description |
|---|---|---|
| `rrn` | string | Robot Registration Number, e.g. `RRN-000000000001` |
| `name` | string | Human-readable robot name |
| `owner` | string | Owner identifier (email or org) |
| `capabilities` | object | Capability Object Map (§18) — declared skills and hardware |
| `hardware_safety` | object | P66 manifest — ESTOP config, LoA requirements |
| `rcan_version` | string | Highest RCAN spec version supported |
| `verification_tier` | string | `community` / `verified` / `partner` / `certified` |
| `runtime` | string | e.g. `opencastor/2026.4.1.0` |
| `registered_at` | ISO 8601 | Registration timestamp |
| `revoked` | boolean | Whether this robot's identity is revoked |

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/robots` | List all registered robots (paginated) |
| `GET` | `/robots/{rrn}` | Resolve a robot record by RRN |
| `GET` | `/robots/{rrn}/revocation-status` | Check if an RRN is revoked |
| `GET` | `/robots/{rrn}/keys` | Fetch JWKS public keys for an RRN |
| `POST` | `/robots/register` | Register a new robot (authenticated) |
| `GET` | `/.well-known/rcan-node.json` | Registry node manifest |

Full API reference: [robotregistryfoundation.org/api/](https://robotregistryfoundation.org/api/)

## Registered Robots (Examples)

| RRN | Name | Runtime | Hardware |
|---|---|---|---|
| RRN-000000000001 | Bob | OpenCastor v2026.4.1.0 | Raspberry Pi 5, Gemini 2.5 Flash |
| RRN-000000000005 | Alex | OpenCastor v2026.4.1.0 | Raspberry Pi 5 + SO-ARM101 5-DOF arm |

Browse all: [robotregistryfoundation.org/registry/](https://robotregistryfoundation.org/registry/)

## Verification Tiers

| Tier | Badge | How to Achieve |
|---|---|---|
| Community | ⬜ | Self-registered; no identity check |
| Verified | 🟡 | Email or domain verified; manufacturer identity confirmed |
| Partner | 🔵 | Signed partnership agreement with RRF |
| Certified | ✅ | Passed third-party conformance test suite |

Robots may only issue LoA 1 tokens from community registries. LoA 2/3 requires a verified or authoritative registry.

## Registry Tiers

| Tier | Who | Trust Level |
|---|---|---|
| **Root** | RRF (rcan.dev) | Signs authoritative registry keys; manages global trust anchors |
| **Authoritative** | Manufacturers, verified operators | Can issue LoA 2/3 JWTs; must pass annual audit |
| **Community** | Anyone | Self-signed; LoA 1 only |

Any organization can run an authoritative registry node. RCAN's federation model means robots registered at `bd.rcan.example` are fully interoperable with robots registered at `rcan.dev`.

## Development

```bash
npm install
npm run dev      # localhost:4321
npm run build    # production → dist/
```

## Ecosystem

| Project | Version | Purpose |
|---|---|---|
| **RRF** (this) | v1.6.0 | Global robot identity registry |
| [RCAN Protocol](https://rcan.dev/spec/) | v1.6.0 | Open robot communication standard |
| [OpenCastor](https://github.com/craigm26/OpenCastor) | v2026.4.1.0 | Robot runtime, RCAN reference implementation |
| [rcan-py](https://github.com/continuonai/rcan-py) | v0.6.0 | Python RCAN SDK |
| [rcan-ts](https://github.com/continuonai/rcan-ts) | v0.6.0 | TypeScript RCAN SDK |
| [Fleet UI](https://app.opencastor.com) | live | Web fleet dashboard |

## Contributing

The RRF is in active formation. Open issues and discussions at GitHub.

We're seeking co-founders, board members, manufacturer partnerships, and standards body endorsements.

Governance charter: [robotregistryfoundation.org/governance/](https://robotregistryfoundation.org/governance/)

## License

Site content: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
Code: MIT
