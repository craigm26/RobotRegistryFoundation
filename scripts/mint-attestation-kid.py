#!/usr/bin/env python3
"""Mint a hybrid Ed25519 + ML-DSA-65 attestation keypair for U1b.

Emits into --out-dir:
  attestation-ed25519-private.pem   PKCS8 PEM — provision to the gateway (U1a)
  attestation-mldsa65-private.pem   ML-DSA-65 raw secret (base64 PEM-like) — ARCHIVE OFFLINE
  mint-manifest.json                every value the registration step needs

Run with the rcan venv:  ~/rcan-py/.venv/bin/python scripts/mint-attestation-kid.py ...

The registration_body in mint-manifest.json is produced by rcan.hybrid.sign_body and is
byte-compatible with RobotRegistryFoundation/functions/v2/authorities/register.ts verifyBody.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from rcan import generate_ml_dsa_keypair, sign_body


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def main() -> None:
    ap = argparse.ArgumentParser(description="Mint a hybrid attestation keypair (U1b).")
    ap.add_argument("--organization", required=True, help="RRF authority organization (free-form), e.g. OpenCastor")
    ap.add_argument("--display-name", required=True, help="human label for the authority record")
    ap.add_argument("--purpose", default="attestation", help="AuthorityPurpose (default: attestation)")
    ap.add_argument("--out-dir", required=True, help="directory to write the three artifacts into")
    ap.add_argument("--force", action="store_true", help="overwrite an existing keypair/manifest in --out-dir (default: refuse)")
    args = ap.parse_args()
    os.umask(0o077)  # private keys: deny group/other from creation (closes the write->chmod window)

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    # Private signing keys land here; keep the dir owner-only too (best-effort).
    os.chmod(out, 0o700)

    _targets = [
        out / "attestation-ed25519-private.pem",
        out / "attestation-mldsa65-private.pem",
        out / "mint-manifest.json",
    ]
    _existing = [p.name for p in _targets if p.exists()]
    if _existing and not args.force:
        raise SystemExit(
            f"refusing to overwrite existing {_existing} in {out} — pass --force to replace "
            f"(rotation = re-mint with a NEW RAN; see docs/runbooks/u1b-attestation-registration.md)"
        )

    # 1. Ed25519: PKCS8 PEM (gateway), raw 32-byte seed (sign_body), raw 32-byte pub (registered).
    ed = Ed25519PrivateKey.generate()
    ed_pem = ed.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    ed_seed = ed.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    ed_pub = ed.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    assert len(ed_seed) == 32 and len(ed_pub) == 32

    # 2. ML-DSA-65 keypair (pub = 1952 bytes; key_id = sha256(pub)[:8]).
    kp = generate_ml_dsa_keypair()
    assert len(kp.public_key_bytes) == 1952
    assert kp._secret_key is not None

    # 3. Hybrid registration body. sign_body adds pq_signing_pub, pq_kid, and
    #    sig.{ml_dsa,ed25519,ed25519_pub}; pq_kid == sha256(pq_pub)[:8] == kp.key_id.
    meta = {
        "organization": args.organization,
        "display_name": args.display_name,
        "purpose": args.purpose,
        "signing_pub": b64(ed_pub),
        "signing_alg": ["Ed25519", "ML-DSA-65"],
    }
    body = sign_body(kp, meta, ed25519_secret=ed_seed, ed25519_public=ed_pub)
    assert body["pq_kid"] == kp.key_id
    assert body["sig"]["ed25519_pub"] == meta["signing_pub"]

    # 4. Write the gateway private-key PEM (provision) and ML-DSA archive (offline).
    #    Private signing keys must never be group/other readable — chmod 0600 after write.
    ed_priv_path = out / "attestation-ed25519-private.pem"
    ed_priv_path.write_bytes(ed_pem)
    os.chmod(ed_priv_path, 0o600)
    mldsa_archive = (
        "-----BEGIN ML-DSA-65 PRIVATE KEY-----\n"
        + b64(kp._secret_key)
        + "\n-----END ML-DSA-65 PRIVATE KEY-----\n"
    )
    mldsa_priv_path = out / "attestation-mldsa65-private.pem"
    mldsa_priv_path.write_text(mldsa_archive)
    os.chmod(mldsa_priv_path, 0o600)

    # 5. The manifest: everything the registration step (Task 2 / runbook) needs.
    manifest = {
        "organization": args.organization,
        "display_name": args.display_name,
        "purpose": args.purpose,
        "signing_alg": ["Ed25519", "ML-DSA-65"],
        "signing_pub_b64": b64(ed_pub),
        "pq_signing_pub_b64": body["pq_signing_pub"],
        "pq_kid": body["pq_kid"],
        "ed25519_private_pem_file": "attestation-ed25519-private.pem",
        "mldsa_private_pem_file": "attestation-mldsa65-private.pem",
        "registration_body": body,
    }
    (out / "mint-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    print(f"minted attestation keypair → {out}")
    print(f"  organization : {args.organization}")
    print(f"  pq_kid       : {body['pq_kid']}")
    print(f"  signing_pub  : {b64(ed_pub)}")
    print(f"  pq_signing_pub bytes: {len(base64.b64decode(body['pq_signing_pub']))}")
    print("  PROVISION attestation-ed25519-private.pem to the gateway (U1a).")
    print("  ARCHIVE   attestation-mldsa65-private.pem OFFLINE (never reaches the robot).")


if __name__ == "__main__":
    main()
