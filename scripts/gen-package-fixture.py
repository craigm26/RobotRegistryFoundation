"""Generate package fixture: signed POST body for /v2/packages/register.

Pattern after gen-component-fixture.py. Emits a fixture JSON that includes:
  - http_body: the full signed POST body (verifies through rcan-ts verifyBody)
  - keypair:   the public/secret bytes (base64) so test files can re-sign
                bodies for /versions, /revoke, /transfer endpoints

Usage:
  python scripts/gen-package-fixture.py > functions/_lib/fixtures/package-fixture.json
"""

import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric import ed25519
from rcan.crypto import generate_ml_dsa_keypair, sign_hybrid

kp = generate_ml_dsa_keypair()
ed_sec = ed25519.Ed25519PrivateKey.generate()
ed_sec_bytes = ed_sec.private_bytes_raw()
ed_pub_bytes = ed_sec.public_key().public_bytes_raw()

ml_dsa_pub_b64 = base64.b64encode(kp.public_key_bytes).decode()
ml_dsa_sec_b64 = base64.b64encode(kp._secret_key).decode()
ed25519_pub_b64 = base64.b64encode(ed_pub_bytes).decode()
ed25519_sec_b64 = base64.b64encode(ed_sec_bytes).decode()
pq_kid = "publisher-feetech-" + hashlib.sha256(kp.public_key_bytes).hexdigest()[:8]

signed_fields = {
    "name": "feetech-arm",
    "description": "Feetech bus arm driver",
    "package_type": "actuator",
    "repository_url": "https://github.com/example/feetech-arm",
    "hardware_tags": ["arm", "feetech"],
    "manifest_signals": ["SO-ARM101"],
    "skill_files": ["using-feetech-arm.SKILL.md"],
    "has_plugin_layout": False,
    "version": "1.0.0",
    "pq_signing_pub": ml_dsa_pub_b64,
    "pq_kid": pq_kid,
    "ed25519_pub": ed25519_pub_b64,
}
message = json.dumps(
    signed_fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
hs = sign_hybrid(kp, ed_sec_bytes, message)

http_body = {
    **signed_fields,
    "sig": {
        "ml_dsa": base64.b64encode(hs.ml_dsa_sig).decode(),
        "ed25519": base64.b64encode(hs.ed25519_sig).decode(),
        "ed25519_pub": base64.b64encode(ed_pub_bytes).decode(),
    },
}

print(
    json.dumps(
        {
            "http_body": http_body,
            "canonical_bytes_b64": base64.b64encode(message).decode(),
            "keypair": {
                "pq_kid": pq_kid,
                "pq_signing_pub_b64": ml_dsa_pub_b64,
                "pq_signing_sec_b64": ml_dsa_sec_b64,
                "ed25519_pub_b64": ed25519_pub_b64,
                "ed25519_sec_b64": ed25519_sec_b64,
            },
        },
        indent=2,
    )
)
