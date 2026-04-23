"""Generate component fixture: signed POST body for /v2/components/register."""

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
pq_kid = hashlib.sha256(kp.public_key_bytes).hexdigest()[:8]

signed_fields = {
    "parent_rrn": "RRN-000000000042",
    "type": "camera",
    "model": "oak-d-pro",
    "manufacturer": "luxonis",
    "firmware_version": "2026.3.0",
    "capabilities": ["rgb", "depth"],
    "specs": {"fov_deg": 120},
    "pq_signing_pub": ml_dsa_pub_b64,
    "pq_kid": pq_kid,
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
        },
        indent=2,
    )
)
