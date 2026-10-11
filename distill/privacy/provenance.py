"""Controlled provenance: a stable, keyed token per tenant, never the tenant's name.

The token lets the shared updater count independent tenants and merge repeat contributions,
while the corpus and audit log never name a tenant. The key stays local: set
SWARMSHIELD_PROVENANCE_SALT, or one is generated in `.data/provenance.salt` (gitignored).
"""

import hashlib
import hmac
import os
import secrets
from pathlib import Path

SALT_PATH = Path(__file__).resolve().parents[2] / ".data" / "provenance.salt"


def load_salt(path: Path = SALT_PATH) -> bytes:
    env = os.environ.get("SWARMSHIELD_PROVENANCE_SALT")
    if env:
        return env.encode()
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(secrets.token_hex(32))
    return path.read_text().strip().encode()


def source_token(customer_id: str, salt: bytes) -> str:
    return "src-" + hmac.new(salt, customer_id.encode(), hashlib.sha256).hexdigest()[:12]
