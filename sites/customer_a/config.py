"""customer-a configuration. Bump CODE_REVISION when the site's code or config changes:
it's reported on every event, on GET /revision and /__meta, and in the X-Code-Revision header.
"""

import os
from pathlib import Path

CUSTOMER_ID = "customer-a"
CODE_REVISION = "customer-a-1.0.0"

PORT = 3001
STORE_URL = os.environ.get("SWARMSHIELD_STORE_URL", "http://localhost:4000")
EMIT_FALLBACK_PATH = Path(
    os.environ.get("CUSTOMER_A_EMIT_FALLBACK", ".data/sites/customer-a/emit-fallback.jsonl")
)
