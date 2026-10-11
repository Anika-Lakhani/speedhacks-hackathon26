"""Opaque, signed pagination cursors.

A cursor records where the last page ended (a store Position) plus the tenant and query it
was issued for, signed with HMAC-SHA256. Using it with a different customer_id, endpoint or
filters, or tampering with it, is rejected, so a cursor can never move a caller into another
tenant's data or a different slice.
"""

import base64
import hashlib
import hmac
import json
from typing import Any

from keewano.storage import Position


class InvalidCursor(ValueError):
    pass


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class CursorCodec:
    def __init__(self, secret: bytes):
        self._secret = secret

    def _sign(self, body: bytes) -> bytes:
        return hmac.new(self._secret, body, hashlib.sha256).digest()

    def encode(self, customer_id: str, kind: str, filters: dict[str, Any], pos: Position) -> str:
        body = json.dumps(
            {"c": customer_id, "k": kind, "f": filters, "p": [pos.ts, pos.seq]},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return f"{_b64(body)}.{_b64(self._sign(body))}"

    def decode(self, cursor: str, customer_id: str, kind: str, filters: dict[str, Any]) -> Position:
        try:
            body_b64, sig_b64 = cursor.split(".")
            body, sig = _unb64(body_b64), _unb64(sig_b64)
        except ValueError as e:
            raise InvalidCursor("malformed cursor") from e
        if not hmac.compare_digest(sig, self._sign(body)):
            raise InvalidCursor("cursor signature does not match")
        data = json.loads(body)
        if data["c"] != customer_id:
            raise InvalidCursor("cursor was issued for a different customer_id")
        if data["k"] != kind or data["f"] != filters:
            raise InvalidCursor("cursor was issued for a different query")
        ts, seq = data["p"]
        return Position(ts, seq)
