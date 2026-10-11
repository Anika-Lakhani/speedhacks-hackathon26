"""Synthetic fixture values referenced by scenarios as `fixture:<name>`.

Only made-up values live here; probes never carry real user data.
"""

SESSION_USER = "user-1001"
OTHER_USER = "user-2002"

FIXTURES: dict[str, str] = {
    "other_order": "ORD-90002",
    "other_account": "ACC-90002",
    "synthetic_user": "synthetic.user@example.test",
    "wrong_password": "not-the-password",
    "wrong_otp": "000000",
    "guessable_token": "123456",
    "internal_marker_url": "http://probe-sink.invalid/swarmshield-marker",
    "injection_marker": "SWARMSHIELD_MARKER'",
    "markup_marker": "<swarm-marker>",
    "traversal_name": "../swarmshield-marker.txt",
    "benign_content": "swarmshield benign marker",
}

PREFIX = "fixture:"


class FixtureError(KeyError):
    pass


def resolve(value: str) -> str:
    """Resolve `fixture:<name>`; any other string passes through unchanged."""
    if not value.startswith(PREFIX):
        return value
    name = value[len(PREFIX) :]
    try:
        return FIXTURES[name]
    except KeyError:
        raise FixtureError(f"unknown fixture {name!r}") from None
