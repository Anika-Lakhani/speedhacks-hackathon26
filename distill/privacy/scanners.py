"""Privacy gates for the shared corpus: secrets, PII, tenant identifiers, re-identification.

A scan reports which rule fired, never the matched text, so a report can be logged or
shown without repeating the secret it found.
"""

import re
from dataclasses import dataclass
from functools import cache
from pathlib import Path

import yaml

from distill.pages import PROFILES

FLAGS_PATH = Path(__file__).resolve().parents[2] / "contracts" / "flags.yaml"

SECRET_RULES: dict[str, re.Pattern] = {
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "private_key_block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    "slack_token": re.compile(r"\bxox[abpors]-[A-Za-z0-9-]{10,}\b"),
    "api_key_prefix": re.compile(r"\b(?:sk|pk|rk)_(?:live|test)?_?[A-Za-z0-9]{16,}\b"),
    "bearer_or_jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+"),
    "credential_assignment": re.compile(
        r"(?i)\b(?:password|passwd|secret|api[_-]?key|token|auth)\s*[:=]\s*\S{4,}"
    ),
    "high_entropy_string": re.compile(r"\b[A-Za-z0-9+/_-]{40,}={0,2}"),
}

PII_RULES: dict[str, re.Pattern] = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "phone": re.compile(
        r"(?<![\w-])(?:\+\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}(?![\w-])"
    ),
    "us_ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "card_number": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    "ip_address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}

# Details that could single out a tenant even with its name removed.
REIDENTIFICATION_RULES: dict[str, re.Pattern] = {
    "precise_timestamp": re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}"),
    "evidence_ref": re.compile(r"ev://"),
    "uuid_or_event_ref": re.compile(r"\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b"),
    "run_id": re.compile(r"(?i)\brun[-_:]\s*[A-Za-z0-9-]{4,}"),
    "code_revision": re.compile(r"(?i)\b(?:rev|revision|commit)\s*[:=-]?\s*[0-9a-f]{7,40}\b"),
    "scenario_id": re.compile(r"\bSCN-[A-Z]+-\d+\b"),
    "url_or_host": re.compile(
        r"(?i)\b(?:https?://|localhost\b|[a-z0-9-]+\.(?:com|io|net|org|dev)\b)"
    ),
    "api_path": re.compile(r"(?<![\w/])/[a-z][\w-]*(?:/[\w{}.-]+)*"),
}


@dataclass(frozen=True)
class Hit:
    kind: str  # secret | pii | tenant_identifier | reidentification
    rule: str


@cache
def tenant_terms() -> frozenset[str]:
    """Tenant names, site URLs and tenant-specific endpoints, lowercased."""
    terms: set[str] = set()
    for customer_id, profile in PROFILES.items():
        terms |= {customer_id, customer_id.replace("-", "_"), str(profile["base_url"])}
        terms.add(str(profile["base_url"]).split("//")[1])  # host:port
    try:
        for flag in yaml.safe_load(FLAGS_PATH.read_text()) or []:
            terms.update(e.split("{")[0].rstrip("/") for e in flag.get("endpoints", []))
            terms.add(flag["flag"])
    except FileNotFoundError:
        pass
    return frozenset(t.lower() for t in terms if len(t) > 3)


def scan(text: str, kinds: tuple[str, ...] | None = None) -> list[Hit]:
    """Every rule that fires on `text`. `kinds` limits which gates run."""
    groups = {
        "secret": SECRET_RULES,
        "pii": PII_RULES,
        "reidentification": REIDENTIFICATION_RULES,
    }
    hits = [
        Hit(kind, rule)
        for kind, rules in groups.items()
        if kinds is None or kind in kinds
        for rule, pattern in rules.items()
        if pattern.search(text)
    ]
    if kinds is None or "tenant_identifier" in kinds:
        lowered = text.lower()
        if any(term in lowered for term in tenant_terms()):
            hits.append(Hit("tenant_identifier", "known_tenant_term"))
    return hits
