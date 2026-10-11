"""Page schemas for `customer-X.md` (overview §5.4) and `shared-intelligence.md` (§5.5).

Dev C owns both formats. Dev A reads them with `attack/harness/context.py`, which fixes a few
layout rules (see `docs/memory-page-schema.md`):

- customer page sections are headings `## <n>. <title>`; no other heading may start with a digit
- `knowledge_version: <x.y.z>` appears in `shared-intelligence.md` before any item
- every `### ` heading in `shared-intelligence.md` is read by A as a live lesson, so only active
  items use `###`; pending, quarantined and retired items use `####`
"""

import re

PAGE_SCHEMA_VERSION = "1.0"
INITIAL_KNOWLEDGE_VERSION = "0.1.0"

CUSTOMER_SECTIONS: dict[int, str] = {
    1: "Environment profile & tested revision",
    2: "Assets, sensitive actions, trust boundaries, security invariants",
    3: "Recent code/config changes",
    4: "Observed events & notable sequences",
    5: "Confirmed findings & evidence",
    6: "Hypotheses & unverified leads",
    7: "Prior swarm runs",
    8: "Defenses & regression tests",
    9: "Open risks & prioritized next tests",
    10: "Candidate lessons for shared intelligence",
}

SHARED_SECTIONS: list[str] = [
    "Taxonomy & version",
    "Generalized attack patterns & preconditions",
    "Reusable synthetic scenarios",
    "Invariants & defensive patterns",
    "Verified mitigation & regression guidance",
    "Deprecated & superseded knowledge",
    "Change log",
    "Pending contributions",
]

# Weakness classes match `weakness_class` in Dev A's scenario catalog. A family groups classes
# that share a lesson, so a lesson learned on one class can apply to a sibling on another tenant
# (e.g. idor on customer-a -> bola on customer-b). None of these keys may contain "any" or "all":
# A's applicability filter treats those substrings as "applies everywhere".
TAXONOMY: dict[str, list[str]] = {
    "object_access": ["idor", "bola"],
    "authorization": ["missing_authz"],
    "auth_abuse": ["missing_rate_limit", "weak_reset_flow"],
    "server_side_request": ["ssrf"],
    "input_handling": ["injection", "output_encoding", "path_traversal"],
}

# Static profile per demo customer: the §1 and §2 seed content. Names, routes and invariants
# mirror dev-B §4a and Dev A's catalog. All data on these sites is synthetic.
PROFILES: dict[str, dict[str, object]] = {
    "customer-a": {
        "app": "e-commerce storefront",
        "base_url": "http://localhost:3001",
        "assets": ["customer accounts and sessions", "orders (per-user)", "password reset tokens"],
        "sensitive_actions": [
            "login and one-time-code verification (`/login`, `/login/verify-otp`)",
            "password reset confirmation (`/password-reset/confirm`)",
            "order detail reads (`/orders/{id}`)",
        ],
        "trust_boundaries": [
            "anonymous -> authenticated session",
            "one user -> another user's orders",
        ],
        "invariants": [
            "A user can only read their own orders",
            "Repeated failed logins for one account are throttled",
            "One-time-code guesses are rate limited per account",
            "A password reset requires an unguessable, single-use token",
        ],
    },
    "customer-b": {
        "app": "SaaS dashboard (workspaces and roles)",
        "base_url": "http://localhost:3002",
        "assets": ["workspace accounts", "member roles", "integration callback settings"],
        "sensitive_actions": [
            "account reads (`/api/accounts/{id}`)",
            "user administration (`/admin/users`)",
            "webhook test callbacks (`/api/webhooks/test`)",
        ],
        "trust_boundaries": [
            "member -> admin role",
            "one workspace's accounts -> another's",
            "server -> internal network via callbacks",
        ],
        "invariants": [
            "A user can only read accounts they own",
            "Only admin roles can list users",
            "Server-side callbacks never target internal or non-allowlisted hosts",
        ],
    },
    "customer-c": {
        "app": "CMS (posts, comments, uploads)",
        "base_url": "http://localhost:3003",
        "assets": ["posts and comments", "uploaded files", "search index"],
        "sensitive_actions": [
            "search (`/search`)",
            "comment preview rendering (`/comments/preview`)",
            "file uploads (`/uploads`)",
        ],
        "trust_boundaries": [
            "user input -> query engine",
            "user markup -> other readers' browsers",
            "uploaded filename -> server filesystem",
        ],
        "invariants": [
            "User input is never interpreted as query syntax",
            "User-supplied markup is always encoded on output",
            "Uploaded files are stored under server-chosen names inside the upload root",
        ],
    },
}

_CUSTOMER_HEADING = re.compile(r"^##\s+(\d+)\.\s+(.*)$")


def _bullets(items) -> str:
    return "\n".join(f"- {x}" for x in items)


def render_customer_scaffold(customer_id: str) -> str:
    """A fresh customer page: header, §1–§2 seeded from the profile, §3–§10 empty."""
    p = PROFILES[customer_id]
    body = {
        1: (
            f"- app: {p['app']}\n- base_url: {p['base_url']} (local only)\n"
            "- tested_revision: unknown\n- last_distilled: never"
        ),
        2: (
            f"**Assets**\n{_bullets(p['assets'])}\n\n"
            f"**Sensitive actions**\n{_bullets(p['sensitive_actions'])}\n\n"
            f"**Trust boundaries**\n{_bullets(p['trust_boundaries'])}\n\n"
            f"**Security invariants**\n{_bullets(p['invariants'])}"
        ),
    }
    parts = [
        f"# {customer_id}: security memory",
        "",
        f"page_schema: {PAGE_SCHEMA_VERSION} · customer_id: {customer_id}",
        "",
        "<!-- Maintained by distill/customer_analysis via targeted section patches. -->",
    ]
    for n, title in CUSTOMER_SECTIONS.items():
        parts += ["", f"## {n}. {title}", ""]
        if n in body:
            parts.append(body[n])
    return "\n".join(parts).rstrip() + "\n"


def render_shared_scaffold() -> str:
    """A fresh shared corpus: version header, taxonomy, empty sections."""
    taxonomy = "\n".join(
        f"| `{family}` | {', '.join(f'`{c}`' for c in classes)} |"
        for family, classes in TAXONOMY.items()
    )
    body = {
        "Taxonomy & version": (
            "| Family | Weakness classes |\n|---|---|\n" + taxonomy + "\n\n"
            "Active items are `### <id>` headings. Pending, quarantined and retired items are\n"
            "`#### <id>` so the attack planner never reads them as live lessons."
        ),
        "Change log": f"- {INITIAL_KNOWLEDGE_VERSION}: corpus created (empty).",
    }
    parts = [
        "# Shared intelligence",
        "",
        f"knowledge_version: {INITIAL_KNOWLEDGE_VERSION}",
        f"page_schema: {PAGE_SCHEMA_VERSION}",
        "",
        "<!-- Maintained by distill/shared_updater. Contains no tenant-identifying data. -->",
    ]
    for title in SHARED_SECTIONS:
        parts += ["", f"## {title}", ""]
        if title in body:
            parts.append(body[title])
    return "\n".join(parts).rstrip() + "\n"


def parse_customer_sections(text: str) -> dict[int, str]:
    """Section number -> body (stripped). Text before §1 (title, header) is not a section."""
    sections: dict[int, list[str]] = {}
    current: int | None = None
    for line in text.splitlines():
        m = _CUSTOMER_HEADING.match(line)
        if m:
            current = int(m[1])
            sections[current] = []
        elif current is not None:
            sections[current].append(line)
    return {n: "\n".join(lines).strip() for n, lines in sections.items()}
