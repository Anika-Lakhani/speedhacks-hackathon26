"""Generalized lesson templates, one per weakness (overview §5.5).

A shared item's text comes only from here, never from a customer page. A contribution supplies
the weakness class and evidence strength; the words are tenant-neutral by construction. Classes
that describe the same weakness under two names (IDOR and BOLA) share one lesson, so findings
from different tenants merge into one item.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Lesson:
    id: str
    title: str
    classes: tuple[str, ...]  # applicability: the weakness classes this lesson is relevant to
    pattern: str
    preconditions: str
    test: str
    invariant: str
    mitigation: str
    regression: str


LESSONS: dict[str, Lesson] = {
    lesson.id: lesson
    for lesson in [
        Lesson(
            id="SI-object_access_authz",
            title="Object-level authorization missing on per-user records",
            classes=("idor", "bola"),
            pattern="Records are fetched by a client-supplied identifier without checking that "
            "the record belongs to the caller.",
            preconditions="authenticated session; guessable or enumerable record identifiers",
            test="As one synthetic user, request a record owned by another synthetic user by its "
            "identifier; expect a denial, not the record.",
            invariant="A caller can only read records they own.",
            mitigation="Scope every lookup by the caller in the data-access layer, not the UI.",
            regression="Keep a cross-user read test for every per-user record type.",
        ),
        Lesson(
            id="SI-function_authz",
            title="Privileged function reachable by a lower role",
            classes=("missing_authz",),
            pattern="An administrative operation checks authentication but not the caller's role.",
            preconditions="authenticated session with a non-admin role",
            test="As a synthetic non-admin user, call an admin-only listing; expect a denial.",
            invariant="Only admin roles can perform admin operations.",
            mitigation="Enforce role checks server-side on every privileged route; deny by "
            "default.",
            regression="Test each privileged route with every non-privileged role.",
        ),
        Lesson(
            id="SI-auth_rate_limit",
            title="Authentication attempts not throttled",
            classes=("missing_rate_limit",),
            pattern="Repeated failed logins or one-time-code guesses for one account are never "
            "slowed or locked.",
            preconditions="a login or code-verification step reachable without prior throttling",
            test="Send a burst of failed attempts for one synthetic account; expect throttling "
            "after a small threshold.",
            invariant="Repeated failed authentication attempts for one account are throttled.",
            mitigation="Throttle per account and per client, with backoff or temporary lockout.",
            regression="Assert throttling engages at the configured threshold.",
        ),
        Lesson(
            id="SI-reset_token_strength",
            title="Weak password reset token",
            classes=("weak_reset_flow",),
            pattern="Password reset accepts predictable, long-lived or reusable tokens.",
            preconditions="a self-service password reset flow",
            test="Attempt a reset confirmation with a predictable or already-used synthetic token; "
            "expect rejection.",
            invariant="A password reset requires an unguessable, single-use, short-lived token.",
            mitigation="Use high-entropy single-use tokens with a short expiry, bound to the "
            "account.",
            regression="Test token reuse and expiry on every change to the reset flow.",
        ),
        Lesson(
            id="SI-server_side_fetch",
            title="Server-side fetch of user-supplied URLs",
            classes=("ssrf",),
            pattern="The server fetches a user-supplied callback URL without restricting the "
            "destination.",
            preconditions="a feature that registers or tests user-supplied webhooks or callbacks",
            test="Register a callback whose synthetic URL points at an internal-shaped host; "
            "expect refusal.",
            invariant="Server-side requests only reach allowlisted external destinations.",
            mitigation="Resolve and check destinations against an allowlist; block internal "
            "ranges.",
            regression="Test internal-shaped destinations on every change to callback handling.",
        ),
        Lesson(
            id="SI-query_injection",
            title="User input interpreted as query syntax",
            classes=("injection",),
            pattern="Search or filter input is concatenated into a query instead of bound as data.",
            preconditions="a search or filter input passed to a query engine",
            test="Submit query-syntax characters in a search-style input; expect them to be "
            "treated literally.",
            invariant="User input is never interpreted as query syntax.",
            mitigation="Use parameterized queries or a query builder; never build query strings.",
            regression="Keep a literal-handling test for each search and filter input.",
        ),
        Lesson(
            id="SI-output_encoding",
            title="User markup rendered without encoding",
            classes=("output_encoding",),
            pattern="User-supplied content is rendered back as markup instead of encoded text.",
            preconditions="user content shown to other users or in a preview",
            test="Submit a synthetic markup marker in user content; expect it encoded on output.",
            invariant="User-supplied markup is always encoded on output.",
            mitigation="Encode by output context in the template layer; sanitize allowed markup.",
            regression="Test encoding for every view that renders user content.",
        ),
        Lesson(
            id="SI-upload_storage_path",
            title="Upload filename controls the storage path",
            classes=("path_traversal",),
            pattern="A client-supplied filename is used to build the storage path.",
            preconditions="a file upload feature",
            test="Upload with a traversal-shaped synthetic filename; expect a server-chosen name "
            "inside the upload root.",
            invariant="Uploaded files are stored under server-chosen names inside the upload root.",
            mitigation="Generate storage names server-side; never join client filenames into "
            "paths.",
            regression="Test traversal-shaped names on every change to upload handling.",
        ),
    ]
}

LESSON_FOR_CLASS: dict[str, Lesson] = {
    c: lesson for lesson in LESSONS.values() for c in lesson.classes
}
