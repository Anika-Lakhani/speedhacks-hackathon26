"""Evidence labels and test verdicts (overview §5.2, §5.3)."""

from enum import StrEnum


class EvidenceLabel(StrEnum):
    """How well-supported a conclusion is. Missing evidence is never a pass."""

    OBSERVED = "observed"
    HYPOTHESIZED = "hypothesized"
    REPRODUCED = "reproduced"
    VERIFIED = "verified"


class Verdict(StrEnum):
    """Outcome of one scenario test, checked against the scenario's invariant."""

    CONFIRMED = "confirmed"
    NOT_REPRODUCED = "not_reproduced"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"
