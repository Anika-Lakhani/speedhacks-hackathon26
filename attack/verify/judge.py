"""ProbeResult + invariant + flag ground truth -> Verdict (spec §4).

`verified` is never produced here; that promotion is the human-gated step in the harness.
"""

import json
from typing import Any

from pydantic import BaseModel

from attack.catalog import ExpectedSignal, Scenario
from attack.engine.probe import ACTOR_HEADER, BLOCKED, ProbeResult
from contracts import Verdict


class VerifiedResult(BaseModel):
    scenario_id: str
    verdict: Verdict
    invariant: str
    signal_matched: bool
    flag_was_on: bool | None
    confidence: float
    evidence_ref: str | None
    notes: str


def _body_text(body: Any) -> str:
    return body if isinstance(body, str) else json.dumps(body, sort_keys=True)


def signal_matched(sig: ExpectedSignal, response: dict[str, Any], request: dict[str, Any]) -> bool:
    """Pure check of the vulnerable-response assertions."""
    if sig.status is not None and response.get("status") != sig.status:
        return False
    text = _body_text(response.get("body"))
    if any(s not in text for s in sig.body_contains):
        return False
    if any(s in text for s in sig.body_not_contains):
        return False
    present = {h.lower() for h in response.get("headers", {})}
    if any(h.lower() in present for h in sig.header_absent):
        return False
    if sig.owner_is_other:
        body = response.get("body")
        owner = body.get("owner_user_id") if isinstance(body, dict) else None
        if not owner or owner == request.get("headers", {}).get(ACTOR_HEADER):
            return False
    return True


def judge(scenario: Scenario, result: ProbeResult) -> VerifiedResult:
    def out(verdict, matched, flag_on, confidence, notes):
        return VerifiedResult(
            scenario_id=scenario.id,
            verdict=verdict,
            invariant=scenario.invariant,
            signal_matched=matched,
            flag_was_on=flag_on,
            confidence=confidence,
            evidence_ref=result.evidence_ref,
            notes=notes,
        )

    if result.error:
        if result.error.startswith(BLOCKED):
            return out(Verdict.BLOCKED, False, None, 1.0, result.error)
        return out(Verdict.INCONCLUSIVE, False, None, 0.1, result.error)
    if not result.response:
        return out(Verdict.INCONCLUSIVE, False, None, 0.1, "empty response")
    if scenario.flag not in result.flags_snapshot:
        return out(Verdict.INCONCLUSIVE, False, None, 0.1, f"flag {scenario.flag!r} not in /__meta")

    matched = signal_matched(scenario.expected_signal, result.response, result.request)
    flag_on = bool(result.flags_snapshot[scenario.flag])
    if matched and flag_on:
        return out(Verdict.CONFIRMED, True, True, 0.95, "vulnerable response with flag on")
    if not matched and not flag_on:
        return out(Verdict.NOT_REPRODUCED, False, False, 0.9, "secure response with flag off")
    if matched:
        return out(
            Verdict.INCONCLUSIVE,
            True,
            False,
            0.3,
            "MISMATCH: vulnerable-looking response but flag off; check verifier/catalog",
        )
    return out(
        Verdict.INCONCLUSIVE,
        False,
        True,
        0.3,
        "probe did not trigger a weakness the flag says is present",
    )
