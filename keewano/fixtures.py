"""Generate fixtures/events/<customer_id>.jsonl (dev-B §4a.7). Deterministic; synthetic data only.

    uv run python -m keewano.fixtures

Per customer: 50 organic events and 4 probe.result events (two runs: flag on -> allow,
flag off -> deny). Scenario IDs other than SCN-IDOR-001 are placeholders until Dev A's
catalog exists.
"""

import random
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from contracts import Event, make_evidence_ref

OUT_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "events"
START = datetime(2026, 10, 11, 9, 0, tzinfo=UTC)
REVISION = "fixture-r1"
ORGANIC_PER_CUSTOMER = 50

# (event_type, target, action, policy_outcome weights, state_transition)
ORGANIC = {
    "customer-a": [
        ("auth.login", "/login", "login", {"allow": 8, "deny": 2}, "anonymous->authenticated"),
        ("auth.logout", "/logout", "logout", {"allow": 1}, "authenticated->anonymous"),
        ("order.view", "/orders/{id}", "GET /orders/{n}", {"allow": 9, "deny": 1}, None),
        ("order.create", "/orders", "POST /orders", {"allow": 1}, "cart->order"),
        ("cart.add", "/cart", "POST /cart", {"allow": 1}, None),
        ("auth.password_reset", "/password-reset", "request reset", {"allow": 3, "flag": 1}, None),
    ],
    "customer-b": [
        ("auth.login", "/login", "login", {"allow": 8, "deny": 2}, "anonymous->authenticated"),
        (
            "workspace.view",
            "/workspaces/{id}",
            "GET /workspaces/{n}",
            {"allow": 9, "deny": 1},
            None,
        ),
        ("doc.view", "/docs/{id}", "GET /docs/{n}", {"allow": 9, "deny": 1}, None),
        ("member.invite", "/workspaces/{id}/members", "invite member", {"allow": 1}, None),
        (
            "role.change",
            "/members/{id}/role",
            "set role editor",
            {"allow": 2, "deny": 1},
            "viewer->editor",
        ),
        (
            "integration.callback_register",
            "/integrations",
            "register callback",
            {"allow": 3, "flag": 1},
            None,
        ),
    ],
    "customer-c": [
        ("auth.login", "/login", "login", {"allow": 8, "deny": 2}, "anonymous->authenticated"),
        ("post.view", "/posts/{id}", "GET /posts/{n}", {"allow": 1}, None),
        ("post.create", "/posts", "POST /posts", {"allow": 4, "flag": 1}, None),
        ("comment.create", "/posts/{id}/comments", "POST comment", {"allow": 4, "flag": 1}, None),
        ("upload.create", "/uploads", "POST /uploads", {"allow": 3, "deny": 1}, None),
    ],
}

# (scenario_id, flag, target, action)
PROBES = {
    "customer-a": ("SCN-IDOR-001", "idor_orders", "/orders/{id}", "GET /orders/1002"),
    "customer-b": ("SCN-BOLA-001", "broken_object_authz", "/docs/{id}", "GET /docs/2002"),
    "customer-c": ("SCN-XSS-001", "missing_output_encoding", "/posts/{id}", "GET /posts/3002"),
}


def _id(rng: random.Random) -> str:
    return str(uuid.UUID(int=rng.getrandbits(128), version=4))


def _organic(cid: str, rng: random.Random) -> list[Event]:
    events, ts = [], START
    for _ in range(ORGANIC_PER_CUSTOMER):
        ts += timedelta(seconds=rng.randint(5, 240))
        etype, target, action, outcomes, transition = rng.choice(ORGANIC[cid])
        outcome = rng.choices(list(outcomes), weights=list(outcomes.values()))[0]
        events.append(
            Event(
                event_id=_id(rng),
                customer_id=cid,
                ts=ts,
                actor="user",
                tool=None,
                event_type=etype,
                target=target,
                action=action.replace("{n}", str(rng.randint(1000, 1099))),
                policy_outcome=outcome,
                state_transition=transition if outcome == "allow" else None,
                code_revision=REVISION,
                simulated=False,
            )
        )
    return events


def _probe_results(cid: str, rng: random.Random, after: datetime) -> list[Event]:
    scenario, flag, target, action = PROBES[cid]
    events = []
    for run_no, flag_on in ((1, True), (2, False)):
        run_id = f"fixture-run-{cid}-{run_no}"
        for attempt in range(2):
            eid = _id(rng)
            events.append(
                Event(
                    event_id=eid,
                    customer_id=cid,
                    ts=after + timedelta(minutes=10 * run_no, seconds=attempt),
                    run_id=run_id,
                    actor="system",
                    tool=f"{cid}-site",
                    event_type="probe.result",
                    target=target,
                    action=action,
                    policy_outcome="allow" if flag_on else "deny",
                    code_revision=REVISION,
                    simulated=True,
                    evidence_ref=make_evidence_ref(cid, run_id, eid),
                    scenario_id=scenario,
                    attrs={"flag": flag, "flag_on": flag_on},
                )
            )
    return events


def build(cid: str) -> list[Event]:
    rng = random.Random(f"swarmshield-fixtures-{cid}")
    organic = _organic(cid, rng)
    return organic + _probe_results(cid, rng, organic[-1].ts)


def main(out_dir: Path = OUT_DIR) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for cid in ORGANIC:
        events = build(cid)
        path = out_dir / f"{cid}.jsonl"
        path.write_text(
            "".join(e.model_dump_json(exclude_none=True) + "\n" for e in events), encoding="utf-8"
        )
        print(f"wrote {len(events)} events to {path}")


if __name__ == "__main__":
    main()
