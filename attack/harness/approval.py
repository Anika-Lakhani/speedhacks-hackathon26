"""Human gate between `confirmed` (reproduced) and the `verified` evidence label."""

import json
from pathlib import Path

from pydantic import BaseModel

DEFAULT_QUEUE_PATH = Path(".data") / "swarmshield" / "approvals.json"  # .data/ is gitignored


class PendingApproval(BaseModel):
    customer_id: str
    run_id: str
    scenario_id: str
    evidence_ref: str | None
    status: str = "pending"  # pending | approved


class ApprovalQueue:
    def __init__(self, path: Path | None = DEFAULT_QUEUE_PATH):
        self.path = path
        self.items: list[PendingApproval] = []
        if path and path.exists():
            self.items = [PendingApproval(**row) for row in json.loads(path.read_text())]

    def _save(self) -> None:
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps([i.model_dump() for i in self.items], indent=2))

    def add(self, item: PendingApproval) -> None:
        self.items.append(item)
        self._save()

    def pending(self, run_id: str | None = None) -> list[PendingApproval]:
        return [
            i
            for i in self.items
            if i.status == "pending" and (run_id is None or i.run_id == run_id)
        ]

    def approve(self, run_id: str, scenario_id: str) -> PendingApproval:
        for item in self.items:
            if (
                item.run_id == run_id
                and item.scenario_id == scenario_id
                and item.status == "pending"
            ):
                item.status = "approved"
                self._save()
                return item
        raise KeyError(f"nothing pending for {run_id}/{scenario_id}")
