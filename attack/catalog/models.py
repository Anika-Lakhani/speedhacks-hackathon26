import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

PATH_PARAM = re.compile(r"\{(\w+)\}")
MARKER_HEADER = "X-SwarmShield-Probe"

Severity = Literal["low", "medium", "high", "critical"]


class Probe(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["benign_request"]
    method: str
    path: str
    params: dict[str, str] = {}
    marker_header: str = MARKER_HEADER

    @model_validator(mode="after")
    def _path_params_defined(self) -> "Probe":
        self.method = self.method.upper()
        missing = set(PATH_PARAM.findall(self.path)) - set(self.params)
        if missing:
            raise ValueError(f"path params without a value in params: {sorted(missing)}")
        return self


class ExpectedSignal(BaseModel):
    """What a VULNERABLE (flag on) response looks like."""

    model_config = ConfigDict(extra="forbid")

    status: int | None = None
    body_contains: list[str] = []
    body_not_contains: list[str] = []
    header_absent: list[str] = []
    owner_is_other: bool = False


class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^SCN-[A-Z]+-\d{3}$")
    title: str
    customer_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    weakness_class: str
    invariant: str
    flag: str
    preconditions: list[str] = []
    probe: Probe
    expected_signal: ExpectedSignal
    severity: Severity
    # Generated scenarios are LLM-drafted data that passed code-side validation; provenance
    # records which model/prompt/run produced them and why.
    origin: Literal["curated", "generated"] = "curated"
    provenance: dict[str, Any] | None = None
