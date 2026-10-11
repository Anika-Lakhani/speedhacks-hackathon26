from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict

DEFAULT_FLAGS_PATH = Path(__file__).resolve().parents[2] / "contracts" / "flags.yaml"


class FlagDef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    flag: str
    customer_id: str
    default: bool = False
    endpoints: list[str] = []
    scenario_ids: list[str] = []


def load_flags(path: Path = DEFAULT_FLAGS_PATH) -> list[FlagDef]:
    return [FlagDef(**row) for row in yaml.safe_load(path.read_text()) or []]
