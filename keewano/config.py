"""Store configuration, read from environment variables only.

Swapping the storage implementation is a config change: SWARMSHIELD_STORE=sqlite|keewano.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_TENANTS = ("customer-a", "customer-b", "customer-c")
DATA_DIR = Path(".data")


@dataclass(frozen=True)
class Settings:
    store: str = "sqlite"
    sqlite_path: Path = DATA_DIR / "keewano.sqlite3"
    rejects_path: Path = DATA_DIR / "rejects.jsonl"
    tenants: tuple[str, ...] = DEFAULT_TENANTS
    # Keewano (M3b); unused until the ingestion method is decided
    keewano_project_ids: dict[str, str] = field(default_factory=dict)


def _tenants(raw: str | None) -> tuple[str, ...]:
    if not raw:
        return DEFAULT_TENANTS
    return tuple(t.strip() for t in raw.split(",") if t.strip())


def _project_ids(raw: str | None) -> dict[str, str]:
    """KEEWANO_PROJECT_IDS="customer-a=<uuid>,customer-b=<uuid>" (one project per tenant)."""
    out = {}
    for pair in (raw or "").split(","):
        if "=" in pair:
            tenant, pid = pair.split("=", 1)
            out[tenant.strip()] = pid.strip()
    return out


def load_settings(env: dict[str, str] | None = None) -> Settings:
    env = os.environ if env is None else env
    defaults = Settings()
    return Settings(
        store=env.get("SWARMSHIELD_STORE", defaults.store).strip().lower(),
        sqlite_path=Path(env.get("SWARMSHIELD_SQLITE_PATH", defaults.sqlite_path)),
        rejects_path=Path(env.get("SWARMSHIELD_REJECTS_PATH", defaults.rejects_path)),
        tenants=_tenants(env.get("SWARMSHIELD_TENANTS")),
        keewano_project_ids=_project_ids(env.get("KEEWANO_PROJECT_IDS")),
    )
