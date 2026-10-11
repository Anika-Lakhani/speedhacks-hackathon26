"""Create per-tenant storage for the configured store. Safe to run any number of times.

uv run python -m keewano.setup
"""

from keewano.config import load_settings
from keewano.storage import make_store


def main() -> None:
    settings = load_settings()
    store = make_store(settings)
    store.setup(settings.tenants)
    where = f" at {settings.sqlite_path}" if settings.store == "sqlite" else ""
    print(f"{settings.store} store ready{where}: {', '.join(sorted(store.tenants()))}")


if __name__ == "__main__":
    main()
