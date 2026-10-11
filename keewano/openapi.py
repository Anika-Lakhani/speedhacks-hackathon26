"""Write docs/openapi.json from the FastAPI app (a test fails if it's stale).

uv run python -m keewano.openapi
"""

import json
import tempfile
from pathlib import Path

from keewano.api import create_app
from keewano.config import Settings

OPENAPI_PATH = Path(__file__).resolve().parents[1] / "docs" / "openapi.json"


def openapi_spec() -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        settings = Settings(
            sqlite_path=Path(tmp) / "openapi.sqlite3", rejects_path=Path(tmp) / "r.jsonl"
        )
        app = create_app(settings)
        try:
            return app.openapi()
        finally:
            app.state.store.close()  # Windows can't delete an open SQLite file


def main() -> None:
    OPENAPI_PATH.write_text(json.dumps(openapi_spec(), indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OPENAPI_PATH}")


if __name__ == "__main__":
    main()
