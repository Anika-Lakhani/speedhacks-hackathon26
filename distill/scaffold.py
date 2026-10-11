"""Create missing memory pages. Never overwrites an existing page unless --force.

uv run python -m distill.scaffold [--force]
"""

import argparse
from pathlib import Path

from distill.pages import PROFILES, render_customer_scaffold, render_shared_scaffold

MEMORY_DIR = Path(__file__).resolve().parents[1] / "memory"


def scaffold(memory_dir: Path = MEMORY_DIR, force: bool = False) -> list[Path]:
    """Write any missing pages; return the paths written."""
    pages = {memory_dir / "customers" / f"{c}.md": render_customer_scaffold(c) for c in PROFILES}
    pages[memory_dir / "shared-intelligence.md"] = render_shared_scaffold()
    written = []
    for path, text in pages.items():
        if path.exists() and not force:
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        written.append(path)
    return written


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--force", action="store_true", help="overwrite existing pages")
    args = ap.parse_args()
    for path in scaffold(force=args.force):
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
