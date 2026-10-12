"""Reset the demo to a fresh, repeatable start state — run this between demos.

    uv run --env-file .env python -m dashboard.reset_demo

What it does:
  1. Wipes every memory page back to a clean scaffold and clears the shared corpus.
  2. Re-runs the fleet seed so customer-b/c and shared-intelligence.md are richly populated
     again (the "already-established intelligence layer").
  3. Arms a few vulnerabilities on the live customer-a site so the next scan has real findings.

customer-a's page stays clean so the live run visibly fills it in. The store (:4000) and the
customer-a site (:3001) must be running.
"""

import os
import shutil

import httpx

import dashboard.seed_demo as seed
from distill.scaffold import MEMORY_DIR, scaffold

# Vulnerabilities to re-arm on customer-a (3 weaknesses, 4 scenarios: IDOR, login + OTP rate
# limiting, weak password reset). Trim this dict if you want a shorter demo.
ARM_FLAGS = {
    "idor_orders": True,
    "login_rate_limit_off": True,
    "weak_password_reset": True,
}
SITE_A_URL = os.environ.get("DASHBOARD_SITE_URL_CUSTOMER_A", "http://localhost:3001")


def main(memory_dir=MEMORY_DIR) -> None:
    # 1. clean slate for all pages + corpus
    scaffold(memory_dir, force=True)
    shutil.rmtree(memory_dir / "shared", ignore_errors=True)
    print("memory pages reset to clean scaffolds.")

    # 2. rebuild the established fleet (customer-b/c + shared corpus)
    seed.main(memory_dir)

    # 3. arm vulnerabilities on customer-a so the next scan finds something
    r = httpx.put(f"{SITE_A_URL}/__flags", json=ARM_FLAGS, timeout=10.0)
    r.raise_for_status()
    armed = [k for k, v in r.json()["flags"].items() if v]
    print(f"\ncustomer-a armed ({r.json()['code_revision']}): {', '.join(armed)}")
    print("Ready to demo again.")


if __name__ == "__main__":
    main()
