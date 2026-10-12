"""Demo dashboard: one page per customer, read-only over B's and C's data, plus the write
paths (configure + Run, toggle flags, Fix, review gates) when wired to an in-process world.

    uv run uvicorn dashboard.app:create_app --factory --port 8000        # read-only (live B/C)
    uv run --env-file .env uvicorn dashboard.app:create_demo_app --factory --port 8000  # full loop
"""

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from dashboard.data import DashboardData

STATIC = Path(__file__).parent / "static"


class ScenarioBody(BaseModel):
    scenario_id: str


class ApproveBody(BaseModel):
    run_id: str
    scenario_id: str


class FlagsBody(BaseModel):
    flags: dict[str, bool]


def create_app(data: DashboardData | None = None, world=None) -> FastAPI:
    if world is not None and data is None:
        data = world.data
    data = data or DashboardData()
    app = FastAPI(title="SwarmShield dashboard")

    def customer(customer_id: str) -> str:
        if not data.known(customer_id):
            raise HTTPException(404, f"unknown customer '{customer_id}'")
        return customer_id

    @app.get("/api/customers")
    def customers():
        return data.customers()

    @app.get("/api/customer/{customer_id}/meta")
    def meta(customer_id: str):
        return data.meta(customer(customer_id))

    @app.get("/api/customer/{customer_id}/flags")
    def flags(customer_id: str):
        return data.flags(customer(customer_id))

    @app.get("/api/customer/{customer_id}/runs")
    def runs(customer_id: str):
        return data.runs(customer(customer_id))

    @app.get("/api/customer/{customer_id}/vulnerabilities")
    def vulnerabilities(customer_id: str):
        return data.vulnerabilities(customer(customer_id))

    @app.get("/api/customer/{customer_id}/memory")
    def memory(customer_id: str):
        return data.memory(customer(customer_id))

    @app.get("/api/shared")
    def shared():
        return data.shared()

    if world is not None:
        _register_write_routes(app, world, customer)

    @app.get("/api/features")
    def features():
        return {"write": world is not None}

    @app.get("/")
    def index():
        return FileResponse(STATIC / "index.html")

    @app.get("/customer/{customer_id}")
    def customer_page(customer_id: str):
        customer(customer_id)
        return FileResponse(STATIC / "customer.html")

    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    return app


def _register_write_routes(app: FastAPI, world, customer) -> None:
    from attack.catalog.generation import PromotionError
    from dashboard.demo import RunBusy, RunOptions

    @app.post("/api/customer/{customer_id}/run")
    def start_run(customer_id: str, options: RunOptions):
        try:
            return {"run_id": world.start_run(customer(customer_id), options)}
        except RunBusy as e:
            raise HTTPException(409, str(e)) from e

    @app.get("/api/run/{run_id}")
    def run_status(run_id: str):
        try:
            return world.run_status(run_id)
        except KeyError as e:
            raise HTTPException(404, f"unknown run '{run_id}'") from e

    @app.put("/api/customer/{customer_id}/flags")
    def set_flags(customer_id: str, body: FlagsBody):
        try:
            return world.set_flags(customer(customer_id), body.flags)
        except KeyError as e:
            raise HTTPException(400, str(e)) from e

    @app.post("/api/customer/{customer_id}/reset")
    def reset(customer_id: str):
        return world.reset_demo(customer(customer_id))

    @app.post("/api/customer/{customer_id}/fix")
    def fix(customer_id: str, body: ScenarioBody):
        try:
            return world.fix(customer(customer_id), body.scenario_id)
        except KeyError as e:
            raise HTTPException(400, str(e)) from e

    @app.get("/api/customer/{customer_id}/generated")
    def generated(customer_id: str):
        return world.generated_scenarios(customer(customer_id))

    @app.post("/api/customer/{customer_id}/generated/promote")
    def promote(customer_id: str, body: ScenarioBody):
        customer(customer_id)
        try:
            return world.promote(body.scenario_id)
        except PromotionError as e:
            raise HTTPException(400, str(e)) from e
        except KeyError as e:
            raise HTTPException(404, str(e)) from e

    @app.post("/api/customer/{customer_id}/generated/reject")
    def reject(customer_id: str, body: ScenarioBody):
        customer(customer_id)
        try:
            return world.reject(body.scenario_id)
        except KeyError as e:
            raise HTTPException(404, str(e)) from e

    @app.get("/api/customer/{customer_id}/approvals")
    def approvals(customer_id: str):
        return world.approvals(customer(customer_id))

    @app.post("/api/customer/{customer_id}/approvals/approve")
    def approve(customer_id: str, body: ApproveBody):
        customer(customer_id)
        try:
            return world.approve(body.run_id, body.scenario_id)
        except KeyError as e:
            raise HTTPException(404, str(e)) from e


def create_demo_app() -> FastAPI:
    """Full loop over in-process fakes: every write path works with nothing else running."""
    from dashboard.demo import DemoWorld

    return create_app(world=DemoWorld())


def create_live_app() -> FastAPI:
    """Full loop against the REAL Keewano store and REAL demo sites, both over HTTP.

        uv run python -m keewano.setup
        uv run uvicorn keewano.api:create_app --factory --port 4000
        SWARMSHIELD_STORE_URL=http://localhost:4000 uv run uvicorn \\
            sites.customer_a.app:create_app --factory --port 3001
        SWARMSHIELD_SHARE_MODE=auto uv run --env-file .env uvicorn \\
            dashboard.app:create_live_app --factory --port 8000
    """
    import os

    from attack.clients.keewano import KeewanoClient
    from attack.clients.site import SiteClient
    from dashboard.data import _site_url
    from dashboard.demo import DemoWorld

    keewano = KeewanoClient(
        os.environ.get("DASHBOARD_KEEWANO_URL", "http://localhost:4000"), timeout=5.0
    )
    return create_app(
        world=DemoWorld(
            keewano=keewano,
            site_factory=lambda cid: SiteClient(_site_url(cid), timeout=5.0),
        )
    )
