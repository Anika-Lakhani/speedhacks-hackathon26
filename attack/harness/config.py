from pydantic import BaseModel


class RunBudget(BaseModel):
    max_scenarios: int = 12
    max_tool_calls: int = 50
    max_runtime_s: int = 120
    max_retries: int = 0
    max_spend_usd: float = 1.0
    max_swarm_size: int = 1


DEFAULT_TOOLS = ["site.meta", "site.probe", "keewano.post_events", "keewano.get_slice"]


class RunConfig(BaseModel):
    customer_id: str
    objective: str
    budget: RunBudget = RunBudget()
    allowed_tools: list[str] = list(DEFAULT_TOOLS)  # anything else is refused
    target_allowlist: list[str]  # base URLs the engine may hit
    # POSTs only ever go to synthetic fixtures on simulated demo sites.
    allowed_verbs: list[str] = ["GET", "HEAD", "OPTIONS", "POST"]
    require_approval: bool = True  # human gate before promoting to `verified`
    auto_approve: bool = False  # demo flag: release the gate immediately
    diff_summary: str = ""
    changed_surfaces: list[str] = []
    # Scenario generation: 0 disables it. code_context is path -> source, read by the caller.
    generate_max: int = 0
    code_context: dict[str, str] = {}
    event_limit: int = 40
