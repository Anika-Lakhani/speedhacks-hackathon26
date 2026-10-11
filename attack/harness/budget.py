import time
from collections.abc import Callable

from attack.clients.site import SiteResponse
from attack.harness.config import RunBudget


class HaltRun(BaseException):
    """Stops a run. A BaseException so the engine's per-probe `except Exception` cannot
    swallow a budget or allowlist breach and turn it into an `inconclusive` verdict."""


class BudgetExceeded(HaltRun):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class ToolNotAllowed(HaltRun):
    pass


class BudgetTracker:
    """Ticks runtime, tool calls and spend; the first breach halts the run."""

    def __init__(
        self,
        budget: RunBudget,
        allowed_tools: list[str],
        clock: Callable[[], float] = time.monotonic,
    ):
        self.budget = budget
        self.allowed_tools = set(allowed_tools)
        self._clock = clock
        self._start = clock()
        self.tool_calls = 0
        self.spend_usd = 0.0

    @property
    def elapsed_s(self) -> float:
        return self._clock() - self._start

    def add_spend(self, usd: float) -> None:
        self.spend_usd += usd
        self.check()

    def check(self) -> None:
        if self.elapsed_s > self.budget.max_runtime_s:
            raise BudgetExceeded("max_runtime_s")
        if self.spend_usd > self.budget.max_spend_usd:
            raise BudgetExceeded("max_spend_usd")

    def require_calls(self, n: int) -> None:
        """Pre-check that a multi-call step (probe + meta) fits before starting it."""
        self.check()
        if self.tool_calls + n > self.budget.max_tool_calls:
            raise BudgetExceeded("max_tool_calls")

    def before_call(self, tool: str) -> None:
        if tool not in self.allowed_tools:
            raise ToolNotAllowed(tool)
        self.check()
        if self.tool_calls >= self.budget.max_tool_calls:
            raise BudgetExceeded("max_tool_calls")
        self.tool_calls += 1

    def usage(self) -> dict:
        return {
            "tool_calls": self.tool_calls,
            "runtime_s": round(self.elapsed_s, 3),
            "spend_usd": round(self.spend_usd, 4),
        }


class GuardedSite:
    """Site wrapper so every call the engine makes passes the allowlist and the budget."""

    def __init__(self, site, tracker: BudgetTracker):
        self._site = site
        self._tracker = tracker
        self.base_url = site.base_url

    def meta(self):
        self._tracker.before_call("site.meta")
        return self._site.meta()

    def probe(self, method, path, headers, query=None, json=None) -> SiteResponse:
        self._tracker.before_call("site.probe")
        return self._site.probe(method, path, headers, query=query, json=json)
