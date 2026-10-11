"""Shared Gemini plumbing: env config, strict JSON-schema calls, cost estimate, retry."""

import os
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel

DEFAULT_MODEL = "gemini-2.5-flash"
# Rough $/Mtok used only for the budget tracker's spend estimate; override via env.
DEFAULT_PRICE_IN = 1.25
DEFAULT_PRICE_OUT = 10.0

T = TypeVar("T", bound=BaseModel)


def load_dotenv(path: Path = Path(".env")) -> None:
    """Minimal .env reader; real environment variables win."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def strip_additional_properties(node: Any) -> Any:
    """Gemini's structured output rejects `additionalProperties`; strictness is enforced
    on our side by the pydantic models (extra='forbid') when the response is validated."""
    if isinstance(node, dict):
        return {
            k: strip_additional_properties(v)
            for k, v in node.items()
            if k != "additionalProperties"
        }
    if isinstance(node, list):
        return [strip_additional_properties(v) for v in node]
    return node


def gemini_schema(model_cls: type[BaseModel]) -> dict[str, Any]:
    return strip_additional_properties(model_cls.model_json_schema())


class GeminiBase:
    def __init__(self, client: Any = None, model: str | None = None):
        load_dotenv()
        self.model = model or os.environ.get("GEMINI_MODEL", DEFAULT_MODEL)
        if client is None:
            from google import genai

            client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))
        self.client = client

    def _cost(self, usage: Any) -> float:
        price_in = float(os.environ.get("GEMINI_PRICE_IN", DEFAULT_PRICE_IN))
        price_out = float(os.environ.get("GEMINI_PRICE_OUT", DEFAULT_PRICE_OUT))
        tokens_in = getattr(usage, "prompt_token_count", 0) or 0
        tokens_out = getattr(usage, "candidates_token_count", 0) or 0
        return (tokens_in * price_in + tokens_out * price_out) / 1_000_000

    def _call(self, system: str, contents: str, output_cls: type[T]) -> tuple[T, float]:
        resp = self.client.models.generate_content(
            model=self.model,
            contents=contents,
            config={
                "system_instruction": system,
                "response_mime_type": "application/json",
                "response_json_schema": gemini_schema(output_cls),
            },
        )
        # resp.text is None when a safety filter blocks the reply; that fails validation.
        output = output_cls.model_validate_json(resp.text)
        return output, self._cost(getattr(resp, "usage_metadata", None))

    def generate_json(
        self, system: str, contents: str, output_cls: type[T], attempts: int = 2
    ) -> tuple[T | None, float, str | None]:
        """Returns (validated output or None, cost, last error). Retries once by default."""
        cost, error = 0.0, None
        for _ in range(attempts):
            try:
                output, spent = self._call(system, contents, output_cls)
            except Exception as e:  # decode, filter, network or auth failure
                error = f"{type(e).__name__}: {e}"[:300]
                continue
            return output, cost + spent, None
        return None, cost, error
