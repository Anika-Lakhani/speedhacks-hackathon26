from typing import Any, Protocol

import httpx
from pydantic import BaseModel


class SiteResponse(BaseModel):
    status: int
    headers: dict[str, str] = {}
    body: Any = None


class Site(Protocol):
    base_url: str

    def meta(self) -> dict[str, Any]: ...

    def set_flags(self, flags: dict[str, bool]) -> dict[str, Any]: ...

    def probe(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        query: dict[str, str] | None = None,
        json: dict[str, str] | None = None,
    ) -> SiteResponse: ...


class SiteClient:
    """Thin httpx wrapper over a demo site (dev-B §4a.1)."""

    def __init__(self, base_url: str, timeout: float = 5.0):
        self.base_url = base_url.rstrip("/")
        self._http = httpx.Client(base_url=self.base_url, timeout=timeout)

    def meta(self) -> dict[str, Any]:
        r = self._http.get("/__meta")
        r.raise_for_status()
        return r.json()

    def set_flags(self, flags: dict[str, bool]) -> dict[str, Any]:
        """Test-only: set ground truth before a run."""
        r = self._http.put("/__flags", json=flags)
        r.raise_for_status()
        return r.json()

    def probe(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        query: dict[str, str] | None = None,
        json: dict[str, str] | None = None,
    ) -> SiteResponse:
        r = self._http.request(method, path, headers=headers, params=query, json=json)
        try:
            body: Any = r.json()
        except ValueError:
            body = r.text
        return SiteResponse(status=r.status_code, headers=dict(r.headers), body=body)
