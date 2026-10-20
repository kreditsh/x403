"""The authority API client: the six calls of spec section 7, sync and async, and
offline verification against the authority's published keys."""

from __future__ import annotations

from typing import Any

from .headers import decode, encode
from .jws import VerifyResult, verify_decision
from .types import VERSION, Authority, Decision, JWKS, Outcome, Receipt, RiskQuery

try:
    import httpx
except ImportError:  # pragma: no cover - the client extra is optional
    httpx = None  # type: ignore[assignment]


class X403Error(Exception):
    def __init__(self, status: int, detail: Any):
        self.status = status
        self.detail = detail
        super().__init__(f"{status}: {detail if isinstance(detail, str) else detail!r}")


def build_query(**fields: Any) -> RiskQuery:
    """Fill scheme and version so a caller passes only what varies."""
    query: dict[str, Any] = {"scheme": "x403", "version": VERSION}
    query.update({k: v for k, v in fields.items() if v is not None})
    return query  # type: ignore[return-value]


def _need_httpx() -> None:
    if httpx is None:
        raise RuntimeError("install x403[client] for the HTTP client")


def _unpack(res: Any) -> Any:
    try:
        payload = res.json() if res.content else {}
    except ValueError:
        payload = res.text
    if res.status_code >= 400:
        detail = payload.get("detail") if isinstance(payload, dict) and "detail" in payload else payload
        raise X403Error(res.status_code, detail)
    return payload


class _Base:
    encode = staticmethod(encode)
    decode = staticmethod(decode)

    def __init__(self, authority: str, api_key: str | None = None, headers: dict[str, str] | None = None, timeout: float = 10.0):
        self.authority = authority.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.extra = dict(headers or {})
        self._jwks: JWKS | None = None
        self._authority: Authority | None = None

    def _headers(self, body: bool) -> dict[str, str]:
        out = {"accept": "application/json", **self.extra}
        if body:
            out["content-type"] = "application/json"
        if self.api_key:
            out["authorization"] = f"Bearer {self.api_key}"
        return out

    def _jwks_path(self) -> str:
        url = (self._authority or {}).get("jwks_url") or f"{self.authority}/.well-known/x403/jwks.json"
        return url[len(self.authority) :] if url.startswith(self.authority) else url

    def reset(self) -> None:
        """Forget cached keys, e.g. after a verify fails on an unknown kid."""
        self._jwks = None
        self._authority = None


class X403(_Base):
    def __init__(self, authority: str, api_key: str | None = None, headers: dict[str, str] | None = None, timeout: float = 10.0, client: Any = None):
        super().__init__(authority, api_key, headers, timeout)
        _need_httpx()
        self._client = client or httpx.Client(timeout=timeout)

    def _call(self, method: str, path: str, body: Any = None) -> Any:
        url = path if path.startswith("http") else f"{self.authority}{path}"
        res = self._client.request(method, url, json=body, headers=self._headers(body is not None))
        return _unpack(res)

    def decide(self, **fields: Any) -> Decision:
        return self._call("POST", "/x403/decide", build_query(**fields))

    def preflight(self, **fields: Any) -> Decision:
        """The same question with mode preflight: decide now, pay later citing the id."""
        return self._call("POST", "/x403/decide", build_query(**{**fields, "mode": "preflight"}))

    def receipt(self, receipt: Receipt) -> Receipt:
        return self._call("POST", "/x403/receipts", receipt)

    def outcome(self, outcome: Outcome) -> Outcome:
        return self._call("POST", "/x403/outcomes", outcome)

    def get(self, decision_id: str) -> Decision:
        return self._call("GET", f"/x403/decisions/{decision_id}")

    def authority_document(self) -> Authority:
        if self._authority is None:
            self._authority = self._call("GET", "/.well-known/x403/authority.json")
        return self._authority  # type: ignore[return-value]

    def jwks(self) -> JWKS:
        """The authority's keys, fetched once from the address its document names."""
        if self._jwks is None:
            try:
                self.authority_document()
            except X403Error:
                pass  # without a document the conventional path still answers
            self._jwks = self._call("GET", self._jwks_path())
        return self._jwks  # type: ignore[return-value]

    def verify(self, decision: Decision) -> VerifyResult:
        """Offline verification of a decision against the cached keys."""
        return verify_decision(decision, self.jwks())


class AsyncX403(_Base):
    def __init__(self, authority: str, api_key: str | None = None, headers: dict[str, str] | None = None, timeout: float = 10.0, client: Any = None):
        super().__init__(authority, api_key, headers, timeout)
        _need_httpx()
        self._client = client or httpx.AsyncClient(timeout=timeout)

    async def _call(self, method: str, path: str, body: Any = None) -> Any:
        url = path if path.startswith("http") else f"{self.authority}{path}"
        res = await self._client.request(method, url, json=body, headers=self._headers(body is not None))
        return _unpack(res)

    async def decide(self, **fields: Any) -> Decision:
        return await self._call("POST", "/x403/decide", build_query(**fields))

    async def preflight(self, **fields: Any) -> Decision:
        return await self._call("POST", "/x403/decide", build_query(**{**fields, "mode": "preflight"}))

    async def receipt(self, receipt: Receipt) -> Receipt:
        return await self._call("POST", "/x403/receipts", receipt)

    async def outcome(self, outcome: Outcome) -> Outcome:
        return await self._call("POST", "/x403/outcomes", outcome)

    async def get(self, decision_id: str) -> Decision:
        return await self._call("GET", f"/x403/decisions/{decision_id}")

    async def authority_document(self) -> Authority:
        if self._authority is None:
            self._authority = await self._call("GET", "/.well-known/x403/authority.json")
        return self._authority  # type: ignore[return-value]

    async def jwks(self) -> JWKS:
        if self._jwks is None:
            try:
                await self.authority_document()
            except X403Error:
                pass
            self._jwks = await self._call("GET", self._jwks_path())
        return self._jwks  # type: ignore[return-value]

    async def verify(self, decision: Decision) -> VerifyResult:
        return verify_decision(decision, await self.jwks())
