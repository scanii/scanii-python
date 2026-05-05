"""Scanii SDK exception hierarchy."""

from __future__ import annotations


class ScaniiError(Exception):
    """Base exception for all Scanii API errors.

    Raised on HTTP 4xx/5xx responses. Carries the API-supplied message plus
    optional diagnostic headers for support handoffs.

    Per SDK Principle 3 (integration-only) the SDK does not retry on the
    caller's behalf — backoff is the caller's responsibility.

    See https://scanii.github.io/openapi/v22/
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        request_id: str | None = None,
        host_id: str | None = None,
        body: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.request_id = request_id
        self.host_id = host_id
        self.body = body


class ScaniiAuthError(ScaniiError):
    """Raised on HTTP 401 or 403 — credentials rejected by the API."""


class ScaniiRateLimitError(ScaniiError):
    """Raised on HTTP 429.

    ``retry_after`` carries the value of the ``Retry-After`` response header in
    seconds when the server provided one, otherwise ``None``.
    """

    def __init__(self, message: str, *, retry_after: int | None = None, **kwargs: object) -> None:
        super().__init__(message, **kwargs)  # type: ignore[arg-type]
        self.retry_after = retry_after
