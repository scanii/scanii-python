"""Scanii regional API endpoints."""

from __future__ import annotations

from typing import ClassVar
from urllib.parse import urljoin


class ScaniiTarget:
    """
    Scanii regional API endpoint.

    Use one of the predefined regional constants (e.g. ``ScaniiTarget.US1``)
    for production. The constructor accepts an arbitrary URL for testing
    against scanii-cli or other local mocks::

        target = ScaniiTarget("http://localhost:4000")

    Note: ``ScaniiTarget.AUTO`` (latency-based routing) is intentionally
    not provided. Customer data residency / chain-of-custody compliance
    requires an explicit regional choice. Other Scanii SDKs that historically
    defaulted to AUTO are being updated to deprecate it.
    """

    US1: ClassVar[ScaniiTarget]
    EU1: ClassVar[ScaniiTarget]
    EU2: ClassVar[ScaniiTarget]
    AP1: ClassVar[ScaniiTarget]
    AP2: ClassVar[ScaniiTarget]
    CA1: ClassVar[ScaniiTarget]

    def __init__(self, url: str) -> None:
        if not url:
            raise ValueError("ScaniiTarget URL must be a non-empty string")
        self._url = url

    @property
    def endpoint(self) -> str:
        """The base URL this target points at."""
        return self._url

    def resolve(self, path: str) -> str:
        """Join the target's base URL with a request path."""
        base = self._url if self._url.endswith("/") else self._url + "/"
        return urljoin(base, path)

    def __repr__(self) -> str:
        return f"ScaniiTarget({self._url!r})"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ScaniiTarget) and self._url == other._url

    def __hash__(self) -> int:
        return hash(self._url)


ScaniiTarget.US1 = ScaniiTarget("https://api-us1.scanii.com")
ScaniiTarget.EU1 = ScaniiTarget("https://api-eu1.scanii.com")
ScaniiTarget.EU2 = ScaniiTarget("https://api-eu2.scanii.com")
ScaniiTarget.AP1 = ScaniiTarget("https://api-ap1.scanii.com")
ScaniiTarget.AP2 = ScaniiTarget("https://api-ap2.scanii.com")
ScaniiTarget.CA1 = ScaniiTarget("https://api-ca1.scanii.com")
