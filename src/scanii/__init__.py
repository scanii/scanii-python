"""Scanii Python SDK — zero-dependency client for the Scanii content security API.

See https://scanii.github.io/openapi/v22/ for the full API reference.
"""

from scanii._version import __version__
from scanii.client import ScaniiClient
from scanii.errors import ScaniiAuthError, ScaniiError, ScaniiRateLimitError
from scanii.models import (
    ScaniiAuthToken,
    ScaniiPendingResult,
    ScaniiProcessingResult,
    ScaniiTraceEvent,
    ScaniiTraceResult,
)
from scanii.target import ScaniiTarget

__all__ = [
    "__version__",
    "ScaniiClient",
    "ScaniiTarget",
    "ScaniiProcessingResult",
    "ScaniiPendingResult",
    "ScaniiAuthToken",
    "ScaniiTraceResult",
    "ScaniiTraceEvent",
    "ScaniiError",
    "ScaniiAuthError",
    "ScaniiRateLimitError",
]
