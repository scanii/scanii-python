"""Scanii SDK response model dataclasses."""

from __future__ import annotations

import json
import warnings
from dataclasses import dataclass


@dataclass(frozen=True)
class ScaniiTraceEvent:
    """A single processing event in a scan trace.

    See https://scanii.github.io/openapi/v22/
    """

    timestamp: str
    message: str

    @classmethod
    def from_dict(cls, raw: dict[str, object]) -> "ScaniiTraceEvent":
        return cls(
            timestamp=str(raw.get("timestamp") or ""),
            message=str(raw.get("message") or ""),
        )


@dataclass(frozen=True)
class ScaniiTraceResult:
    """Result of :meth:`~scanii.ScaniiClient.retrieve_trace`.

    This is a v2.2 preview surface; the API shape may shift before it is
    marked stable.

    See https://scanii.github.io/openapi/v22/
    """

    resource_id: str
    events: tuple[ScaniiTraceEvent, ...]
    request_id: str | None
    host_id: str | None

    @classmethod
    def from_response(cls, body: str, headers: dict[str, str]) -> "ScaniiTraceResult":
        raw = json.loads(body) if body else {}
        return cls(
            resource_id=str(raw.get("id") or ""),
            events=tuple(ScaniiTraceEvent.from_dict(e) for e in raw.get("events") or []),
            request_id=headers.get("x-scanii-request-id"),
            host_id=headers.get("x-scanii-host-id"),
        )


@dataclass(frozen=True)
class ScaniiProcessingResult:
    """Result of a synchronous scan returned by :meth:`~scanii.ScaniiClient.process`,
    :meth:`~scanii.ScaniiClient.process_file`, :meth:`~scanii.ScaniiClient.process_from_url`,
    and :meth:`~scanii.ScaniiClient.retrieve`.

    ``findings`` is always a tuple. An empty tuple means the content is clean.

    See https://scanii.github.io/openapi/v22/
    """

    id: str
    findings: tuple[str, ...]
    checksum: str | None
    content_length: int | None
    content_type: str | None
    metadata: dict[str, str]
    creation_date: str | None
    request_id: str | None
    host_id: str | None
    resource_location: str | None
    error: str | None = None
    """
    .. deprecated:: 1.0.0
       Server-side errors arrive as :class:`~scanii.ScaniiError` subclasses on
       non-2xx responses; this field is never populated on success.
       Will be removed in a future major version.
    """

    def __post_init__(self) -> None:
        if self.error is not None:
            warnings.warn(
                "ScaniiProcessingResult.error is deprecated and will be removed in a "
                "future major version. Server-side errors arrive as ScaniiError "
                "subclasses on non-2xx responses; this field is never populated on success.",
                DeprecationWarning,
                stacklevel=2,
            )

    @classmethod
    def from_response(cls, body: str, headers: dict[str, str]) -> "ScaniiProcessingResult":
        raw = json.loads(body) if body else {}
        return cls(
            id=str(raw.get("id") or ""),
            findings=tuple(str(f) for f in (raw.get("findings") or [])),
            checksum=str(raw["checksum"]) if raw.get("checksum") is not None else None,
            content_length=(
                int(raw["content_length"]) if raw.get("content_length") is not None else None
            ),
            content_type=(
                str(raw["content_type"]) if raw.get("content_type") is not None else None
            ),
            metadata={str(k): str(v) for k, v in (raw.get("metadata") or {}).items()},
            creation_date=(
                str(raw["creation_date"]) if raw.get("creation_date") is not None else None
            ),
            request_id=headers.get("x-scanii-request-id"),
            host_id=headers.get("x-scanii-host-id"),
            resource_location=headers.get("location"),
            error=str(raw["error"]) if raw.get("error") is not None else None,
        )


@dataclass(frozen=True)
class ScaniiPendingResult:
    """Result of an asynchronous scan submission returned by
    :meth:`~scanii.ScaniiClient.process_async`, :meth:`~scanii.ScaniiClient.process_async_file`,
    and :meth:`~scanii.ScaniiClient.fetch`.

    The actual scan result is fetched later via :meth:`~scanii.ScaniiClient.retrieve`
    or delivered to the supplied callback URL.

    See https://scanii.github.io/openapi/v22/
    """

    id: str
    request_id: str | None
    host_id: str | None
    resource_location: str | None

    @classmethod
    def from_response(cls, body: str, headers: dict[str, str]) -> "ScaniiPendingResult":
        raw = json.loads(body) if body else {}
        return cls(
            id=str(raw.get("id") or ""),
            request_id=headers.get("x-scanii-request-id"),
            host_id=headers.get("x-scanii-host-id"),
            resource_location=headers.get("location"),
        )


@dataclass(frozen=True)
class ScaniiAuthToken:
    """Short-lived auth token returned by :meth:`~scanii.ScaniiClient.create_auth_token`
    and :meth:`~scanii.ScaniiClient.retrieve_auth_token`.

    Pass ``id`` as the ``token`` argument when constructing a :class:`~scanii.ScaniiClient`
    to authenticate using the token instead of API key + secret.

    See https://scanii.github.io/openapi/v22/
    """

    id: str
    creation_date: str | None
    expiration_date: str | None
    request_id: str | None
    host_id: str | None
    resource_location: str | None

    @classmethod
    def from_response(cls, body: str, headers: dict[str, str]) -> "ScaniiAuthToken":
        raw = json.loads(body) if body else {}
        return cls(
            id=str(raw.get("id") or ""),
            creation_date=(
                str(raw["creation_date"]) if raw.get("creation_date") is not None else None
            ),
            expiration_date=(
                str(raw["expiration_date"]) if raw.get("expiration_date") is not None else None
            ),
            request_id=headers.get("x-scanii-request-id"),
            host_id=headers.get("x-scanii-host-id"),
            resource_location=headers.get("location"),
        )
