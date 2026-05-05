"""Hand-rolled multipart/form-data encoder (RFC 7578).

Internal module — underscore-prefixed, not part of the public API.
"""

from __future__ import annotations

import mimetypes
import secrets
from typing import IO


def _make_boundary() -> str:
    return f"----scanii-python-boundary-{secrets.token_hex(16)}"


def _guess_content_type(filename: str) -> str:
    ct, _ = mimetypes.guess_type(filename)
    return ct or "application/octet-stream"


def encode(
    fields: dict[str, str],
    file_obj: IO[bytes] | None = None,
    filename: str | None = None,
    content_type: str | None = None,
) -> tuple[bytes, str]:
    """Encode a multipart/form-data body.

    When ``file_obj`` is provided (anything with ``read(n) -> bytes``), reads
    from it into a file part. When ``file_obj`` is ``None``, produces a
    fields-only multipart body (used by ``process_from_url``'s ``location=``
    case).

    Returns ``(body_bytes, content_type_header)`` where ``content_type_header``
    is the full ``Content-Type: multipart/form-data; boundary=...`` string.
    """
    boundary = _make_boundary()
    parts: list[bytes] = []

    for name, value in fields.items():
        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{name}"\r\n'
            f"Content-Type: text/plain; charset=UTF-8\r\n"
            f"\r\n"
            f"{value}\r\n".encode("utf-8")
        )

    if file_obj is not None:
        if filename is None:
            raise ValueError("filename is required when file_obj is provided")
        ct = content_type or _guess_content_type(filename)
        header = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: {ct}\r\n"
            f"\r\n"
        ).encode("utf-8")
        file_bytes = file_obj.read()
        parts.append(header + file_bytes + b"\r\n")

    parts.append(f"--{boundary}--\r\n".encode("utf-8"))

    body = b"".join(parts)
    ct_header = f"multipart/form-data; boundary={boundary}"
    return body, ct_header
