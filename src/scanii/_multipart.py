"""Hand-rolled multipart/form-data encoder (RFC 7578).

Internal module — underscore-prefixed, not part of the public API.

The encoder is stream-first: when a file_obj is provided it builds a
:class:`_ChainedIO` that chains prologue bytes + the caller's IO + epilogue
bytes without reading the file body at construction time. The file content is
only read when urllib reads from the chained stream on the wire.

Mirrors the approach of scanii-ruby's Multipart::ChainedIO and
scanii-rust's prologue/epilogue pattern.
"""

from __future__ import annotations

import io
import mimetypes
import os
import secrets
import tempfile
from typing import IO, cast


def _make_boundary() -> str:
    return f"----scanii-python-boundary-{secrets.token_hex(16)}"


def _guess_content_type(filename: str) -> str:
    ct, _ = mimetypes.guess_type(filename)
    return ct or "application/octet-stream"


def _io_remaining_bytes(file_obj: IO[bytes]) -> int | None:
    """Return the number of bytes remaining to be read from file_obj, or None.

    Tries three strategies in order:
    1. ``fileno()`` + ``os.fstat`` — most reliable for real files.
    2. ``getvalue()`` — works for in-memory :class:`io.BytesIO` and
       :class:`tempfile.SpooledTemporaryFile` when still in RAM.
    3. ``seek``/``tell`` — works for any seekable IO; restores position.

    Returns ``None`` when all three fail (pipes, generators, sockets).
    """
    # Strategy 1 — real files with an OS file descriptor
    try:
        fd = file_obj.fileno()
        size = os.fstat(fd).st_size
        pos = file_obj.tell()
        return size - pos
    except (AttributeError, io.UnsupportedOperation, OSError):
        pass

    # Strategy 2 — BytesIO / in-memory SpooledTemporaryFile
    try:
        val: bytes = file_obj.getvalue()  # type: ignore[attr-defined]
        pos = file_obj.tell()
        return len(val) - pos
    except AttributeError:
        pass

    # Strategy 3 — any seekable IO
    try:
        pos = file_obj.tell()
        file_obj.seek(0, 2)
        end = file_obj.tell()
        file_obj.seek(pos)
        return end - pos
    except (AttributeError, OSError, io.UnsupportedOperation):
        pass

    return None


class _ChainedIO:
    """Sequential reader over a list of IO parts.

    Reads from parts[0] until exhausted, then parts[1], etc. — without
    reading any part at construction time. Used to chain prologue bytes +
    a caller-supplied file IO + epilogue bytes so the file body is only
    read when urllib transfers bytes to the socket.

    Mirrors Ruby's ``Scanii::Multipart::ChainedIO``.
    """

    def __init__(self, parts: list[IO[bytes]]) -> None:
        self._parts = parts
        self._idx = 0

    def read(self, n: int = -1) -> bytes:
        if n < 0:
            return self._read_all()
        return self._read_n(n)

    def _read_all(self) -> bytes:
        chunks: list[bytes] = []
        while self._idx < len(self._parts):
            chunk = self._parts[self._idx].read()
            if chunk:
                chunks.append(chunk)
            self._idx += 1
        return b"".join(chunks)

    def _read_n(self, n: int) -> bytes:
        if n == 0:
            return b""
        chunks: list[bytes] = []
        remaining = n
        while remaining > 0 and self._idx < len(self._parts):
            chunk = self._parts[self._idx].read(remaining)
            if chunk:
                chunks.append(chunk)
                remaining -= len(chunk)
            else:
                self._idx += 1
        return b"".join(chunks)


def encode(
    fields: dict[str, str],
    file_obj: IO[bytes] | None = None,
    filename: str | None = None,
    content_type: str | None = None,
) -> tuple[IO[bytes], str, int]:
    """Encode a multipart/form-data body.

    **File mode** (``file_obj`` provided): returns a :class:`_ChainedIO` that
    streams prologue bytes → file body → epilogue bytes without reading the
    file at construction time. The caller's IO is only read when urllib reads
    from the returned stream. Paths and ``BytesIO`` get true socket-level
    streaming; IOs without ``fileno()`` or ``seek``/``tell`` fall back to a
    ``SpooledTemporaryFile(max_size=1 MiB)`` — small payloads stay in memory,
    larger ones spill to disk.

    **Fields-only mode** (``file_obj=None``): returns an ``io.BytesIO``
    containing a multipart body with no file part. Used by
    ``process_from_url``.

    Returns ``(body_stream, content_type_header, content_length)``.
    """
    boundary = _make_boundary()
    ct_header = f"multipart/form-data; boundary={boundary}"

    # Build text-field parts (same for both modes)
    text_bytes: list[bytes] = []
    for name, value in fields.items():
        text_bytes.append(
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{name}"\r\n'
                f"Content-Type: text/plain; charset=UTF-8\r\n"
                f"\r\n"
                f"{value}\r\n"
            ).encode("utf-8")
        )

    if file_obj is None:
        # Fields-only mode — closing boundary with no file part
        text_bytes.append(f"--{boundary}--\r\n".encode("utf-8"))
        body = b"".join(text_bytes)
        return io.BytesIO(body), ct_header, len(body)

    # File mode — stream prologue + file + epilogue
    if filename is None:
        raise ValueError("filename is required when file_obj is provided")

    ct = content_type or _guess_content_type(filename)
    prologue = b"".join(text_bytes) + (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: {ct}\r\n"
        f"\r\n"
    ).encode("utf-8")
    # Epilogue: CRLF closes the file data part, then the final boundary.
    epilogue = b"\r\n" + f"--{boundary}--\r\n".encode("utf-8")

    # Determine file size without reading the body
    file_size = _io_remaining_bytes(file_obj)

    if file_size is None:
        # Size-indeterminate IO (pipes, sockets, generators) — buffer via
        # SpooledTemporaryFile so we can compute length and still stream.
        spooled: tempfile.SpooledTemporaryFile[bytes] = tempfile.SpooledTemporaryFile(
            max_size=1024 * 1024
        )
        buf = file_obj.read(65536)
        while buf:
            spooled.write(buf)
            buf = file_obj.read(65536)
        spooled.seek(0)
        file_size = _io_remaining_bytes(cast(IO[bytes], spooled))
        if file_size is None:
            spooled.seek(0, 2)
            file_size = spooled.tell()
            spooled.seek(0)
        file_obj = cast(IO[bytes], spooled)

    total_length = len(prologue) + file_size + len(epilogue)
    chained = _ChainedIO([io.BytesIO(prologue), file_obj, io.BytesIO(epilogue)])
    return cast(IO[bytes], chained), ct_header, total_length
