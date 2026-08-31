"""Scanii SDK client."""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import IO

from scanii._multipart import encode as _multipart_encode
from scanii._version import __version__
from scanii.errors import ScaniiAuthError, ScaniiError, ScaniiRateLimitError
from scanii.models import (
    ScaniiAuthToken,
    ScaniiPendingResult,
    ScaniiProcessingResult,
    ScaniiTraceResult,
)
from scanii.target import ScaniiTarget

_API_VERSION = "/v2.2"


class ScaniiClient:
    """Synchronous client for the Scanii REST API v2.2.

    Construct with either ``key`` + ``secret`` (HTTP Basic Auth) or ``token``
    (auth-token authentication). Mixing the two raises ``ValueError``.

    ``target`` is required — choose a regional constant for production or
    construct a custom ``ScaniiTarget`` for local testing::

        client = ScaniiClient(key="your-key", secret="your-secret", target=ScaniiTarget.US1)

    Per SDK Principle 3 the client is integration-only: it does not retry,
    batch, or paginate. Each public method maps to exactly one HTTP request.

    See https://scanii.github.io/openapi/v22/
    """

    def __init__(
        self,
        *,
        key: str | None = None,
        secret: str | None = None,
        token: str | None = None,
        target: ScaniiTarget | None = None,
        timeout: float = 60.0,
    ) -> None:
        if not isinstance(target, ScaniiTarget):
            raise TypeError(
                "ScaniiClient requires a ScaniiTarget for data residency compliance. Examples:\n"
                "  ScaniiClient(key=..., secret=..., target=ScaniiTarget.US1)\n"
                "  ScaniiClient(key=..., secret=..., target=ScaniiTarget.EU1)\n"
                "For local testing against scanii-cli:\n"
                '  ScaniiClient(key=..., secret=..., target=ScaniiTarget("http://localhost:4000"))\n'
                "Available regional constants: US1, EU1, EU2, AP1, AP2, CA1."
            )
        self._auth_header = self._build_auth_header(key, secret, token)
        self._target = target
        self._timeout = float(timeout)
        self._user_agent = f"scanii-python/{__version__}"

    # ------------------------------------------------------------------
    # File scanning — stream-first
    # ------------------------------------------------------------------

    def process(
        self,
        content: IO[bytes],
        filename: str,
        content_type: str | None = None,
        metadata: dict[str, str] | None = None,
        callback: str | None = None,
    ) -> ScaniiProcessingResult:
        """Submit an IO-like object for synchronous scanning.

        ``content`` is duck-typed: anything with ``read(n) -> bytes``.
        Both ``open(path, 'rb')`` and ``io.BytesIO(...)`` work.

        :param content: IO-like object (anything with ``read(n) -> bytes``)
        :param filename: filename sent in the multipart part
        :param content_type: content-type of the file part; guessed from filename when None
        :param metadata: arbitrary key/value pairs attached to the result
        :param callback: URL to POST the result to on completion
        :see: https://scanii.github.io/openapi/v22/ POST /files
        :return: :class:`~scanii.ScaniiProcessingResult`
        """
        fields = self._build_fields(metadata, callback)
        body_stream, ct, content_length = _multipart_encode(
            fields, file_obj=content, filename=filename, content_type=content_type
        )
        status, resp_body, headers = self._post(
            "/files", body=body_stream, content_type=ct, content_length=content_length
        )
        self._raise_for_status(status, resp_body, headers, expected=201)
        return ScaniiProcessingResult.from_response(resp_body, headers)

    def process_file(
        self,
        path: str | os.PathLike[str],
        metadata: dict[str, str] | None = None,
        callback: str | None = None,
    ) -> ScaniiProcessingResult:
        """Submit a file path for synchronous scanning.

        Opens the file in binary mode, streams it to Scanii, and closes it.
        Delegates to :meth:`process` with ``filename`` set to the basename.

        :param path: path to the file to upload
        :param metadata: arbitrary key/value pairs attached to the result
        :param callback: URL to POST the result to on completion
        :see: https://scanii.github.io/openapi/v22/ POST /files
        :return: :class:`~scanii.ScaniiProcessingResult`
        """
        path = os.fspath(path)
        with open(path, "rb") as f:
            return self.process(f, filename=os.path.basename(path),
                                metadata=metadata, callback=callback)

    def process_async(
        self,
        content: IO[bytes],
        filename: str,
        content_type: str | None = None,
        metadata: dict[str, str] | None = None,
        callback: str | None = None,
    ) -> ScaniiPendingResult:
        """Submit an IO-like object for server-side asynchronous scanning.

        Returns a pending id; the final result is delivered to ``callback``
        (when supplied) or fetched via :meth:`retrieve`.

        :param content: IO-like object (anything with ``read(n) -> bytes``)
        :param filename: filename sent in the multipart part
        :param content_type: content-type of the file part; guessed from filename when None
        :param metadata: arbitrary key/value pairs attached to the result
        :param callback: URL to POST the result to on completion
        :see: https://scanii.github.io/openapi/v22/ POST /files/async
        :return: :class:`~scanii.ScaniiPendingResult`
        """
        fields = self._build_fields(metadata, callback)
        body_stream, ct, content_length = _multipart_encode(
            fields, file_obj=content, filename=filename, content_type=content_type
        )
        status, resp_body, headers = self._post(
            "/files/async", body=body_stream, content_type=ct, content_length=content_length
        )
        self._raise_for_status(status, resp_body, headers, expected=202)
        return ScaniiPendingResult.from_response(resp_body, headers)

    def process_async_file(
        self,
        path: str | os.PathLike[str],
        metadata: dict[str, str] | None = None,
        callback: str | None = None,
    ) -> ScaniiPendingResult:
        """Submit a file path for server-side asynchronous scanning.

        Opens the file in binary mode and delegates to :meth:`process_async`.

        :param path: path to the file to upload
        :param metadata: arbitrary key/value pairs attached to the result
        :param callback: URL to POST the result to on completion
        :see: https://scanii.github.io/openapi/v22/ POST /files/async
        :return: :class:`~scanii.ScaniiPendingResult`
        """
        path = os.fspath(path)
        with open(path, "rb") as f:
            return self.process_async(f, filename=os.path.basename(path),
                                      metadata=metadata, callback=callback)

    # ------------------------------------------------------------------
    # v2.2 surface
    # ------------------------------------------------------------------

    def retrieve_trace(self, id: str) -> ScaniiTraceResult | None:
        """Retrieve the processing event trace for a previously submitted scan.

        Returns ``None`` when no trace exists for the given id (HTTP 404).

        This is a v2.2 preview surface; the API shape may shift before it is
        marked stable.

        :param id: processing id returned by :meth:`process` or :meth:`process_file`
        :see: https://scanii.github.io/openapi/v22/ GET /files/{id}/trace
        :return: :class:`~scanii.ScaniiTraceResult` or ``None``
        """
        if not id:
            raise ValueError("id must not be empty")
        status, resp_body, headers = self._request("GET", f"/files/{_urlencode(id)}/trace")
        if status == 404:
            return None
        self._raise_for_status(status, resp_body, headers, expected=200)
        return ScaniiTraceResult.from_response(resp_body, headers)

    def process_from_url(
        self,
        location: str,
        callback: str | None = None,
        metadata: dict[str, str] | None = None,
    ) -> ScaniiProcessingResult:
        """Submit a remote URL for synchronous scanning.

        Sends the URL as a ``location`` field in a ``multipart/form-data`` POST
        to ``/files``. The Scanii server fetches and scans the URL synchronously
        and returns a :class:`~scanii.ScaniiProcessingResult`. This is distinct
        from :meth:`fetch`, which submits to ``/files/fetch`` for asynchronous
        server-side fetching.

        ``location`` must be a string URL — matches the existing :meth:`fetch`
        string-URL convention and the Java reference (``processFromUrl(String)``).

        This is a v2.2 preview surface; the API shape may shift before it is
        marked stable.

        :param location: URL of the content to scan
        :param callback: URL to POST the result to on completion
        :param metadata: arbitrary key/value pairs attached to the result
        :see: https://scanii.github.io/openapi/v22/ POST /files
        :return: :class:`~scanii.ScaniiProcessingResult`
        """
        if not location:
            raise ValueError("location must not be empty")
        fields = self._build_fields(metadata, callback)
        fields["location"] = location
        # Fields-only multipart — POST /v2.2/files rejects urlencoded on this endpoint.
        body_stream, ct, content_length = _multipart_encode(fields)
        status, resp_body, headers = self._post(
            "/files", body=body_stream, content_type=ct, content_length=content_length
        )
        self._raise_for_status(status, resp_body, headers, expected=201)
        return ScaniiProcessingResult.from_response(resp_body, headers)

    def delete(self, id: str) -> bool:
        """Delete a previously processed file result.

        The processing trace is a separate resource and is **not** removed by
        this call — it stays readable via :meth:`retrieve_trace` until you
        delete it with :meth:`delete_trace`. To erase a scan entirely, call
        both.

        :param id: processing id returned by :meth:`process` or :meth:`process_file`
        :see: https://scanii.github.io/openapi/v22/ DELETE /files/{id}
        :return: ``True`` on success (HTTP 204)
        :raises ScaniiError: when no result exists for the id (HTTP 404), which is
            also what a repeated delete of the same id returns
        """
        if not id:
            raise ValueError("id must not be empty")
        status, resp_body, headers = self._request("DELETE", f"/files/{_urlencode(id)}")
        self._raise_for_status(status, resp_body, headers, expected=204)
        return True

    def delete_trace(self, id: str) -> bool:
        """Delete the processing trace for a previously processed file.

        Leaves the processing result itself untouched.

        :param id: processing id returned by :meth:`process` or :meth:`process_file`
        :see: https://scanii.github.io/openapi/v22/ DELETE /files/{id}/trace
        :return: ``True`` on success (HTTP 204)
        :raises ScaniiError: when no trace exists for the id (HTTP 404), which is
            also what a repeated delete of the same id returns
        """
        if not id:
            raise ValueError("id must not be empty")
        status, resp_body, headers = self._request(
            "DELETE", f"/files/{_urlencode(id)}/trace"
        )
        self._raise_for_status(status, resp_body, headers, expected=204)
        return True

    # ------------------------------------------------------------------
    # Other API methods
    # ------------------------------------------------------------------

    def fetch(
        self,
        url: str,
        metadata: dict[str, str] | None = None,
        callback: str | None = None,
    ) -> ScaniiPendingResult:
        """Ask Scanii to download a remote URL and scan it asynchronously.

        :see: https://scanii.github.io/openapi/v22/ POST /files/fetch
        :return: :class:`~scanii.ScaniiPendingResult`
        """
        if not url:
            raise ValueError("url must not be empty")
        form: dict[str, str] = {"location": url}
        if callback:
            form["callback"] = callback
        for k, v in (metadata or {}).items():
            form[f"metadata[{k}]"] = str(v)
        body = urllib.parse.urlencode(form).encode("utf-8")
        status, resp_body, headers = self._post(
            "/files/fetch", body=body,
            content_type="application/x-www-form-urlencoded"
        )
        self._raise_for_status(status, resp_body, headers, expected=202)
        return ScaniiPendingResult.from_response(resp_body, headers)

    def retrieve(self, id: str) -> ScaniiProcessingResult:
        """Retrieve a previously submitted scan result by id.

        :see: https://scanii.github.io/openapi/v22/ GET /files/{id}
        :return: :class:`~scanii.ScaniiProcessingResult`
        """
        if not id:
            raise ValueError("id must not be empty")
        status, resp_body, headers = self._request("GET", f"/files/{_urlencode(id)}")
        self._raise_for_status(status, resp_body, headers, expected=200)
        return ScaniiProcessingResult.from_response(resp_body, headers)

    def ping(self) -> bool:
        """Verify that the configured credentials reach the API.

        :see: https://scanii.github.io/openapi/v22/ GET /ping
        :return: ``True`` when the API responds 200
        :raises ScaniiAuthError: when credentials are rejected
        """
        status, resp_body, headers = self._request("GET", "/ping")
        if status == 200:
            return True
        self._raise_for_status(status, resp_body, headers, expected=200)
        return False  # unreachable; keeps type checker happy

    def create_auth_token(self, timeout_seconds: int) -> ScaniiAuthToken:
        """Mint a short-lived auth token.

        ``timeout_seconds`` must be a positive integer.

        :see: https://scanii.github.io/openapi/v22/ POST /auth/tokens
        :return: :class:`~scanii.ScaniiAuthToken`
        """
        ts = int(timeout_seconds)
        if ts <= 0:
            raise ValueError("timeout_seconds must be positive")
        body = urllib.parse.urlencode({"timeout": ts}).encode("utf-8")
        status, resp_body, headers = self._post(
            "/auth/tokens", body=body,
            content_type="application/x-www-form-urlencoded"
        )
        if status not in (200, 201):
            self._raise_for_status(status, resp_body, headers, expected=201)
        return ScaniiAuthToken.from_response(resp_body, headers)

    def retrieve_auth_token(self, id: str) -> ScaniiAuthToken:
        """Inspect a previously created auth token.

        :see: https://scanii.github.io/openapi/v22/ GET /auth/tokens/{id}
        :return: :class:`~scanii.ScaniiAuthToken`
        """
        if not id:
            raise ValueError("id must not be empty")
        status, resp_body, headers = self._request("GET", f"/auth/tokens/{_urlencode(id)}")
        self._raise_for_status(status, resp_body, headers, expected=200)
        return ScaniiAuthToken.from_response(resp_body, headers)

    def delete_auth_token(self, id: str) -> bool:
        """Revoke an auth token.

        :see: https://scanii.github.io/openapi/v22/ DELETE /auth/tokens/{id}
        :return: ``True`` on success (HTTP 204)
        """
        if not id:
            raise ValueError("id must not be empty")
        status, resp_body, headers = self._request("DELETE", f"/auth/tokens/{_urlencode(id)}")
        self._raise_for_status(status, resp_body, headers, expected=204)
        return True

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_auth_header(
        self, key: str | None, secret: str | None, token: str | None
    ) -> str:
        if token:
            if key or secret:
                raise ValueError("supply either token or key+secret, not both")
            credentials = base64.b64encode(f"{token}:".encode("utf-8")).decode("ascii")
            return f"Basic {credentials}"
        if not key:
            raise ValueError("key must be set (or use token for auth-token mode)")
        if ":" in key:
            raise ValueError("key must not contain a colon")
        if not secret:
            raise ValueError("secret must be set when using key auth")
        credentials = base64.b64encode(f"{key}:{secret}".encode("utf-8")).decode("ascii")
        return f"Basic {credentials}"

    def _build_fields(
        self, metadata: dict[str, str] | None, callback: str | None
    ) -> dict[str, str]:
        fields: dict[str, str] = {}
        for k, v in (metadata or {}).items():
            fields[f"metadata[{k}]"] = str(v)
        if callback:
            fields["callback"] = callback
        return fields

    def _post(
        self,
        path: str,
        body: bytes | IO[bytes],
        content_type: str,
        content_length: int | None = None,
    ) -> tuple[int, str, dict[str, str]]:
        return self._request(
            "POST", path, body=body, content_type=content_type,
            content_length=content_length
        )

    def _request(
        self,
        method: str,
        path: str,
        body: bytes | IO[bytes] | None = None,
        content_type: str | None = None,
        content_length: int | None = None,
    ) -> tuple[int, str, dict[str, str]]:
        url = self._target.resolve(_API_VERSION + path)
        headers: dict[str, str] = {
            "Authorization": self._auth_header,
            "User-Agent": self._user_agent,
            "Accept": "application/json",
        }
        if content_type:
            headers["Content-Type"] = content_type
        # Set Content-Length explicitly for stream bodies (urllib can't compute it).
        # For bytes bodies urllib sets it automatically via len(); we leave that alone.
        if content_length is not None:
            headers["Content-Length"] = str(content_length)

        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                resp_body = resp.read().decode("utf-8", errors="replace")
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                return resp.status, resp_body, resp_headers
        except urllib.error.HTTPError as e:
            resp_body = e.read().decode("utf-8", errors="replace")
            resp_headers = {k.lower(): v for k, v in e.headers.items()}
            return e.code, resp_body, resp_headers
        except urllib.error.URLError:
            raise

    def _raise_for_status(
        self,
        status: int,
        body: str,
        headers: dict[str, str],
        *,
        expected: int,
    ) -> None:
        if status == expected:
            return
        request_id = headers.get("x-scanii-request-id")
        host_id = headers.get("x-scanii-host-id")
        message = self._extract_error_message(body) or f"HTTP {status}"

        if status in (401, 403):
            raise ScaniiAuthError(
                message, status_code=status, request_id=request_id,
                host_id=host_id, body=body
            )
        if status == 429:
            retry_after_raw = headers.get("retry-after")
            retry_after = int(retry_after_raw) if retry_after_raw else None
            raise ScaniiRateLimitError(
                message, status_code=status, request_id=request_id,
                host_id=host_id, body=body, retry_after=retry_after
            )
        raise ScaniiError(
            message, status_code=status, request_id=request_id,
            host_id=host_id, body=body
        )

    def _extract_error_message(self, body: str) -> str | None:
        if not body:
            return None
        try:
            decoded = json.loads(body)
            if isinstance(decoded, dict):
                error = decoded.get("error")
                if isinstance(error, str):
                    return error
            return body
        except (json.JSONDecodeError, ValueError):
            return body


def _urlencode(value: str) -> str:
    return urllib.parse.quote(value, safe="")
