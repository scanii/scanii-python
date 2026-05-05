"""Unit tests for ScaniiClient — no network required."""

from __future__ import annotations

import io
import json
from http.client import HTTPMessage
from unittest.mock import MagicMock, patch

import pytest

from scanii import ScaniiClient  # noqa: E402
from scanii.errors import ScaniiAuthError, ScaniiError, ScaniiRateLimitError
from scanii.models import (
    ScaniiAuthToken,
    ScaniiPendingResult,
    ScaniiProcessingResult,
    ScaniiTraceResult,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ENDPOINT = "http://localhost:4000"
KEY = "key"
SECRET = "secret"


def _make_client(**kwargs) -> ScaniiClient:
    return ScaniiClient(key=KEY, secret=SECRET, endpoint=ENDPOINT, **kwargs)


def _mock_response(status: int, body: str, headers: dict | None = None) -> MagicMock:
    """Return a mock that mimics urllib.request.urlopen()'s response object."""
    msg = HTTPMessage()
    for k, v in (headers or {}).items():
        msg[k] = v

    resp = MagicMock()
    resp.status = status
    resp.headers = msg
    resp.read.return_value = body.encode("utf-8")
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


def _processing_body(id: str = "test-id", findings: list | None = None) -> str:
    return json.dumps({
        "id": id,
        "findings": findings or [],
        "checksum": "abc123",
        "content_length": 42,
        "content_type": "text/plain",
        "metadata": {},
        "creation_date": "2026-01-01T00:00:00Z",
    })


def _pending_body(id: str = "pending-id") -> str:
    return json.dumps({"id": id})


# ---------------------------------------------------------------------------
# Constructor validation
# ---------------------------------------------------------------------------

class TestConstructor:
    def test_key_and_secret_accepted(self):
        c = _make_client()
        assert c._user_agent == "scanii-python/1.0.0"

    def test_token_accepted(self):
        c = ScaniiClient(token="mytoken", endpoint=ENDPOINT)
        assert "Basic" in c._auth_header

    def test_both_key_and_token_raises(self):
        with pytest.raises(ValueError, match="not both"):
            ScaniiClient(key="k", secret="s", token="t", endpoint=ENDPOINT)

    def test_missing_key_raises(self):
        with pytest.raises(ValueError):
            ScaniiClient(endpoint=ENDPOINT)

    def test_missing_secret_raises(self):
        with pytest.raises(ValueError):
            ScaniiClient(key="k", endpoint=ENDPOINT)

    def test_key_with_colon_raises(self):
        with pytest.raises(ValueError, match="colon"):
            ScaniiClient(key="bad:key", secret="s", endpoint=ENDPOINT)

    def test_empty_endpoint_raises(self):
        with pytest.raises(ValueError):
            ScaniiClient(key=KEY, secret=SECRET, endpoint="")

    def test_non_http_endpoint_raises(self):
        with pytest.raises(ValueError, match="http"):
            ScaniiClient(key=KEY, secret=SECRET, endpoint="ftp://example.com")

    def test_trailing_slash_stripped(self):
        c = ScaniiClient(key=KEY, secret=SECRET, endpoint="http://localhost:4000///")
        assert c._endpoint == "http://localhost:4000"

    def test_user_agent_reads_from_version_module(self):
        from scanii._version import __version__
        c = _make_client()
        assert c._user_agent == f"scanii-python/{__version__}"


# ---------------------------------------------------------------------------
# process
# ---------------------------------------------------------------------------

class TestProcess:
    def test_process_sends_multipart(self):
        body = _processing_body(findings=["content.malicious.local-test-file"])
        mock_resp = _mock_response(201, body, {"x-scanii-request-id": "req-1"})
        with patch("urllib.request.urlopen", return_value=mock_resp) as m:
            c = _make_client()
            result = c.process(io.BytesIO(b"data"), filename="test.bin")

        assert isinstance(result, ScaniiProcessingResult)
        assert result.findings == ("content.malicious.local-test-file",)
        call_args = m.call_args[0][0]
        assert b"multipart/form-data" in call_args.get_header("Content-type").encode()

    def test_process_returns_findings(self):
        body = _processing_body(findings=["f1", "f2"])
        mock_resp = _mock_response(201, body)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            c = _make_client()
            result = c.process(io.BytesIO(b"x"), filename="x.bin")
        assert result.findings == ("f1", "f2")

    def test_process_raises_auth_error_on_401(self):
        import urllib.error
        from http.client import HTTPMessage

        err = urllib.error.HTTPError(
            url="http://localhost", code=401, msg="Unauthorized",
            hdrs=HTTPMessage(), fp=io.BytesIO(b'{"error":"bad credentials"}')
        )
        with patch("urllib.request.urlopen", side_effect=err):
            with pytest.raises(ScaniiAuthError):
                _make_client().process(io.BytesIO(b"x"), filename="x.bin")

    def test_process_raises_rate_limit_error_on_429(self):
        import urllib.error
        from http.client import HTTPMessage

        msg = HTTPMessage()
        msg["retry-after"] = "30"
        err = urllib.error.HTTPError(
            url="http://localhost", code=429, msg="Too Many Requests",
            hdrs=msg, fp=io.BytesIO(b'{"error":"slow down"}')
        )
        with patch("urllib.request.urlopen", side_effect=err):
            with pytest.raises(ScaniiRateLimitError) as exc_info:
                _make_client().process(io.BytesIO(b"x"), filename="x.bin")
        assert exc_info.value.retry_after == 30

    def test_process_raises_scanii_error_on_500(self):
        import urllib.error
        from http.client import HTTPMessage

        err = urllib.error.HTTPError(
            url="http://localhost", code=500, msg="Server Error",
            hdrs=HTTPMessage(), fp=io.BytesIO(b'{"error":"oops"}')
        )
        with patch("urllib.request.urlopen", side_effect=err):
            with pytest.raises(ScaniiError):
                _make_client().process(io.BytesIO(b"x"), filename="x.bin")

    def test_process_network_error_propagates(self):
        import urllib.error
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("refused")):
            with pytest.raises(urllib.error.URLError):
                _make_client().process(io.BytesIO(b"x"), filename="x.bin")


# ---------------------------------------------------------------------------
# process_file delegates to process
# ---------------------------------------------------------------------------

class TestProcessFile:
    def test_process_file_opens_file(self, tmp_path):
        p = tmp_path / "test.bin"
        p.write_bytes(b"hello")
        body = _processing_body()
        mock_resp = _mock_response(201, body)
        with patch("urllib.request.urlopen", return_value=mock_resp) as m:
            c = _make_client()
            result = c.process_file(p)
        assert isinstance(result, ScaniiProcessingResult)
        call_args = m.call_args[0][0]
        # filename derived from basename
        assert b"test.bin" in call_args.data


# ---------------------------------------------------------------------------
# process_async / process_async_file
# ---------------------------------------------------------------------------

class TestProcessAsync:
    def test_process_async_returns_pending(self):
        body = _pending_body()
        mock_resp = _mock_response(202, body)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            c = _make_client()
            result = c.process_async(io.BytesIO(b"x"), filename="x.bin")
        assert isinstance(result, ScaniiPendingResult)
        assert result.id == "pending-id"

    def test_process_async_file_opens_file(self, tmp_path):
        p = tmp_path / "async.bin"
        p.write_bytes(b"data")
        body = _pending_body()
        mock_resp = _mock_response(202, body)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = _make_client().process_async_file(p)
        assert isinstance(result, ScaniiPendingResult)


# ---------------------------------------------------------------------------
# retrieve
# ---------------------------------------------------------------------------

class TestRetrieve:
    def test_retrieve_returns_result(self):
        body = _processing_body(id="abc")
        mock_resp = _mock_response(200, body)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = _make_client().retrieve("abc")
        assert result.id == "abc"

    def test_retrieve_empty_id_raises(self):
        with pytest.raises(ValueError):
            _make_client().retrieve("")


# ---------------------------------------------------------------------------
# retrieve_trace
# ---------------------------------------------------------------------------

class TestRetrieveTrace:
    def test_retrieve_trace_returns_result(self):
        body = json.dumps({
            "id": "trace-id",
            "events": [{"timestamp": "2026-01-01T00:00:00Z", "message": "started"}],
        })
        mock_resp = _mock_response(200, body)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = _make_client().retrieve_trace("trace-id")
        assert isinstance(result, ScaniiTraceResult)
        assert result.resource_id == "trace-id"
        assert len(result.events) == 1
        assert result.events[0].message == "started"

    def test_retrieve_trace_returns_none_on_404(self):
        import urllib.error
        from http.client import HTTPMessage

        err = urllib.error.HTTPError(
            url="http://localhost", code=404, msg="Not Found",
            hdrs=HTTPMessage(), fp=io.BytesIO(b"")
        )
        with patch("urllib.request.urlopen", side_effect=err):
            result = _make_client().retrieve_trace("unknown")
        assert result is None

    def test_retrieve_trace_empty_id_raises(self):
        with pytest.raises(ValueError):
            _make_client().retrieve_trace("")


# ---------------------------------------------------------------------------
# process_from_url
# ---------------------------------------------------------------------------

class TestProcessFromUrl:
    def test_process_from_url_sends_multipart(self):
        body = _processing_body()
        mock_resp = _mock_response(201, body)
        with patch("urllib.request.urlopen", return_value=mock_resp) as m:
            c = _make_client()
            result = c.process_from_url("https://example.com/file.pdf")
        assert isinstance(result, ScaniiProcessingResult)
        call_args = m.call_args[0][0]
        assert b"multipart/form-data" in call_args.get_header("Content-type").encode()
        assert b"location" in call_args.data

    def test_process_from_url_empty_location_raises(self):
        with pytest.raises(ValueError, match="location"):
            _make_client().process_from_url("")


# ---------------------------------------------------------------------------
# fetch
# ---------------------------------------------------------------------------

class TestFetch:
    def test_fetch_returns_pending(self):
        body = _pending_body()
        mock_resp = _mock_response(202, body)
        with patch("urllib.request.urlopen", return_value=mock_resp) as m:
            result = _make_client().fetch("https://example.com/file.pdf")
        assert isinstance(result, ScaniiPendingResult)
        call_args = m.call_args[0][0]
        assert b"application/x-www-form-urlencoded" in call_args.get_header("Content-type").encode()

    def test_fetch_empty_url_raises(self):
        with pytest.raises(ValueError):
            _make_client().fetch("")


# ---------------------------------------------------------------------------
# ping
# ---------------------------------------------------------------------------

class TestPing:
    def test_ping_returns_true(self):
        mock_resp = _mock_response(200, "")
        with patch("urllib.request.urlopen", return_value=mock_resp):
            assert _make_client().ping() is True

    def test_ping_raises_auth_error_on_401(self):
        import urllib.error
        from http.client import HTTPMessage

        err = urllib.error.HTTPError(
            url="http://localhost", code=401, msg="Unauthorized",
            hdrs=HTTPMessage(), fp=io.BytesIO(b'{"error":"bad credentials"}')
        )
        with patch("urllib.request.urlopen", side_effect=err):
            with pytest.raises(ScaniiAuthError):
                _make_client().ping()


# ---------------------------------------------------------------------------
# Auth token
# ---------------------------------------------------------------------------

class TestAuthTokens:
    def _token_body(self) -> str:
        return json.dumps({
            "id": "token-abc",
            "creation_date": "2026-01-01T00:00:00Z",
            "expiration_date": "2026-01-01T01:00:00Z",
        })

    def test_create_auth_token(self):
        mock_resp = _mock_response(201, self._token_body())
        with patch("urllib.request.urlopen", return_value=mock_resp):
            token = _make_client().create_auth_token(300)
        assert isinstance(token, ScaniiAuthToken)
        assert token.id == "token-abc"

    def test_create_auth_token_zero_raises(self):
        with pytest.raises(ValueError, match="positive"):
            _make_client().create_auth_token(0)

    def test_retrieve_auth_token(self):
        mock_resp = _mock_response(200, self._token_body())
        with patch("urllib.request.urlopen", return_value=mock_resp):
            token = _make_client().retrieve_auth_token("token-abc")
        assert token.id == "token-abc"

    def test_delete_auth_token(self):
        mock_resp = _mock_response(204, "")
        with patch("urllib.request.urlopen", return_value=mock_resp):
            assert _make_client().delete_auth_token("token-abc") is True

    def test_delete_auth_token_empty_id_raises(self):
        with pytest.raises(ValueError):
            _make_client().delete_auth_token("")


# ---------------------------------------------------------------------------
# Deprecation warning on ScaniiProcessingResult.error
# ---------------------------------------------------------------------------

class TestDeprecationWarning:
    def test_error_field_emits_deprecation_warning(self):
        with pytest.warns(DeprecationWarning, match="deprecated"):
            ScaniiProcessingResult(
                id="x",
                findings=(),
                checksum=None,
                content_length=None,
                content_type=None,
                metadata={},
                creation_date=None,
                request_id=None,
                host_id=None,
                resource_location=None,
                error="something went wrong",
            )

    def test_no_warning_when_error_is_none(self):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("error", DeprecationWarning)
            # Should not raise
            ScaniiProcessingResult(
                id="x",
                findings=(),
                checksum=None,
                content_length=None,
                content_type=None,
                metadata={},
                creation_date=None,
                request_id=None,
                host_id=None,
                resource_location=None,
                error=None,
            )


# ---------------------------------------------------------------------------
# User-Agent header
# ---------------------------------------------------------------------------

class TestUserAgent:
    def test_user_agent_sent(self):
        body = _processing_body()
        mock_resp = _mock_response(201, body)
        with patch("urllib.request.urlopen", return_value=mock_resp) as m:
            _make_client().process(io.BytesIO(b"x"), filename="x.bin")
        req = m.call_args[0][0]
        assert req.get_header("User-agent").startswith("scanii-python/")

    def test_user_agent_includes_version(self):
        from scanii._version import __version__
        c = _make_client()
        assert c._user_agent == f"scanii-python/{__version__}"
