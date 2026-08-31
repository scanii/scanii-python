"""Unit tests for ScaniiClient — no network required."""

from __future__ import annotations

import io
import json
from http.client import HTTPMessage
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scanii import ScaniiClient, ScaniiTarget
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
TARGET = ScaniiTarget(ENDPOINT)


def _make_client(**kwargs) -> ScaniiClient:
    return ScaniiClient(key=KEY, secret=SECRET, target=TARGET, **kwargs)


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
# ScaniiTarget
# ---------------------------------------------------------------------------

class TestScaniiTarget:
    def test_regional_constants_exist(self):
        for name in ("US1", "EU1", "EU2", "AP1", "AP2", "CA1"):
            assert isinstance(getattr(ScaniiTarget, name), ScaniiTarget)

    def test_regional_constant_urls(self):
        assert ScaniiTarget.US1.endpoint == "https://api-us1.scanii.com"
        assert ScaniiTarget.EU1.endpoint == "https://api-eu1.scanii.com"
        assert ScaniiTarget.EU2.endpoint == "https://api-eu2.scanii.com"
        assert ScaniiTarget.AP1.endpoint == "https://api-ap1.scanii.com"
        assert ScaniiTarget.AP2.endpoint == "https://api-ap2.scanii.com"
        assert ScaniiTarget.CA1.endpoint == "https://api-ca1.scanii.com"

    def test_resolve_absolute_path(self):
        t = ScaniiTarget("http://localhost:4000")
        assert t.resolve("/v2.2/files") == "http://localhost:4000/v2.2/files"

    def test_resolve_regional_constant(self):
        assert ScaniiTarget.US1.resolve("/v2.2/ping") == "https://api-us1.scanii.com/v2.2/ping"

    def test_empty_url_raises(self):
        with pytest.raises(ValueError, match="non-empty"):
            ScaniiTarget("")

    def test_equality_same_url(self):
        a = ScaniiTarget("http://localhost:4000")
        b = ScaniiTarget("http://localhost:4000")
        assert a == b

    def test_inequality_different_url(self):
        assert ScaniiTarget("http://localhost:4000") != ScaniiTarget("http://localhost:5000")

    def test_hash_equal_for_same_url(self):
        a = ScaniiTarget("http://localhost:4000")
        b = ScaniiTarget("http://localhost:4000")
        assert hash(a) == hash(b)
        assert {a, b} == {a}  # set deduplicates

    def test_repr(self):
        assert repr(ScaniiTarget("http://localhost:4000")) == "ScaniiTarget('http://localhost:4000')"

    def test_constants_match_openapi_spec(self):
        """Drift detection: constants must match openapi/src/v22.yaml servers block."""
        import re

        spec_path = Path(__file__).parent.parent.parent / "openapi" / "src" / "v22.yaml"
        if not spec_path.exists():
            pytest.skip("openapi/src/v22.yaml not present — run from workspace root to enable")
        text = spec_path.read_text(encoding="utf-8")
        urls = set(re.findall(r"- url: (https://api-\S+\.scanii\.com)", text))
        constants = {
            ScaniiTarget.US1.endpoint,
            ScaniiTarget.EU1.endpoint,
            ScaniiTarget.EU2.endpoint,
            ScaniiTarget.AP1.endpoint,
            ScaniiTarget.AP2.endpoint,
            ScaniiTarget.CA1.endpoint,
        }
        assert urls == constants, (
            f"ScaniiTarget constants drift from openapi spec.\n"
            f"  Spec:      {sorted(urls)}\n"
            f"  Constants: {sorted(constants)}"
        )


# ---------------------------------------------------------------------------
# Constructor validation
# ---------------------------------------------------------------------------

class TestConstructor:
    def test_key_and_secret_accepted(self):
        from scanii._version import __version__

        c = _make_client()
        assert c._user_agent == f"scanii-python/{__version__}"

    def test_token_accepted(self):
        c = ScaniiClient(token="mytoken", target=TARGET)
        assert "Basic" in c._auth_header

    def test_both_key_and_token_raises(self):
        with pytest.raises(ValueError, match="not both"):
            ScaniiClient(key="k", secret="s", token="t", target=TARGET)

    def test_missing_key_raises(self):
        with pytest.raises(ValueError):
            ScaniiClient(target=TARGET)

    def test_missing_secret_raises(self):
        with pytest.raises(ValueError):
            ScaniiClient(key="k", target=TARGET)

    def test_key_with_colon_raises(self):
        with pytest.raises(ValueError, match="colon"):
            ScaniiClient(key="bad:key", secret="s", target=TARGET)

    def test_missing_target_raises_with_helpful_message(self):
        with pytest.raises(TypeError, match="ScaniiTarget"):
            ScaniiClient(key="x", secret="y")  # type: ignore[call-arg]

    def test_wrong_target_type_raises_with_helpful_message(self):
        with pytest.raises(TypeError, match="ScaniiTarget"):
            ScaniiClient(key="x", secret="y", target="http://localhost:4000")  # type: ignore[arg-type]

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
        req = m.call_args[0][0]
        # The prologue is a BytesIO and contains the filename even after the file closes.
        # Reading _parts[0] doesn't touch the actual file.
        assert b"test.bin" in req.data._parts[0].read()


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
        assert b"location" in call_args.data.read()

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
# delete / delete_trace
# ---------------------------------------------------------------------------

class TestDelete:
    def test_delete_sends_delete_to_files_path(self):
        mock_resp = _mock_response(204, "")
        with patch("urllib.request.urlopen", return_value=mock_resp) as m:
            assert _make_client().delete("abc") is True
        req = m.call_args[0][0]
        assert req.get_method() == "DELETE"
        assert req.full_url == f"{ENDPOINT}/v2.2/files/abc"

    def test_delete_trace_sends_delete_to_trace_path(self):
        mock_resp = _mock_response(204, "")
        with patch("urllib.request.urlopen", return_value=mock_resp) as m:
            assert _make_client().delete_trace("abc") is True
        req = m.call_args[0][0]
        assert req.get_method() == "DELETE"
        assert req.full_url == f"{ENDPOINT}/v2.2/files/abc/trace"

    def test_delete_url_encodes_the_id(self):
        mock_resp = _mock_response(204, "")
        with patch("urllib.request.urlopen", return_value=mock_resp) as m:
            _make_client().delete("a b/c")
        req = m.call_args[0][0]
        assert req.full_url == f"{ENDPOINT}/v2.2/files/a%20b%2Fc"

    def test_delete_404_raises(self):
        mock_resp = _mock_response(404, json.dumps({"error": "not found"}))
        with patch("urllib.request.urlopen", return_value=mock_resp):
            with pytest.raises(ScaniiError):
                _make_client().delete("missing")

    def test_delete_trace_404_raises(self):
        mock_resp = _mock_response(404, json.dumps({"error": "no trace"}))
        with patch("urllib.request.urlopen", return_value=mock_resp):
            with pytest.raises(ScaniiError):
                _make_client().delete_trace("missing")

    def test_delete_403_raises_auth_error(self):
        # Per the spec, a temporary auth token is not privileged to delete.
        mock_resp = _mock_response(403, json.dumps({"error": "forbidden"}))
        with patch("urllib.request.urlopen", return_value=mock_resp):
            with pytest.raises(ScaniiAuthError):
                _make_client().delete("abc")

    def test_delete_trace_403_raises_auth_error(self):
        mock_resp = _mock_response(403, json.dumps({"error": "forbidden"}))
        with patch("urllib.request.urlopen", return_value=mock_resp):
            with pytest.raises(ScaniiAuthError):
                _make_client().delete_trace("abc")

    def test_delete_empty_id_raises(self):
        with pytest.raises(ValueError):
            _make_client().delete("")

    def test_delete_trace_empty_id_raises(self):
        with pytest.raises(ValueError):
            _make_client().delete_trace("")


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


# ---------------------------------------------------------------------------
# Streaming encoder — true streaming verification
# ---------------------------------------------------------------------------

class TestStreamingEncoder:
    def test_encoder_does_not_read_file_body_at_construction_time(self, tmp_path):
        """The encoder must not read the caller's IO at construction time."""
        from scanii._multipart import encode

        p = tmp_path / "payload.bin"
        p.write_bytes(b"x" * 4096)
        with open(p, "rb") as f:
            stream, ct, length = encode({"key": "val"}, file_obj=f, filename="payload.bin")
            # The file body must NOT have been read yet
            assert f.tell() == 0, (
                "encoder read the file at construction time; "
                "file IO must be deferred until urllib reads from the chained stream"
            )
            # Reading now (file still open) must produce the correct total length
            body = stream.read()
        assert len(body) == length

    def test_encoder_file_content_present_in_stream(self, tmp_path):
        from scanii._multipart import encode

        content = b"sentinel-content-abc123"
        p = tmp_path / "data.bin"
        p.write_bytes(content)
        with open(p, "rb") as f:
            stream, _ct, _length = encode({}, file_obj=f, filename="data.bin")
            body = stream.read()  # must read while file is still open
        assert content in body

    def test_encoder_spooled_fallback_for_unseekable_io(self):
        """IOs without fileno/seek/getvalue buffer via SpooledTemporaryFile."""
        from scanii._multipart import encode

        class _UnseekableIO:
            def __init__(self, data: bytes) -> None:
                self._data = data
                self._pos = 0

            def read(self, n: int = -1) -> bytes:
                if n < 0:
                    result = self._data[self._pos:]
                    self._pos = len(self._data)
                    return result
                result = self._data[self._pos:self._pos + n]
                self._pos += len(result)
                return result

        content = b"fallback-test-payload"
        fake_io = _UnseekableIO(content)
        stream, ct, length = encode({}, file_obj=fake_io, filename="test.bin")
        body = stream.read()
        assert content in body
        assert len(body) == length, "reported length must match actual body size"

    def test_content_length_header_set_for_stream_body(self):
        """Content-Length is included in the request when body is a stream."""
        body_resp = _processing_body()
        mock_resp = _mock_response(201, body_resp)
        with patch("urllib.request.urlopen", return_value=mock_resp) as m:
            _make_client().process(io.BytesIO(b"data"), filename="test.bin")
        req = m.call_args[0][0]
        assert req.get_header("Content-length") is not None
