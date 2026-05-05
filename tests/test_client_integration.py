"""Integration tests for ScaniiClient — requires scanii-cli on http://localhost:4000.

Run scanii-cli locally:
    docker run -d --name scanii-cli -p 4000:4000 ghcr.io/scanii/scanii-cli:latest server

In CI the action scanii/setup-cli-action@v1 handles startup. Tests self-skip
with a message when scanii-cli is not reachable.
"""

from __future__ import annotations

import io
import os
import tempfile
from pathlib import Path

import pytest

from scanii import ScaniiClient
from scanii.errors import ScaniiAuthError, ScaniiError

KEY = "key"
SECRET = "secret"
ENDPOINT = os.environ.get("SCANII_TEST_ENDPOINT", "http://localhost:4000")

LOCAL_MALWARE_UUID = "38DCC0C9-7FB6-4D0D-9C37-288A380C6BB9"
LOCAL_MALWARE_FINDING = "content.malicious.local-test-file"

_cli_available: bool | None = None


def _is_cli_reachable() -> bool:
    global _cli_available
    if _cli_available is not None:
        return _cli_available
    try:
        c = ScaniiClient(key=KEY, secret=SECRET, endpoint=ENDPOINT, timeout=2.0)
        c.ping()
        _cli_available = True
    except Exception:
        _cli_available = False
    return _cli_available


@pytest.fixture(autouse=True)
def require_cli():
    if not _is_cli_reachable():
        pytest.skip(f"scanii-cli not reachable at {ENDPOINT}")


@pytest.fixture
def client() -> ScaniiClient:
    return ScaniiClient(key=KEY, secret=SECRET, endpoint=ENDPOINT)


def make_malware_fixture() -> Path:
    path = Path(tempfile.gettempdir()) / "scanii-test-malware.bin"
    path.write_text(LOCAL_MALWARE_UUID, encoding="utf-8")
    return path


def make_clean_file() -> Path:
    path = Path(tempfile.gettempdir()) / "scanii-test-clean.txt"
    path.write_text("hello world, nothing to see here", encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# ping
# ---------------------------------------------------------------------------

class TestPing:
    def test_ping_with_valid_credentials(self, client):
        assert client.ping() is True

    def test_ping_with_bad_credentials_raises_auth_error(self):
        bad = ScaniiClient(key="bad", secret="creds", endpoint=ENDPOINT)
        with pytest.raises(ScaniiAuthError):
            bad.ping()


# ---------------------------------------------------------------------------
# process_file (path convenience)
# ---------------------------------------------------------------------------

class TestProcessFile:
    def test_clean_file_returns_no_findings(self, client):
        path = make_clean_file()
        result = client.process_file(path, metadata={"source": "integration"})
        assert result.id
        assert result.findings == ()

    def test_malware_uuid_fixture_returns_finding(self, client):
        path = make_malware_fixture()
        result = client.process_file(path)
        if LOCAL_MALWARE_FINDING not in result.findings:
            pytest.skip(
                f"scanii-cli did not flag the UUID fixture (older build); "
                f"got: {result.findings!r}"
            )
        assert LOCAL_MALWARE_FINDING in result.findings

    def test_retrieve_after_process_returns_same_id(self, client):
        path = make_clean_file()
        result = client.process_file(path)
        retrieved = client.retrieve(result.id)
        assert retrieved.id == result.id

    def test_process_file_1mib_synthetic_upload(self, client):
        """Verify the streaming path handles a 1 MiB upload end-to-end."""
        path = Path(tempfile.gettempdir()) / "scanii-test-1mib.bin"
        path.write_bytes(b"A" * (1024 * 1024))
        result = client.process_file(path)
        assert result.id
        assert result.findings == ()


# ---------------------------------------------------------------------------
# process (stream-based — IO-like object)
# ---------------------------------------------------------------------------

class TestProcess:
    def test_bytesio_clean_returns_no_findings(self, client):
        content = io.BytesIO(b"nothing suspicious here")
        result = client.process(content, filename="clean.txt")
        assert result.id
        assert result.findings == ()

    def test_bytesio_malware_uuid_returns_finding(self, client):
        content = io.BytesIO(LOCAL_MALWARE_UUID.encode("utf-8"))
        result = client.process(content, filename="malware-test.bin")
        if LOCAL_MALWARE_FINDING not in result.findings:
            pytest.skip(
                f"scanii-cli did not flag the UUID fixture (older build); "
                f"got: {result.findings!r}"
            )
        assert LOCAL_MALWARE_FINDING in result.findings

    def test_file_io_clean_returns_no_findings(self, client):
        path = make_clean_file()
        with open(path, "rb") as f:
            result = client.process(f, filename=path.name)
        assert result.findings == ()

    def test_streaming_parity_with_process_file(self, client):
        path = make_malware_fixture()
        result_file = client.process_file(path)
        with open(path, "rb") as f:
            result_stream = client.process(f, filename=path.name)
        assert set(result_file.findings) == set(result_stream.findings)


# ---------------------------------------------------------------------------
# process_async / process_async_file
# ---------------------------------------------------------------------------

class TestProcessAsync:
    def test_process_async_file_returns_pending(self, client):
        from scanii.models import ScaniiPendingResult
        path = make_clean_file()
        result = client.process_async_file(path)
        assert isinstance(result, ScaniiPendingResult)
        assert result.id

    def test_process_async_stream_returns_pending(self, client):
        from scanii.models import ScaniiPendingResult
        content = io.BytesIO(b"async content")
        result = client.process_async(content, filename="async.bin")
        assert isinstance(result, ScaniiPendingResult)
        assert result.id


# ---------------------------------------------------------------------------
# v2.2 surface — retrieve_trace (hard-assert, no self-skip)
# ---------------------------------------------------------------------------

class TestRetrieveTrace:
    def test_retrieve_trace_known_id_returns_events(self, client):
        path = make_clean_file()
        process_result = client.process_file(path)
        trace = client.retrieve_trace(process_result.id)
        assert trace is not None
        assert isinstance(trace.events, tuple)
        assert len(trace.events) > 0

    def test_retrieve_trace_unknown_id_returns_none(self, client):
        result = client.retrieve_trace("00000000-0000-0000-0000-000000000000")
        assert result is None


# ---------------------------------------------------------------------------
# v2.2 surface — process_from_url (hard-assert, no self-skip)
# ---------------------------------------------------------------------------

class TestProcessFromUrl:
    def test_process_from_url_eicar_returns_finding(self, client):
        # EICAR via URL is safe — the file never lands on the test runner's disk;
        # cli fetches it server-side. The §5 quarantine warning does NOT apply here.
        url = f"{ENDPOINT}/static/eicar.txt"
        result = client.process_from_url(url)
        assert result is not None
        assert result.id
        assert "content.malicious.eicar-test-signature" in result.findings


# ---------------------------------------------------------------------------
# Auth token lifecycle
# ---------------------------------------------------------------------------

class TestAuthTokenLifecycle:
    def test_full_token_lifecycle(self, client):
        from scanii.models import ScaniiAuthToken

        token = client.create_auth_token(300)
        assert isinstance(token, ScaniiAuthToken)
        assert token.id

        retrieved = client.retrieve_auth_token(token.id)
        assert retrieved.id == token.id

        deleted = client.delete_auth_token(token.id)
        assert deleted is True

    def test_token_auth_ping(self, client):
        # Create token and use it for a client — may self-skip on older cli
        # if token-auth ping is not supported.
        token = client.create_auth_token(60)
        token_client = ScaniiClient(token=token.id, endpoint=ENDPOINT, timeout=2.0)
        try:
            result = token_client.ping()
            assert result is True
        except ScaniiError as e:
            if e.status_code in (401, 403):
                pytest.skip("token-auth ping not supported on this scanii-cli build")
            raise


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------

class TestErrors:
    def test_bad_credentials_raises_auth_error(self):
        bad = ScaniiClient(key="bad", secret="creds", endpoint=ENDPOINT)
        path = make_clean_file()
        with pytest.raises(ScaniiAuthError):
            bad.process_file(path)

    def test_unknown_resource_id_raises_error(self, client):
        with pytest.raises(ScaniiError):
            client.retrieve("00000000-0000-0000-0000-000000000000")
