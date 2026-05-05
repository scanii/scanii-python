# scanii-python

Python SDK for the [Scanii](https://scanii.com) content security API.

## Installation

```bash
pip install scanii
```

> _Until the PyPI name is registered, install from source: `pip install git+https://github.com/scanii/scanii-python.git@main`._

## SDK Principles

1. **Light.** Zero runtime dependencies, stdlib only.
2. **Up to date.** Always current with the latest Scanii API.
3. **Integration-only.** Wraps the REST API — retries, concurrency, and batching are the caller's responsibility.

## Quickstart

```python
from scanii import ScaniiClient

client = ScaniiClient(key="your-key", secret="your-secret")
result = client.process_file("./document.pdf")
print(result.findings)  # [] when clean
```

## Streaming

Pass any IO-like object (anything with `read(n) -> bytes`) to `process()` directly — no temp file needed:

```python
import io

# Scan bytes already in memory
result = client.process(io.BytesIO(my_bytes), filename="upload.bin")

# Scan content from an open file handle
with open("./large.pdf", "rb") as f:
    result = client.process(f, filename="large.pdf")
```

## API Reference

### Constructor

```python
ScaniiClient(
    key: str | None = None,
    secret: str | None = None,
    token: str | None = None,
    endpoint: str = "https://api.scanii.com",
    timeout: float = 60.0,
)
```

Supply either `key` + `secret` (HTTP Basic Auth) or `token` (auth-token authentication). Mixing both raises `ValueError`.

### File scanning

| Method | Description |
|---|---|
| `process(content, filename, content_type=None, metadata=None, callback=None)` | Synchronous scan of an IO-like object |
| `process_file(path, metadata=None, callback=None)` | Synchronous scan of a file on disk |
| `process_async(content, filename, content_type=None, metadata=None, callback=None)` | Async-on-server scan of an IO-like object; returns `ScaniiPendingResult` |
| `process_async_file(path, metadata=None, callback=None)` | Async-on-server scan of a file on disk; returns `ScaniiPendingResult` |
| `retrieve(id)` | Retrieve a previous scan result |
| `fetch(url, metadata=None, callback=None)` | Server-side async fetch-and-scan of a remote URL |

### v2.2 preview methods

| Method | Description |
|---|---|
| `retrieve_trace(id)` **(v2.2 preview)** | Retrieve processing event trace; returns `None` on 404 |
| `process_from_url(location, callback=None, metadata=None)` **(v2.2 preview)** | Synchronous scan of a remote URL via `POST /files` |

### Auth tokens

| Method | Description |
|---|---|
| `create_auth_token(timeout_seconds)` | Mint a short-lived token |
| `retrieve_auth_token(id)` | Inspect a token |
| `delete_auth_token(id)` | Revoke a token |

### Health check

| Method | Description |
|---|---|
| `ping()` | Returns `True` when the API is reachable with valid credentials |

## Regional Endpoints

| Region | Endpoint |
|---|---|
| United States (default) | `https://api.scanii.com` |
| European Union | `https://api-eu.scanii.com` |

```python
client = ScaniiClient(key="your-key", secret="your-secret", endpoint="https://api-eu.scanii.com")
```

## Error Handling

```python
from scanii import ScaniiClient, ScaniiError, ScaniiAuthError, ScaniiRateLimitError
import time

client = ScaniiClient(key="your-key", secret="your-secret")

try:
    result = client.process_file("./document.pdf")
except ScaniiAuthError:
    print("Invalid credentials")
except ScaniiRateLimitError as e:
    if e.retry_after:
        time.sleep(e.retry_after)
except ScaniiError as e:
    print(f"API error {e.status_code}: {e}")
```

Network-level failures (`urllib.error.URLError`) propagate unwrapped — retries are the caller's responsibility per SDK Principle 3.

## Local Testing with scanii-cli

All integration tests run against a locally-hosted scanii-cli mock server — no real credentials needed.

```bash
docker run -d --name scanii-cli -p 4000:4000 ghcr.io/scanii/scanii-cli:latest server

# Run tests
pip install -e ".[dev]"
pytest
```

```python
client = ScaniiClient(key="key", secret="secret", endpoint="http://localhost:4000")
result = client.ping()  # True
```

## Contributing

Pull requests welcome. Please open an issue first for substantial changes.

## License

Apache 2.0 — see [LICENSE](LICENSE).
