# scanii-python

Python SDK for the [Scanii](https://scanii.com) content security API.

## Installation

```bash
pip install scanii-python
```

Distribution name is `scanii-python`; import as `from scanii import ScaniiClient`.

## SDK Principles

1. **Light.** Zero runtime dependencies, stdlib only.
2. **Up to date.** Always current with the latest Scanii API.
3. **Integration-only.** Wraps the REST API — retries, concurrency, and batching are the caller's responsibility.

## Quickstart

```python
from scanii import ScaniiClient, ScaniiTarget

client = ScaniiClient(key="your-key", secret="your-secret", target=ScaniiTarget.US1)
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
    *,
    key: str | None = None,
    secret: str | None = None,
    token: str | None = None,
    target: ScaniiTarget,
    timeout: float = 60.0,
)
```

Supply either `key` + `secret` (HTTP Basic Auth) or `token` (auth-token authentication). Mixing both raises `ValueError`. `target` is required — see [Regional Endpoints](#regional-endpoints).

### File scanning

| Method | Description |
|---|---|
| `process(content, filename, content_type=None, metadata=None, callback=None)` | Synchronous scan of an IO-like object |
| `process_file(path, metadata=None, callback=None)` | Synchronous scan of a file on disk |
| `process_async(content, filename, content_type=None, metadata=None, callback=None)` | Async-on-server scan of an IO-like object; returns `ScaniiPendingResult` |
| `process_async_file(path, metadata=None, callback=None)` | Async-on-server scan of a file on disk; returns `ScaniiPendingResult` |
| `retrieve(id)` | Retrieve a previous scan result |
| `delete(id)` | Delete a scan result. Returns `True`; the processing trace is left intact |
| `delete_trace(id)` | Delete a processing trace. Returns `True`; the scan result is left intact |
| `fetch(url, metadata=None, callback=None)` | Server-side async fetch-and-scan of a remote URL |

`delete()` and `delete_trace()` act on independent resources: deleting a scan result
leaves its trace readable, and deleting a trace leaves the result readable. To erase a
scan entirely, call both.

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

Choose a regional target explicitly. Six regional constants are available: `US1`, `EU1`, `EU2`, `AP1`, `AP2`, `CA1`. Latency-based routing (`AUTO` in other Scanii SDKs) is intentionally not provided — chain-of-custody and data-residency compliance require an explicit regional choice. For local testing against scanii-cli, construct a target with an arbitrary URL: `ScaniiTarget("http://localhost:4000")`.

| Constant | URL | Location |
|---|---|---|
| `ScaniiTarget.US1` | `https://api-us1.scanii.com` | Virginia, USA |
| `ScaniiTarget.EU1` | `https://api-eu1.scanii.com` | Dublin, Ireland |
| `ScaniiTarget.EU2` | `https://api-eu2.scanii.com` | London, United Kingdom |
| `ScaniiTarget.AP1` | `https://api-ap1.scanii.com` | Sydney, Australia |
| `ScaniiTarget.AP2` | `https://api-ap2.scanii.com` | Singapore |
| `ScaniiTarget.CA1` | `https://api-ca1.scanii.com` | Montreal, Canada |

```python
client = ScaniiClient(key="your-key", secret="your-secret", target=ScaniiTarget.EU1)
```

## Error Handling

```python
from scanii import ScaniiClient, ScaniiTarget, ScaniiError, ScaniiAuthError, ScaniiRateLimitError
import time

client = ScaniiClient(key="your-key", secret="your-secret", target=ScaniiTarget.US1)

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
client = ScaniiClient(key="key", secret="secret", target=ScaniiTarget("http://localhost:4000"))
result = client.ping()  # True
```

## Contributing

Pull requests welcome. Please open an issue first for substantial changes.

## License

Apache 2.0 — see [LICENSE](LICENSE).
