# Changelog

## 1.0.0 — 2026-05-05

Initial release. Replaces the unmaintained `scanii.py` skeleton.

**Reference:** scanii-java v8.1.0 (includes v2.2 API surface).

### API surface

- `ScaniiClient(key, secret, endpoint, timeout)` — synchronous client, zero runtime dependencies, stdlib only
- `process(content, filename, content_type, metadata, callback)` — stream-first synchronous scan; `content` is any object with `read(n) -> bytes`
- `process_file(path, metadata, callback)` — path convenience; opens the file and delegates to `process`
- `process_async(content, filename, content_type, metadata, callback)` — stream-first async-on-server submission
- `process_async_file(path, metadata, callback)` — path convenience for async submission
- `retrieve_trace(id)` — **(v2.2 preview)** retrieve processing event trace; returns `None` on 404
- `process_from_url(location, callback, metadata)` — **(v2.2 preview)** synchronous URL submission via `POST /files`
- `fetch(url, metadata, callback)` — async server-side fetch-and-scan via `POST /files/fetch`
- `retrieve(id)` — retrieve a previous scan result
- `ping()` — health check
- `create_auth_token(timeout_seconds)` / `retrieve_auth_token(id)` / `delete_auth_token(id)` — auth token lifecycle

### Streaming design

The SDK uses a stream-first API per the workspace streaming standardization:
`process(content, filename)` accepts any IO-like object (`io.BytesIO`, open file handles, network streams). `process_file(path)` is a thin wrapper for the common disk-file case. There is exactly one HTTP-handling code path; the file convenience is syntactic sugar.

### Error handling

- `ScaniiError` — base exception; carries `status_code`, `request_id`, `host_id`, `body`
- `ScaniiAuthError(ScaniiError)` — HTTP 401/403
- `ScaniiRateLimitError(ScaniiError)` — HTTP 429; carries `retry_after` (seconds) when the server provides it
- Network-level failures (`urllib.error.URLError`) propagate unwrapped per SDK Principle 3

### Deprecations (from day one)

- `ScaniiProcessingResult.error` — ships deprecated from day one. The server never populates this field on successful responses; errors arrive as non-2xx HTTP responses that raise `ScaniiError` subclasses. Constructing the dataclass with a non-`None` `error` value emits a `DeprecationWarning`. Will be removed in a future major version.

### Notes

- Supersedes the `scanii==0.0.1` placeholder when PyPI name override clears
- PyPI name override pending (https://github.com/pypi/support/issues/10444); install from source until then: `pip install git+https://github.com/scanii/scanii-python.git@main`
