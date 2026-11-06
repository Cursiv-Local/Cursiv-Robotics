"""Minimal HTTP client for the bridge (standard library only).

Proxies are never used: the bridge is on loopback (or behind the operator's own TLS terminator),
and an environment proxy must never see robot data.

Speed:
- record batches are gzip-compressed when the station is not on this computer (records compress
  about 9 times, which matters on slow field links; on loopback it would only cost CPU). Set
  compress=True/False to override. Stations that refuse gzip (415) get uncompressed batches.
- `submit_lines` sends signed records as the exact bytes they were stored in, with no re-encoding
"""
from __future__ import annotations

import gzip
import json
import time
import urllib.error
import urllib.parse
import urllib.request


class LinkDown(ConnectionError):
    """The simulated radio link is down, or the bridge cannot be reached."""


class BridgeClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8750", token: str | None = None, timeout: float = 30,
                 compress: bool | str = "auto"):
        self.base = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        host = urllib.parse.urlsplit(self.base).hostname or "127.0.0.1"
        self.compress = (host not in ("127.0.0.1", "localhost", "::1")) if compress == "auto" else bool(compress)

    def _call(self, method: str, path: str, body: bytes | None = None, ctype: str = "application/json", extra: dict | None = None):
        # One connection per request, deliberately: the bridge's HTTP server (tiny_http) writes
        # response headers and body separately without TCP_NODELAY, so a reused connection waits
        # about 40 ms per request for a delayed ACK (measured: 6,851 -> 1,760 records/s).
        req = urllib.request.Request(self.base + path, data=body, method=method)
        if body is not None:
            req.add_header("Content-Type", ctype)
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        for k, v in (extra or {}).items():
            req.add_header(k, v)
        try:
            with self._opener.open(req, timeout=self.timeout) as r:
                return r.status, json.loads(r.read() or b"{}"), dict(r.headers)
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                data = json.loads(raw or b"{}")
            except ValueError:
                data = {"error": "non_json", "detail": raw[:200].decode("utf-8", "replace")}
            return e.code, data, dict(e.headers)
        except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
            raise LinkDown(str(e)) from e

    def get(self, path: str):
        return self._call("GET", path)

    def post(self, path: str, obj) -> tuple[int, dict, dict]:
        return self._call("POST", path, json.dumps(obj).encode("utf-8"))

    def submit(self, envelopes: list[dict], max_retries: int = 50):
        """POST a batch; on 503 (queue full) wait for Retry-After and resend. Retries are idempotent."""
        body = {"records": envelopes} if len(envelopes) != 1 else envelopes[0]
        return self._submit_body(json.dumps(body).encode("utf-8"), max_retries)

    def submit_lines(self, lines: list[bytes], max_retries: int = 50):
        """Like submit(), for records already serialised as JSON lines (sent exactly as stored)."""
        return self._submit_body(b'{"records":[' + b",".join(l.rstrip(b"\r\n") for l in lines) + b"]}", max_retries)

    def _submit_body(self, body: bytes, max_retries: int):
        for attempt in range(max_retries):
            if self.compress and len(body) > 1024:
                status, data, headers = self._call("POST", "/v1/observations", gzip.compress(body, 6), extra={"Content-Encoding": "gzip"})
                if status == 415:          # an older station without gzip support: stop compressing
                    self.compress = False
                    continue
            else:
                status, data, headers = self._call("POST", "/v1/observations", body)
            if status != 503:
                return status, data, attempt
            time.sleep(min(float(headers.get("Retry-After", 1)), 2.0) * (0.25 + 0.1 * attempt))
        raise LinkDown("bridge stayed busy")

    def put_attachment(self, data: bytes, sha: str, declared_len: int | None = None):
        req_len = len(data) if declared_len is None else declared_len
        req = urllib.request.Request(f"{self.base}/v1/attachments/{sha}", data=data, method="PUT")
        req.add_header("Content-Type", "application/octet-stream")
        req.add_header("Content-Length", str(req_len))
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with self._opener.open(req, timeout=self.timeout) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")
        except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
            raise LinkDown(str(e)) from e
