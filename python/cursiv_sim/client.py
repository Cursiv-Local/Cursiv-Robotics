"""Minimal HTTP client for the bridge (standard library only).

Proxies are disabled explicitly: the bridge is on loopback, and an environment proxy
must never see robot data.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request


class LinkDown(ConnectionError):
    """The simulated radio link is down, or the bridge cannot be reached."""


class BridgeClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8750", token: str | None = None, timeout: float = 30):
        self.base = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _call(self, method: str, path: str, body: bytes | None = None, ctype: str = "application/json"):
        req = urllib.request.Request(self.base + path, data=body, method=method)
        if body is not None:
            req.add_header("Content-Type", ctype)
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
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
        for attempt in range(max_retries):
            status, data, headers = self.post("/v1/observations", body)
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
