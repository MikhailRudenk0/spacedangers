#!/usr/bin/env python3
"""Prove the verifier actually verifies.

A checker that only ever says PASS is worthless, so this spins up a local HTTP
server with canned responses and asserts that tools/verify.py reaches the right
verdict on each one — including the cases that matter most: a 200 response that
is empty, a 200 that is missing a field, and a truncated body. No network, no
external dependency, runs anywhere.

Usage:  python3 tools/selftest.py
Exit code 0 means the harness can be trusted.
"""

from __future__ import annotations

import gzip
import importlib.util
import json
import pathlib
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("verify", HERE / "verify.py")
verify = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(verify)

GOOD = {"signature": {"source": "test"}, "count": "3", "data": [[1], [2], [3]]}
EMPTY = {"signature": {"source": "test"}, "count": "0", "data": []}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep the test output clean
        pass

    def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 - stdlib naming
        path = self.path.split("?")[0]
        if path == "/good.json":
            self._send(200, json.dumps(GOOD).encode(), "application/json")
        elif path == "/empty.json":
            self._send(200, json.dumps(EMPTY).encode(), "application/json")
        elif path == "/gzipped.json":
            self._send(
                200,
                gzip.compress(json.dumps(GOOD).encode()),
                "application/json",
                {"Content-Encoding": "gzip"},
            )
        elif path == "/report.txt":
            self._send(200, b"NOAA 3-day forecast\nKp 5 6 4\n" * 40, "text/plain")
        elif path == "/truncated.txt":
            self._send(200, b"tiny", "text/plain")
        elif path == "/broken.json":
            self._send(200, b'{"signature": {"source": ', "application/json")
        elif path == "/unauthorized":
            self._send(401, b'{"errors":["token required"]}', "application/json")
        else:
            self._send(404, b"not found", "text/plain")


CASES = [
    # (label, endpoint dict, expected verdict, why this case exists)
    (
        "well-formed JSON with enough records",
        {"id": "good", "url": "/good.json",
         "expect": {"json_keys": ["signature", "count", "data"],
                    "min_items": {"path": "data", "n": 3}}},
        "pass",
        "the happy path must pass",
    ),
    (
        "200 but the payload is empty",
        {"id": "empty", "url": "/empty.json",
         "expect": {"json_keys": ["data"], "min_items": {"path": "data", "n": 1}}},
        "fail",
        "the most common silent breakage: the host is up, the data is gone",
    ),
    (
        "200 but a declared field is missing",
        {"id": "missing_key", "url": "/good.json",
         "expect": {"json_keys": ["signature", "fields"]}},
        "fail",
        "an API that changed its schema must not score as healthy",
    ),
    (
        "gzip-encoded response",
        {"id": "gzipped", "url": "/gzipped.json",
         "expect": {"json_keys": ["data"], "min_items": {"path": "data", "n": 3}}},
        "pass",
        "several catalogue sources only serve gzip",
    ),
    (
        "text body containing the expected marker",
        {"id": "text_ok", "url": "/report.txt",
         "expect": {"contains": ["NOAA"], "min_bytes": 500}},
        "pass",
        "text products are checked by content, not just status",
    ),
    (
        "text body missing the expected marker",
        {"id": "text_wrong", "url": "/report.txt", "expect": {"contains": ["ESA Risk List"]}},
        "fail",
        "a server that returns a login or error page instead must fail",
    ),
    (
        "body far shorter than declared",
        {"id": "truncated", "url": "/truncated.txt", "expect": {"min_bytes": 10000}},
        "fail",
        "catches truncated or placeholder responses",
    ),
    (
        "malformed JSON",
        {"id": "broken", "url": "/broken.json", "expect": {"json_keys": ["signature"]}},
        "fail",
        "unparsable output is a failure even with a 200",
    ),
    (
        "expected 401 from an auth-gated endpoint",
        {"id": "unauth", "url": "/unauthorized", "expect": {"status": 401}},
        "pass",
        "credential-gated sources are liveness-checked by their rejection",
    ),
    (
        "unexpected 404",
        {"id": "gone", "url": "/moved", "expect": {"status": 200}},
        "fail",
        "a relocated endpoint must drop the source's score",
    ),
    (
        "connection refused",
        {"id": "dead", "url": "http://127.0.0.1:1/never", "expect": {"status": 200}},
        "fail",
        "a dead host is a failure, not an exception",
    ),
]


def main() -> int:
    server = HTTPServer(("127.0.0.1", 0), Handler)
    base = f"http://127.0.0.1:{server.server_port}"
    threading.Thread(target=server.serve_forever, daemon=True).start()

    verify.PER_HOST_DELAY = 0.0  # no politeness delay against ourselves
    source = {"id": "selftest", "creds_env": []}

    failures = 0
    print(f"self-test against {base}\n")
    for label, endpoint, expected, rationale in CASES:
        ep = dict(endpoint)
        if not ep["url"].startswith("http"):
            ep["url"] = base + ep["url"]
        got = verify.probe(source, ep, timeout=10)["verdict"]
        ok = got == expected
        failures += not ok
        print(f"  {'ok  ' if ok else 'BAD '} {label:<44} expected {expected:<5} got {got}")
        if not ok:
            print(f"       ({rationale})")

    # The dotted-path helper underpins every min_items check.
    assert verify.dig({"a": {"b": [1, 2]}}, "a.b") == [1, 2]
    assert verify.dig([{"x": 1}], "0.x") == 1
    assert verify.dig({"a": 1}, "a.missing") is None
    assert verify.dig([1, 2, 3], "") == [1, 2, 3]
    print("\n  ok   dotted-path lookup")

    server.shutdown()
    if failures:
        print(f"\n{failures} self-test case(s) wrong — the verifier cannot be trusted")
        return 1
    print(f"\nall {len(CASES)} cases correct — verifier behaves as documented")
    return 0


if __name__ == "__main__":
    sys.exit(main())
