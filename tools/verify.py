#!/usr/bin/env python3
"""Probe every endpoint in catalog/sources.yaml and record what actually happened.

No source in this repo is listed on reputation. Each one is hit over the real
network, and the response is checked against the expectations declared in the
catalog. The output is a JSON document consumed by tools/rank.py.

Usage:
    python3 tools/verify.py [--catalog catalog/sources.yaml]
                            [--out results/verification-latest.json]
                            [--only source_id[,source_id...]]
                            [--timeout 45] [--workers 6]

Credentials are optional. An endpoint that declares `creds_env` is skipped when
those variables are absent; the source is then judged on its unauthenticated
liveness probe. NASA endpoints fall back to DEMO_KEY.
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import os
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import yaml

UA = "spacedangers-source-verifier/1.0 (+https://github.com/MikhailRudenk0/spacedangers)"
PER_HOST_DELAY = 1.0  # seconds between consecutive requests to the same host

# A local egress proxy refusing the CONNECT says nothing about the remote
# service. Runs from inside a restricted network must not record a healthy
# source as dead, so these are reported as `blocked` and excluded from scoring.
EGRESS_BLOCK_MARKERS = (
    "Tunnel connection failed",
    "CONNECT tunnel failed",
    "407 Proxy Authentication",
    "ProxyError",
)


def is_egress_block(error: str) -> bool:
    return any(m.lower() in error.lower() for m in EGRESS_BLOCK_MARKERS)

_host_locks: dict[str, threading.Lock] = defaultdict(threading.Lock)
_host_last: dict[str, float] = defaultdict(float)


def build_url(endpoint: dict) -> str:
    url = endpoint["url"]
    params = dict(endpoint.get("params") or {})
    key_param = endpoint.get("api_key_param")
    if key_param:
        params[key_param] = os.environ.get("NASA_API_KEY", "DEMO_KEY")
    if params:
        sep = "&" if "?" in url else "?"
        url = url + sep + urllib.parse.urlencode(params, safe="'<>=")
    raw = endpoint.get("query_raw")
    if raw:
        sep = "&" if "?" in url else "?"
        url = url + sep + raw
    return url


def decode_body(raw: bytes, headers) -> tuple[bytes, str | None]:
    """Return (decoded_bytes, decode_note)."""
    enc = (headers.get("Content-Encoding") or "").lower()
    if enc == "gzip" or raw[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(raw), "gzip"
        except OSError:
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(raw)) as fh:
                    return fh.read(), "gzip-partial"
            except OSError:
                return raw, "gzip-failed"
    return raw, None


def fetch(url: str, timeout: float, max_bytes: int = 4_000_000) -> dict:
    """One HTTP GET. Never raises; the failure mode is part of the result."""
    host = urllib.parse.urlparse(url).netloc
    lock = _host_locks[host]
    with lock:
        wait = PER_HOST_DELAY - (time.monotonic() - _host_last[host])
        if wait > 0:
            time.sleep(wait)
        _host_last[host] = time.monotonic()

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": UA,
            "Accept": "application/json, text/csv, text/plain, */*",
            "Accept-Encoding": "gzip",
        },
    )
    ctx = ssl.create_default_context()
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read(max_bytes)
            elapsed = time.monotonic() - started
            body, note = decode_body(raw, resp.headers)
            return {
                "ok": True,
                "status": resp.status,
                "final_url": resp.geturl(),
                "content_type": (resp.headers.get("Content-Type") or "").split(";")[0].strip(),
                "bytes": len(body),
                "elapsed_ms": round(elapsed * 1000),
                "decode": note,
                "body": body,
            }
    except urllib.error.HTTPError as exc:
        elapsed = time.monotonic() - started
        try:
            raw = exc.read(max_bytes)
        except Exception:  # noqa: BLE001 - body is best effort
            raw = b""
        body, note = decode_body(raw, exc.headers) if raw else (b"", None)
        return {
            "ok": True,
            "status": exc.code,
            "final_url": url,
            "content_type": (exc.headers.get("Content-Type") or "").split(";")[0].strip()
            if exc.headers
            else "",
            "bytes": len(body),
            "elapsed_ms": round(elapsed * 1000),
            "decode": note,
            "body": body,
            "http_error": True,
        }
    except Exception as exc:  # noqa: BLE001 - network errors are data here
        return {
            "ok": False,
            "status": None,
            "final_url": url,
            "error": f"{type(exc).__name__}: {exc}",
            "elapsed_ms": round((time.monotonic() - started) * 1000),
            "bytes": 0,
            "body": b"",
        }


def dig(obj, path: str):
    """Tiny dotted-path lookup. Empty path returns the object itself."""
    if not path:
        return obj
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict):
            if part not in cur:
                return None
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit():
            idx = int(part)
            if idx >= len(cur):
                return None
            cur = cur[idx]
        else:
            return None
    return cur


def summarise(parsed, body: bytes) -> str:
    """A short, honest fingerprint of what came back."""
    if parsed is not None:
        if isinstance(parsed, list):
            head = parsed[0] if parsed else None
            if isinstance(head, dict):
                return f"list[{len(parsed)}], first keys: {sorted(head)[:8]}"
            return f"list[{len(parsed)}], first: {json.dumps(head)[:120]}"
        if isinstance(parsed, dict):
            return f"object keys: {sorted(parsed)[:10]}"
    text = body[:200].decode("utf-8", "replace").replace("\n", " ").strip()
    return f"text: {text[:160]}"


def check(endpoint: dict, res: dict) -> tuple[list[str], list[str], object, str]:
    """Return (passed, failed, parsed_json_or_None, sample_summary)."""
    expect = endpoint.get("expect") or {}
    passed: list[str] = []
    failed: list[str] = []

    want_status = expect.get("status", 200)
    if res.get("status") == want_status:
        passed.append(f"status=={want_status}")
    else:
        failed.append(f"status {res.get('status')} != {want_status}")

    body: bytes = res.get("body", b"")
    parsed = None
    ctype = res.get("content_type", "")
    looks_json = "json" in ctype or body[:1] in (b"{", b"[")
    if looks_json and body:
        try:
            parsed = json.loads(body.decode("utf-8", "replace"))
            passed.append("valid JSON")
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            failed.append(f"JSON parse failed: {exc}")

    for key in expect.get("json_keys") or []:
        if isinstance(parsed, dict) and key in parsed:
            passed.append(f"key:{key}")
        else:
            failed.append(f"missing JSON key: {key}")

    mi = expect.get("min_items")
    if mi:
        target = dig(parsed, mi.get("path", "")) if parsed is not None else None
        if isinstance(target, list) and len(target) >= mi["n"]:
            passed.append(f"items>={mi['n']} (got {len(target)})")
        else:
            got = len(target) if isinstance(target, list) else type(target).__name__
            failed.append(f"min_items {mi['n']} at '{mi.get('path','')}' -> {got}")

    for needle in expect.get("contains") or []:
        if needle.encode("utf-8") in body or needle.lower().encode("utf-8") in body.lower():
            passed.append(f"contains:{needle!r}")
        else:
            failed.append(f"body missing {needle!r}")

    mb = expect.get("min_bytes")
    if mb:
        if res.get("bytes", 0) >= mb:
            passed.append(f"bytes>={mb}")
        else:
            failed.append(f"only {res.get('bytes', 0)} bytes, wanted {mb}")

    return passed, failed, parsed, summarise(parsed, body)


def probe(source: dict, endpoint: dict, timeout: float) -> dict:
    creds = source.get("creds_env") or []
    # Endpoints are written as unauthenticated liveness probes by default, so
    # a credential-gated source still gets verified. Only an endpoint that
    # explicitly sets `requires_creds: true` is skipped when keys are absent.
    if endpoint.get("requires_creds") and not all(os.environ.get(c) for c in creds):
        return {
            "source_id": source["id"],
            "endpoint_id": endpoint["id"],
            "name": endpoint.get("name", endpoint["id"]),
            "url": build_url(endpoint),
            "verdict": "skipped",
            "reason": f"missing credentials: {', '.join(creds)}",
        }

    url = build_url(endpoint)
    res = fetch(url, timeout=timeout)
    record = {
        "source_id": source["id"],
        "endpoint_id": endpoint["id"],
        "name": endpoint.get("name", endpoint["id"]),
        "url": url,
        "status": res.get("status"),
        "elapsed_ms": res.get("elapsed_ms"),
        "bytes": res.get("bytes"),
        "content_type": res.get("content_type"),
    }
    if not res["ok"]:
        err = res.get("error", "")
        if is_egress_block(err):
            record.update(
                {
                    "verdict": "blocked",
                    "error": err,
                    "reason": "local egress policy refused the connection; source not tested",
                }
            )
        else:
            record.update({"verdict": "fail", "error": err, "checks_failed": ["transport"]})
        return record

    passed, failed, _parsed, sample = check(endpoint, res)
    record.update(
        {
            "verdict": "pass" if not failed else "fail",
            "checks_passed": passed,
            "checks_failed": failed,
            "sample": sample,
        }
    )
    if res.get("decode"):
        record["decode"] = res["decode"]
    return record


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--catalog", default="catalog/sources.yaml")
    ap.add_argument("--out", default="results/verification-latest.json")
    ap.add_argument("--only", default="")
    ap.add_argument("--timeout", type=float, default=45.0)
    ap.add_argument("--workers", type=int, default=6)
    args = ap.parse_args()

    with open(args.catalog, encoding="utf-8") as fh:
        catalog = yaml.safe_load(fh)

    sources = catalog["sources"]
    if args.only:
        wanted = {s.strip() for s in args.only.split(",")}
        sources = [s for s in sources if s["id"] in wanted]

    jobs = [(s, e) for s in sources for e in s["endpoints"]]
    print(f"probing {len(jobs)} endpoints across {len(sources)} sources", flush=True)

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(probe, s, e, args.timeout) for s, e in jobs]
        for fut in futures:
            rec = fut.result()
            results.append(rec)
            mark = {"pass": "PASS", "fail": "FAIL", "skipped": "SKIP", "blocked": "BLOK"}[
                rec["verdict"]
            ]
            detail = ""
            if rec["verdict"] == "fail":
                detail = "  <- " + "; ".join(rec.get("checks_failed") or [rec.get("error", "")])[:160]
            elif rec["verdict"] in ("skipped", "blocked"):
                detail = "  <- " + rec["reason"]
            print(
                f"  {mark}  {rec['source_id']}/{rec['endpoint_id']}  "
                f"{rec.get('status')}  {rec.get('elapsed_ms')}ms  {rec.get('bytes')}B{detail}",
                flush=True,
            )

    by_source: dict[str, list[dict]] = defaultdict(list)
    for rec in results:
        by_source[rec["source_id"]].append(rec)

    doc = {
        "verified_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "catalog_version": catalog.get("version"),
        "totals": {
            "sources": len(sources),
            "endpoints": len(results),
            "pass": sum(1 for r in results if r["verdict"] == "pass"),
            "fail": sum(1 for r in results if r["verdict"] == "fail"),
            "skipped": sum(1 for r in results if r["verdict"] == "skipped"),
            "blocked": sum(1 for r in results if r["verdict"] == "blocked"),
        },
        "results": results,
        "by_source": {k: v for k, v in by_source.items()},
    }

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=False)
        fh.write("\n")

    t = doc["totals"]
    print(
        f"\n{t['pass']} pass / {t['fail']} fail / {t['skipped']} skipped / "
        f"{t['blocked']} blocked -> {args.out}"
    )
    if t["blocked"] and not t["pass"]:
        print(
            "\nEvery probe was refused by the local network, so nothing was tested.\n"
            "Re-run from a host with open outbound HTTPS to get a real ranking."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
