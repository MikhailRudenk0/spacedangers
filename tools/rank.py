#!/usr/bin/env python3
"""Score and rank the catalog from measured verification results.

Liveness comes from tools/verify.py — nothing else. The remaining dimensions
are read from declared catalog attributes and converted to points by the
weight table in catalog/sources.yaml, so the ranking is reproducible and every
number can be traced back to either a probe or a declared field.

Usage:
    python3 tools/rank.py [--catalog catalog/sources.yaml]
                          [--results results/verification-latest.json]
                          [--out-json results/ranking.json]
                          [--out-md docs/SOURCES.md]
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

import yaml

DOMAIN_LABELS = {
    "neo_impact": "NEO / impact risk",
    "fireballs": "Fireballs & bolides",
    "orbits": "Orbits & ephemerides",
    "solar": "Solar activity",
    "geomagnetic": "Geomagnetic",
    "ionosphere": "Ionosphere",
    "radiation": "Radiation environment",
    "debris": "Debris & tracked objects",
    "conjunctions": "Conjunctions",
    "reentry": "Reentry",
    "transients": "High-energy transients",
    "earth_effects": "Earth-side effects",
}

AUTH_LABELS = {
    "none": "none",
    "demo_key": "free key (DEMO_KEY works)",
    "free_key": "free key / token",
    "account": "free account + login",
    "paid": "paid",
}


def liveness_score(records: list[dict], max_points: int) -> tuple[float, str]:
    """Fraction of probes that passed, scaled to max_points.

    Skipped probes are excluded from the denominator rather than counted as
    failures: a source we could not test is not a source we proved broken.
    """
    testable = [r for r in records if r["verdict"] in ("pass", "fail")]
    if not testable:
        return 0.0, "untested"
    passed = sum(1 for r in testable if r["verdict"] == "pass")
    frac = passed / len(testable)
    note = f"{passed}/{len(testable)} probes passed"
    return round(frac * max_points, 2), note


def score_source(source: dict, records: list[dict], cfg: dict) -> dict:
    w = cfg["weights"]
    live, live_note = liveness_score(records, w["liveness"])

    fmts = source.get("formats") or ["html"]
    parse = max(cfg["parse_points"].get(f, 0) for f in fmts)
    parse = round(parse * w["parseability"] / max(cfg["parse_points"].values()), 2)

    def scaled(table_name: str, key: str, weight_name: str) -> float:
        table = cfg[table_name]
        raw = table.get(key, 0)
        return round(raw * w[weight_name] / max(table.values()), 2)

    access = scaled("access_points", source["auth"], "access")
    relevance = scaled("relevance_points", source["relevance"], "relevance")
    cadence = scaled("cadence_points", source["cadence"], "cadence")
    depth = scaled("depth_points", source["depth"], "depth")
    uniq = scaled("uniqueness_points", source["uniqueness"], "uniqueness")

    components = {
        "liveness": live,
        "access": access,
        "parseability": parse,
        "relevance": relevance,
        "cadence": cadence,
        "depth": depth,
        "uniqueness": uniq,
    }
    latencies = [r["elapsed_ms"] for r in records if r.get("elapsed_ms") and r["verdict"] == "pass"]
    return {
        "id": source["id"],
        "name": source["name"],
        "org": source["org"],
        "homepage": source["homepage"],
        "domains": source["domains"],
        "auth": source["auth"],
        "formats": fmts,
        "cadence": source["cadence"],
        "depth": source["depth"],
        "relevance": source["relevance"],
        "uniqueness": source["uniqueness"],
        "license": source.get("license", "unspecified"),
        "provides": source["provides"].rstrip(),
        "components": components,
        "total": round(sum(components.values()), 2),
        "liveness_note": live_note,
        "median_latency_ms": sorted(latencies)[len(latencies) // 2] if latencies else None,
        "endpoints": [
            {
                "id": e["id"],
                "name": e.get("name", e["id"]),
                "url": e["url"],
                "provides": e.get("provides", ""),
            }
            for e in source["endpoints"]
        ],
        "probes": records,
    }


def tier(total: float) -> str:
    if total >= 80:
        return "A — build on it"
    if total >= 65:
        return "B — worth wiring up"
    if total >= 50:
        return "C — situational"
    return "D — only if you need exactly this"


def md_table(rows: list[dict]) -> str:
    out = [
        "| # | Source | Score | Tier | Auth | Cadence | Verified |",
        "|--:|--------|------:|------|------|---------|----------|",
    ]
    for i, r in enumerate(rows, 1):
        out.append(
            f"| {i} | [{r['name']}]({r['homepage']}) | {r['total']:.1f} | {tier(r['total'])[0]} "
            f"| {AUTH_LABELS.get(r['auth'], r['auth'])} | {r['cadence']} | {r['liveness_note']} |"
        )
    return "\n".join(out)


def render_md(ranked: list[dict], meta: dict) -> str:
    L: list[str] = []
    A = L.append
    A("# Space-hazard data sources, ranked")
    A("")
    A(
        f"Generated by `tools/rank.py` from a live verification run on "
        f"**{meta['verified_at']}**. Every source below was hit over the network by "
        f"`tools/verify.py`: {meta['totals']['pass']} of {meta['totals']['endpoints']} "
        f"endpoint probes passed, {meta['totals']['fail']} failed, "
        f"{meta['totals']['skipped']} were skipped for missing credentials."
    )
    A("")
    A("Scores are computed, not hand-assigned. The weights live in "
      "`catalog/sources.yaml` under `scoring`:")
    A("")
    A("| Dimension | Max | What it measures |")
    A("|-----------|----:|------------------|")
    A("| Liveness | 25 | Fraction of this source's probes that passed just now |")
    A("| Relevance | 20 | Warning data > physical driver > reference catalogue |")
    A("| Access | 15 | No auth > demo key > free key > account > paid |")
    A("| Parseability | 12 | JSON/CSV > XML > fixed-width text > HTML scraping |")
    A("| Cadence | 12 | How often the data refreshes |")
    A("| Depth | 8 | How far the archive goes back |")
    A("| Uniqueness | 8 | Whether anywhere else has this data |")
    A("")
    A("## The ranking")
    A("")
    A(md_table(ranked))
    A("")
    A("## What each source gives you")
    A("")
    for i, r in enumerate(ranked, 1):
        A(f"### {i}. {r['name']} — {r['total']:.1f} / 100 ({tier(r['total'])})")
        A("")
        domains = ", ".join(DOMAIN_LABELS.get(d, d) for d in r["domains"])
        A(f"**{r['org']}** · {r['homepage']}  ")
        A(f"**Covers:** {domains}  ")
        A(
            f"**Auth:** {AUTH_LABELS.get(r['auth'], r['auth'])} · "
            f"**Formats:** {', '.join(r['formats'])} · "
            f"**Updates:** {r['cadence']} · "
            f"**Archive:** {r['depth'].replace('_', ' ')} · "
            f"**Licence:** {r['license']}  "
        )
        lat = f"{r['median_latency_ms']} ms median" if r["median_latency_ms"] else "n/a"
        A(f"**Verification:** {r['liveness_note']} · latency {lat}")
        A("")
        A(r["provides"])
        A("")
        A("| Endpoint | Probe result | Fields returned |")
        A("|----------|--------------|-----------------|")
        probes = {p["endpoint_id"]: p for p in r["probes"]}
        for e in r["endpoints"]:
            p = probes.get(e["id"], {})
            verdict = p.get("verdict", "?")
            if verdict == "pass":
                res = f"PASS · {p.get('status')} · {p.get('elapsed_ms')} ms · {p.get('bytes')} B"
            elif verdict == "skipped":
                res = f"SKIP · {p.get('reason', '')}"
            else:
                why = "; ".join(p.get("checks_failed") or [p.get("error", "unknown")])
                res = f"FAIL · {why[:110]}"
            fields = (e["provides"] or "").replace("|", "/")
            A(f"| `{e['id']}`<br/>`{e['url'][:78]}` | {res} | {fields} |")
        A("")
        A("---")
        A("")
    A("## Score breakdown")
    A("")
    A("| Source | Live | Rel | Access | Parse | Cadence | Depth | Uniq | Total |")
    A("|--------|-----:|----:|-------:|------:|--------:|------:|-----:|------:|")
    for r in ranked:
        c = r["components"]
        A(
            f"| {r['name'][:46]} | {c['liveness']:.1f} | {c['relevance']:.1f} | {c['access']:.1f} "
            f"| {c['parseability']:.1f} | {c['cadence']:.1f} | {c['depth']:.1f} | "
            f"{c['uniqueness']:.1f} | **{r['total']:.1f}** |"
        )
    A("")
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--catalog", default="catalog/sources.yaml")
    ap.add_argument("--results", default="results/verification-latest.json")
    ap.add_argument("--out-json", default="results/ranking.json")
    ap.add_argument("--out-md", default="docs/SOURCES.md")
    args = ap.parse_args()

    with open(args.catalog, encoding="utf-8") as fh:
        catalog = yaml.safe_load(fh)
    with open(args.results, encoding="utf-8") as fh:
        meta = json.load(fh)

    cfg = catalog["scoring"]
    by_source = meta["by_source"]

    ranked = [score_source(s, by_source.get(s["id"], []), cfg) for s in catalog["sources"]]
    ranked.sort(key=lambda r: (-r["total"], r["name"]))

    doc = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "verified_at": meta["verified_at"],
        "weights": cfg["weights"],
        "ranking": ranked,
    }
    with open(args.out_json, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    with open(args.out_md, "w", encoding="utf-8") as fh:
        fh.write(render_md(ranked, meta))

    print(f"ranked {len(ranked)} sources -> {args.out_md}, {args.out_json}")
    for i, r in enumerate(ranked[:10], 1):
        print(f"  {i:2}. {r['total']:5.1f}  {r['name']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
