# spacedangers — verified source catalogue

A ranked, machine-verified list of the public internet sources you can parse for
space-hazard data: asteroid impact risk, solar and geomagnetic storms, radiation,
orbital debris and conjunctions, reentries, fireballs, and high-energy transients.

**The ranked list with full descriptions is in [`docs/SOURCES.md`](docs/SOURCES.md).**

## Why this exists

Every "best space APIs" list on the web is a link dump nobody re-tested. Endpoints
move, hosts go behind Cloudflare, services quietly die. So this repo does not
assert that a source works — it checks, on every push and weekly, and the ranking
is recomputed from what actually answered.

## How it works

```
catalog/sources.yaml    one entry per source: access, formats, cadence, what it
                        provides, and the concrete probe(s) that prove it is alive
tools/verify.py         issues the real HTTP requests, validates each response
                        against the declared expectations, records status,
                        latency, size and a sample of the payload
tools/rank.py           scores each source and regenerates docs/SOURCES.md
results/                the raw verification output and the scored ranking
```

Run it yourself:

```bash
pip install -r requirements.txt
python3 tools/verify.py      # -> results/verification-latest.json
python3 tools/rank.py        # -> docs/SOURCES.md, results/ranking.json
```

Probe one source while iterating:

```bash
python3 tools/verify.py --only noaa_swpc --out /tmp/swpc.json
```

## Scoring

100 points, all computed — none hand-assigned. Weights are declared in
`catalog/sources.yaml` under `scoring`, so changing a priority is a config edit,
not a code edit.

| Dimension | Max | Source of the number |
|-----------|----:|----------------------|
| Liveness | 25 | Measured: fraction of this source's probes that passed |
| Relevance | 20 | Declared: warning data > physical driver > reference catalogue |
| Access | 15 | Declared: no auth > demo key > free key > account > paid |
| Parseability | 12 | Declared: JSON/CSV > XML > text > HTML scraping |
| Cadence | 12 | Declared: how often it refreshes |
| Depth | 8 | Declared: how far the archive goes back |
| Uniqueness | 8 | Declared: whether anywhere else carries this data |

A source that stops responding loses 25 points and drops out of the top tier on
the next run, without anyone editing a list.

## Credentials

Everything ranked in tier A and B works with no credentials. Four sources have
an authenticated tier; set these to unlock their real endpoints, or leave them
unset and the verifier probes the service's unauthenticated liveness instead:

| Variable | Source |
|----------|--------|
| `NASA_API_KEY` | api.nasa.gov (NeoWs, DONKI mirror) — falls back to `DEMO_KEY` |
| `SPACETRACK_USER`, `SPACETRACK_PASS` | Space-Track.org |
| `DISCOS_TOKEN` | ESA DISCOSweb |
| `AMS_API_KEY` | American Meteor Society |

In CI they are read from repository secrets.

## Adding a source

Append an entry to `catalog/sources.yaml` with at least one endpoint and an
`expect` block strict enough that a silently-broken response fails it — a 200
that returns an empty list or a Cloudflare page should not pass. Then run
`tools/verify.py --only <id>`. If it passes, it earns its rank.
