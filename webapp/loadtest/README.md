# Load testing the deferred scan queue (k6)

[`k6-scan-queue.js`](k6-scan-queue.js) exercises the Phase 1 scan queue in
[`../webapp.py`](../webapp.py) and asserts the queue contract with exact
expected values. Pass/fail is enforced by k6 thresholds (non-zero exit code on
failure); a readable expected-vs-actual table is printed at the end.

## Prerequisites

- [k6](https://k6.io/docs/get-started/installation/) (`brew install k6`).
- A running instance of the webapp. Its config **must match** the env values you
  pass to k6 (`MAX_CONCURRENT` mirrors the server's `SESSION_MAX`).

## The metrics being checked

| metric | meaning | expected |
| --- | --- | --- |
| `server_errors_5xx` | count of 5xx from `POST /api/scans` | `0` |
| `http_req_failed` | rate of unexpected statuses / conn errors | `0.00%` |
| `queued_invariant_ok` | every 201 has `state=queued`, `complete=0`, `remaining=total`, an `id` | `100%` |
| `retry_after_present` | every 429 carries `Retry-After: 60` | `100%` |
| `checks` | all inline checks | `100%` |
| `scans_accepted_201` / `scans_rejected_429` | accepted vs rejected counts | scenario-dependent (below) |

## Scenarios

Select with `SCENARIO=...`. Default is `burst`.

### 1. `backpressure` — deterministic, fully offline (recommended first run)

Run the server with `SESSION_MAX=0` so the dispatcher never promotes anything:
no scan / DNS ever runs, and the pending queue fills to exactly `MAX_QUEUE`.

```bash
# terminal 1: server with a small, known queue and zero concurrency
cd webapp
SESSION_MAX=0 MAX_QUEUE=20 WEBAPP_START_THREADS=1 \
  gunicorn3 webapp:app --bind 127.0.0.1:8000 --workers 1 --threads 3
# (or: SESSION_MAX=0 MAX_QUEUE=20 python3 webapp.py)

# terminal 2
cd webapp/loadtest
SCENARIO=backpressure MAX_QUEUE=20 BP_OVERFLOW=25 \
  k6 run k6-scan-queue.js
```

Exact expected values:

- `scans_accepted_201 == MAX_QUEUE` (20)
- `scans_rejected_429 == BP_OVERFLOW` (25)
- `server_errors_5xx == 0`, `retry_after_present == 100%`, `queued_invariant_ok == 100%`

These are enforced as thresholds, so the run fails if any is off.

### 2. `burst` — realistic load (hits real DNS)

Run the server with production-like values, then fire more requests than
capacity as fast as possible.

```bash
# terminal 1
cd webapp
SESSION_MAX=10 MAX_QUEUE=500 \
  gunicorn3 webapp:app --bind 127.0.0.1:8000 --workers 1 --threads 3

# terminal 2
cd webapp/loadtest
SCENARIO=burst MAX_CONCURRENT=10 MAX_QUEUE=500 BURST_VUS=100 BURST_OVERFLOW=50 \
  k6 run k6-scan-queue.js
```

Expected (exact invariants):

- `server_errors_5xx == 0` — bursts queue, they never 500.
- Every 201 satisfies the queued invariant; every 429 has `Retry-After`.

Expected (approximate, depends on scan duration): `accepted >= MAX_QUEUE`, and
`429`s appear once the queue saturates. Set a small `MAX_QUEUE` (e.g. 20) to make
429s easy to observe.

### 3. `edge` — validation edge cases (offline)

```bash
cd webapp/loadtest
SCENARIO=edge k6 run k6-scan-queue.js
```

Exact expected values:

- missing `url` -> `400`
- domain label longer than `DOMAIN_MAXLEN` (15) -> `400` `"Domain name is too long"`
- unknown scan id -> `404`

> Note: the queue-full check in `api_scan()` runs *before* request validation, so
> when the queue is saturated every POST returns `429` (backpressure wins over
> `400`). Run `edge` against a server whose queue is not full.

### 4. `lifecycle` — single scan progression (needs network)

```bash
cd webapp/loadtest
SCENARIO=lifecycle DOMAIN=example.com POLL_TIMEOUT_S=120 k6 run k6-scan-queue.js
```

Expected: `POST` returns `201`; polling `GET /api/scans/<id>` keeps all legacy
keys present, `complete <= total`, `state` stays in `{queued, running, done}`,
and the scan reaches `done` (or `remaining == 0`) within the timeout.

### `all`

Runs `edge`, then `lifecycle`, then `burst` staggered. Requires network.

## Environment variables

| var | default | notes |
| --- | --- | --- |
| `BASE_URL` | `http://127.0.0.1:8000` | server under test |
| `MAX_CONCURRENT` | `10` | must equal server `SESSION_MAX` |
| `MAX_QUEUE` | `500` | must equal server `MAX_QUEUE` |
| `DOMAIN` | `example.com` | domain to scan |
| `BURST_VUS` | `100` | concurrent virtual users in `burst` |
| `BURST_OVERFLOW` | `50` | requests beyond `MAX_CONCURRENT+MAX_QUEUE` |
| `BP_OVERFLOW` | `25` | extra requests in `backpressure` (expected 429 count) |
| `POLL_TIMEOUT_S` | `120` | max poll time in `lifecycle` |

A machine-readable dump is written to `loadtest-summary.json` after each run.
