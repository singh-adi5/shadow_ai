# Security Policy

Shadow AI Detector is a DLP / Shadow AI detection pipeline. This document
describes the security controls actually implemented in the code (not
aspirational ones), how to configure them for a deployment, and how to
report a vulnerability.

## Reporting a Vulnerability

This is a portfolio/research project, not a commercially supported product.
If you find a security issue:

1. **Do not open a public GitHub issue for it.**
2. Email the maintainer (see the GitHub profile / repository contact) with
   a description, reproduction steps, and impact.
3. Expect an acknowledgement within a few days. There is no formal SLA —
   this is a single-maintainer project.

## Supported Versions

Only the `main` branch is supported. There are no maintained release
branches.

## Cross-Site Scripting (OWASP A03 — Injection)

The dashboard (`static/dashboard.js`) renders fields that originate from
submitted proxy logs — `user_id`, `department`, `destination_url`,
`message` (which embeds `destination_url`) — and `/dashboard` is
unauthenticated, so anyone can view it. `models.py`'s `destination_url`
validator permits a path segment (`/.*`) with no character restrictions,
so these fields are **not** guaranteed HTML-safe by input validation
alone. All dynamic rendering in `dashboard.js` goes through `textContent`
/ DOM-node construction (the `el()` helper), never `innerHTML` with
string-interpolated data — the correct place to defend against this is
output encoding at render time, not input filtering (which would also
break legitimate URLs containing `<`, `&`, etc. in query strings). Search
the file for `innerHTML` before adding new UI — every current use only
ever clears a container (`= ""`) or embeds static, non-data markup.

## SQL Injection (OWASP A03 — Injection)

`dashboard_store.py` builds filtered/sorted queries with f-strings, which
static analysis (bandit B608) flags by pattern alone. Every such query is
still injection-safe: the f-string only ever splices in (a) hardcoded
clause fragments and `?` placeholders from `_build_filter_clause()` —
actual filter *values* always go through the parameter list, bound by
`sqlite3`, never through the SQL string — and (b) `ORDER BY` SQL selected
via dict lookup against the fixed `_SORT_COLUMNS` allowlist, so the raw
`sort` request parameter is never itself placed in SQL text. The
`# nosec B608` markers at each site document this reasoning inline; if you
add a new filter or sort option, keep values in `params` and keep any new
column/direction choice behind an allowlist the same way — never format a
request value directly into a query string.

## Authentication

`POST /scan`, `POST /scan-file`, and `PATCH /dashboard/alerts/{id}` (the
one dashboard endpoint that *mutates* stored data — incident status) are
protected by an `X-API-Key` header check (`presidio_scanner.require_api_key`),
enforced with a constant-time comparison (`hmac.compare_digest`). Every
other `/dashboard/*` endpoint is a read and stays unauthenticated by design
— see "Live Dashboard" in README.md.

- **Unset `SHADOW_AI_API_KEY`** → the API runs **unauthenticated**. This is
  the default for local development/demo use. A `WARNING` is logged at
  startup (`lifespan()` in `presidio_scanner.py`) whenever this is the case.
- **Set `SHADOW_AI_API_KEY`** (env var, or `.env` file via `python-dotenv`)
  → every request to `/scan` and `/scan-file` must send a matching
  `X-API-Key` header, or the API returns `401`.
- `GET /health` and `GET /config` are intentionally left unauthenticated —
  neither leaks the API key or any scanned data.

**Before exposing this service on a public/deployed endpoint, set
`SHADOW_AI_API_KEY` to a long random value** (e.g. `openssl rand -hex 32`)
and distribute it out-of-band to callers. There is currently no key
rotation, per-caller keys, or OAuth2 support — this is a single shared
secret, suitable for a demo/internal tool, not a multi-tenant service.

## Path Traversal (`/scan-file`)

`file_path` is resolved against `config.SCAN_FILE_BASE_DIR`
(default `./threat_model_output`) and rejected with `403` unless the
resolved path stays inside that directory (`Path.relative_to`). Absolute
paths, `../` traversal, and symlink escapes are all rejected the same way.
There is no way to make `/scan-file` read a file outside
`SCAN_FILE_BASE_DIR`; if you need to scan files elsewhere, point
`SCAN_FILE_BASE_DIR` at that location rather than passing an absolute path.

## Rate Limiting

Two backends, selected automatically:

- **Redis-backed** (`_RedisRateLimiter`, used when Redis is reachable on
  startup): a sliding-window-counter approximation — the current
  fixed-size bucket's count plus the previous bucket's count weighted by
  how far the clock is into the current window. This is deliberately not a
  pure fixed/tumbling window, which would let a client send
  `RATE_LIMIT_REQUESTS` right before a window boundary and again right
  after (2x the configured limit in a short span). It is also not an exact
  sliding log (one Redis entry per request) — it's the standard O(1)
  approximation, safe across multiple `uvicorn` worker processes since all
  workers share the same Redis instance.
- **In-process fallback** (`_InProcessRateLimiter`, deque-based rolling
  window): used automatically when Redis is unreachable. **Only correct for
  a single worker process** — with `API_WORKERS > 1` each process has its
  own deque and the effective limit multiplies by worker count. A
  `WARNING` is logged at startup when this fallback is active.

Limits: `RATE_LIMIT_REQUESTS` per `RATE_LIMIT_WINDOW_SECONDS`, both in
`config.py` / overridable via environment.

### Trusted proxies and `X-Forwarded-For`

The rate limiter keys on client IP. `X-Forwarded-For` is attacker-supplied
and is **only honoured when the direct TCP peer is in `TRUSTED_PROXIES`**
(`config.py`, env var `TRUSTED_PROXIES`, comma-separated). With an empty
list (the default), `X-Forwarded-For` is ignored entirely and the raw
socket peer IP is used — safe by default, but means the rate limiter will
key on your load balancer's IP (and share one bucket across all real
clients) until you configure `TRUSTED_PROXIES` to that load balancer's
address.

`TRUSTED_PROXIES=*` always honours XFF regardless of peer IP. This is set
in `render.yaml` for the reference Render deployment — Render's containers
are only reachable through Render's own edge proxy (no direct path from the
internet to the container), and that edge's IP isn't fixed/published for
exact allowlisting. **Only use `*` on a platform with that same guarantee**
(Render/Fly.io/Railway/Heroku single-service deployments). Never set it on
a deployment a client could reach directly (e.g. a bare VM with a public
IP) — that reintroduces the XFF spoofing bypass this control exists to close.

## Input Validation

- `ProxyLog.destination_url` accepts a bare hostname or a full `http(s)://`
  URL, capped at 2048 characters.
- `ProxyLog.payload` capped at 10 KB (`MAX_PAYLOAD_BYTES`).
- `ScanRequest.logs` requires at least 1 entry and is capped at
  `MAX_LOGS_PER_REQUEST` (default 1000, hard ceiling 10,000 enforced by the
  Pydantic field itself). `/scan-file` returns `400` (not `500`) if a file
  contains zero valid entries or more than the per-request cap — it never
  truncates silently, since silently dropping log entries in a DLP tool
  would hide exactly the threats it exists to catch.

## ReDoS

All regex patterns used for PII detection (Presidio fallback, and the O(1)
ingestion pre-filter) live in one place, `config.py`
(`FALLBACK_PATTERNS`, `PII_QUICK_PATTERN`), and use only bounded
quantifiers on disjoint character classes — no pattern has an unbounded
repetition operator without a hard upper bound. `tests/test_pipeline.py`
(`TestFix2ReDoSSafety`, `TestRegexPatternConsolidation`) runs each pattern
against an adversarial corpus and asserts sub-10ms worst-case match time.

## Concurrency Limits

`POST /scan` offloads each payload's PII scan to a thread pool
(`asyncio.get_running_loop().run_in_executor`) so the event loop is never
blocked by CPU-bound NLP inference. Concurrent scans across **all**
in-flight requests in a process are bounded by `asyncio.Semaphore`
(`config.SCAN_CONCURRENCY_LIMIT`, default 32) — without this, a single
large batch (up to `MAX_LOGS_PER_REQUEST`) could submit thousands of
simultaneous jobs to the default thread pool and starve every other
request.

## Data Minimisation

- `EntityDetection.value` is always the literal string `"[REDACTED]"` —
  raw PII values are never included in scan results, alerts, exports, or
  logs.
- `log_id` / `alert_id` are SHA-256 hashes truncated to 16 hex chars, not
  raw identifiers.
- `STORE_ORIGINAL_DATA` and `LOG_SENSITIVE_VALUES` default to `False` and
  are not currently used to gate any code path that would otherwise store
  raw PII — there is no such path in this codebase.

## PII Detection Coverage

`presidio_recognizers.py` registers custom `PatternRecognizer`s for
`API_KEY` and `GENERIC_PASSWORD` — neither is a Presidio built-in entity
type, so without this registration, requesting them from
`AnalyzerEngine.analyze()` silently returns zero matches (the two
highest-weighted `HIGH_RISK_ENTITY_TYPES`, weight 25 each). Both custom
recognizers reuse the exact bounded regex from `config.FALLBACK_PATTERNS`,
so detection behaviour is identical whether Presidio or the regex fallback
is active.

## Data Persistence

Dashboard/incident data lives in a local SQLite file
(`config.DASHBOARD_DB_PATH`, default `./threat_model_output/dashboard.db`)
— durable across process restarts, capped at the 5000 most recent alerts
(`dashboard_store.MAX_ALERTS_STORED`, oldest pruned on insert). This is a
single local file, not a shared/replicated store: correct for the
single-instance deployment this project targets (`API_WORKERS=1`, no
Redis needed for the same reason — see "Rate Limiting" above), but it does
**not** survive a platform that wipes the filesystem on redeploy (Render's
free plan does, unless you attach a persistent disk — see
[DEPLOYMENT.md](./DEPLOYMENT.md)) and does not work as a shared store
across multiple instances.

## Known Limitations (not yet addressed)

- No authentication on `GET /health` / `GET /config` (by design — neither
  leaks sensitive data, but confirm that holds if you extend either).
- No mTLS / client-cert auth; `X-API-Key` is a single shared secret.
- `USE_HTTPS` in `config.py` is a flag only — TLS termination is expected
  to happen at a reverse proxy / load balancer in front of this service,
  not in the `uvicorn` process itself.
- The Redis rate limiter fails **open** (allows the request) on a Redis
  connection blip, prioritising availability over strict enforcement.
- Regex fallback PII detection is inherently less accurate than the
  Presidio/spaCy NLP path; both share the same entity coverage, but the
  NLP path has materially better recall/precision on natural-language
  payloads.
