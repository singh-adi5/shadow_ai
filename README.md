# Shadow AI Detector

**Enterprise-grade Shadow AI detection pipeline — identifies employees transmitting
sensitive PII to unsanctioned AI endpoints in real time.**

> NIST SP 800-53 compliant · OWASP Top 10 (2021) hardened · FastAPI + Microsoft Presidio

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          SHADOW AI DETECTOR  v2.0                               │
│                   NIST SP 800-53 · OWASP Top 10 · GDPR-aware                   │
└──────────────────────────────────┬──────────────────────────────────────────────┘
                                   │
          ╔════════════════════════▼═══════════════════════════╗
          ║              INGESTION BOUNDARY                     ║
          ║  • Pydantic v2 strict schema validation (A05)       ║
          ║  • Payload size guard: 10 KB max (DoS prevention)   ║
          ║  • IP format + URL format validation                 ║
          ║  • UTF-8 BOM stripping for JSONL files              ║
          ╚═════════════════╦═══════════════════════════════════╝
                            │
        ┌───────────────────┼────────────────────────────────────┐
        │                   │                                    │
        ▼                   ▼                                    ▼
┌───────────────┐   ┌───────────────────┐            ┌──────────────────────┐
│  STAGE 1      │   │  STAGE 2          │            │  FastAPI REST Layer  │
│  Telemetry    │   │  PII Scanner      │◄──────────►│  POST /scan          │
│  Generator    │   │                   │            │  POST /scan-file     │
│               │   │  ┌─────────────┐  │            │  GET  /health        │
│ Synthetic     │──►│  │  Presidio   │  │            │  GET  /config        │
│ proxy logs    │   │  │  ML Engine  │  │            │                      │
│ (JSONL)       │   │  │  en_core_   │  │            │  Rate limiter:       │
│               │   │  │  web_lg     │  │            │  deque rolling-      │
│ 3 categories: │   │  └──────┬──────┘  │            │  window (100/60s)    │
│  • Clean      │   │         │ fallback│            │                      │
│  • Benign AI  │   │  ┌──────▼──────┐  │            │  Security headers:   │
│  • Shadow AI  │   │  │  Regex      │  │            │  CSP, HSTS, X-Frame  │
│               │   │  │  Fallback   │  │            └──────────────────────┘
└───────────────┘   │  │  (5 patterns│  │
                    │  │  compiled)  │  │
                    │  └─────────────┘  │
                    │                   │
                    │  Entities:        │
                    │  CREDIT_CARD      │
                    │  EMAIL_ADDRESS    │
                    │  US_SSN           │
                    │  GENERIC_PASSWORD │
                    │  API_KEY          │
                    │  PHONE_NUMBER     │
                    │  IBAN_CODE        │
                    │  CRYPTO           │
                    └────────┬──────────┘
                             │
                             │  ScanResult (Pydantic model)
                             │  Unified type — no dict/dataclass mismatch
                             ▼
          ╔════════════════════════════════════════════════════╗
          ║              DATA CONTRACT LAYER (models.py)        ║
          ║                                                      ║
          ║  ScanResult ──────────────────────────────────┐     ║
          ║    .log_id          str (SHA-256 hash)         │     ║
          ║    .destination_url str                        │     ║
          ║    .entities_found  List[EntityDetection]      │     ║
          ║    .to_policy_dict() → Dict[str,Any]  ─────────┘     ║
          ║                                                │     ║
          ║  AlertLevel(str, Enum)  ←─── JSON-safe ───────┘     ║
          ║    CRITICAL · WARNING · INFO · BLOCK                 ║
          ║                                                      ║
          ║  PolicyAction(str, Enum)  ←── JSON-safe             ║
          ║    BLOCK · ESCALATE · ALERT · LOG · QUARANTINE       ║
          ╚══════════════════════════╦═════════════════════════╝
                                     │
                                     ▼
          ╔════════════════════════════════════════════════════╗
          ║          STAGE 3 — POLICY ENGINE (STATELESS)        ║
          ║                                                      ║
          ║  ThreatPolicyEngine (no mutable state)               ║
          ║  ┌──────────────────────────────────────────────┐   ║
          ║  │  is_ai_endpoint()                            │   ║
          ║  │    O(k) pre-compiled pattern match           │   ║
          ║  │    k = 7 patterns — constant time            │   ║
          ║  │                                              │   ║
          ║  │  evaluate_threat()  ← 10-line policy         │   ║
          ║  │    IF ai AND high_risk → CRITICAL / BLOCK    │   ║
          ║  │    IF ai AND entity   → WARNING  / ALERT     │   ║
          ║  │    IF ai only         → INFO     / LOG       │   ║
          ║  │    ELSE               → INFO     / LOG       │   ║
          ║  │                                              │   ║
          ║  │  score_threat()                              │   ║
          ║  │    count × 15 + type_weights × AI_mult       │   ║
          ║  │    capped at 100                             │   ║
          ║  └──────────────────────────────────────────────┘   ║
          ║                                                      ║
          ║  PolicyRuleSet (plug-in rules)                       ║
          ║  ┌──────────────────────────────────────────────┐   ║
          ║  │  rule_department_restriction                  │   ║
          ║  │    Sales/HR/Finance + AI + PII → ESCALATE    │   ║
          ║  │    NIST AC-3 · OWASP A01                     │   ║
          ║  │                                              │   ║
          ║  │  rule_after_hours_access                     │   ║
          ║  │    AI access outside 06:00–22:00 UTC         │   ║
          ║  │    Mon–Fri → WARNING / ALERT                 │   ║
          ║  │    NIST AU-3                                  │   ║
          ║  │                                              │   ║
          ║  │  rule_high_volume_exfiltration               │   ║
          ║  │    ≥ 4 entities in one payload → CRITICAL    │   ║
          ║  │    NIST IR-4                                  │   ║
          ║  └──────────────────────────────────────────────┘   ║
          ╚══════════════════════════╦═════════════════════════╝
                                     │
                                     │  List[PolicyAlert]
                                     ▼
          ╔════════════════════════════════════════════════════╗
          ║          STAGE 4 — ALERT OUTPUT & EXPORT            ║
          ║                                                      ║
          ║  AlertOutputter                                      ║
          ║  ┌───────────────┬─────────────┬─────────────────┐  ║
          ║  │ Terminal       │ JSON Export │ Grafana Loki    │  ║
          ║  │ (Rich / plain) │ (SIEM)      │ Push Format     │  ║
          ║  │                │             │                  │  ║
          ║  │  🔴 CRITICAL  │ alerts.json │ .loki.jsonl     │  ║
          ║  │  🟡 WARNING   │ alerts.jsonl│ /loki/api/v1/   │  ║
          ║  │  🟢 INFO      │             │ push compatible │  ║
          ║  └───────────────┴─────────────┴─────────────────┘  ║
          ║                                                      ║
          ║  Audit trail → audit.log (NIST AU-12)               ║
          ╚════════════════════════════════════════════════════╝
```

---

## Security Architecture

> The diagram below is illustrative and predates several fixes (auth,
> trusted-proxy XFF handling, path-traversal guard, sliding-window rate
> limiting). [SECURITY.md](./SECURITY.md) is the authoritative, current
> description of every control listed here.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SECURITY CONTROL LAYERS                              │
├─────────────────────────┬───────────────────────────┬───────────────────────┤
│  INPUT LAYER            │  PROCESSING LAYER         │  OUTPUT LAYER         │
│  (OWASP A05)            │  (NIST SI-4)              │  (NIST AU-3)          │
├─────────────────────────┼───────────────────────────┼───────────────────────┤
│  Pydantic strict types  │  Stateless policy engine  │  str-Enum serialise   │
│  Payload ≤ 10 KB        │  No mutable shared state  │  No raw PII in output │
│  IPv4 format guard      │  Compiled regex O(k)      │  SHA-256 log IDs      │
│  URL length ≤ 2048      │  Presidio confidence ≥0.5 │  JSONL audit trail    │
│  HTTP method allowlist  │  Graceful degradation     │  Loki-ready export    │
│  BOM stripping          │  Per-record error guard   │  GDPR [REDACTED]      │
├─────────────────────────┼───────────────────────────┼───────────────────────┤
│  NETWORK LAYER          │  RATE LIMITING            │  HEADERS              │
├─────────────────────────┼───────────────────────────┼───────────────────────┤
│  Bind: 127.0.0.1 only   │  Rolling deque window     │  X-Content-Type:      │
│  CORS: localhost only   │  100 req / 60 s           │    nosniff            │
│  TLS-ready (SC-13)      │  HTTP 429 on breach       │  X-Frame: DENY        │
│                         │  Fixed: was broken in     │  CSP: default-src     │
│                         │  original (clear() bug)   │  HSTS: 31536000s      │
└─────────────────────────┴───────────────────────────┴───────────────────────┘
```

---

## Threat Detection Matrix

| Scenario | AI Endpoint | Entity Type | Rule | Alert Level | Action |
|----------|------------|-------------|------|-------------|--------|
| Credit card → OpenAI | ✅ | CREDIT_CARD | Core policy | **CRITICAL** | BLOCK |
| SSN → Claude AI | ✅ | US_SSN | Core policy | **CRITICAL** | BLOCK |
| API key → HuggingFace | ✅ | API_KEY | Core policy | **CRITICAL** | BLOCK |
| Email → OpenAI | ✅ | EMAIL_ADDRESS | Core policy | WARNING | ALERT |
| Sales dept + any PII → AI | ✅ | Any | Dept rule | **CRITICAL** | ESCALATE |
| ≥ 4 entities → AI | ✅ | Multiple | Volume rule | **CRITICAL** | BLOCK |
| After-hours access to AI | ✅ | Any | Hours rule | WARNING | ALERT |
| Clean payload → AI | ✅ | None | Core policy | INFO | LOG |
| Any payload → GitHub | ❌ | Any | Core policy | INFO | LOG |

---

## Threat Score Model

```
score = (entity_count × 15)
      + Σ entity_type_weight
      × AI_endpoint_multiplier (×2)

capped at 100

Entity type weights:
  GENERIC_PASSWORD / API_KEY → +25
  CREDIT_CARD / US_SSN / IBAN_CODE / CRYPTO → +20
  EMAIL_ADDRESS → +10
  PHONE_NUMBER → +8
```

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt
python -m spacy download en_core_web_lg   # Presidio NLP model

# 2. (Optional but recommended before exposing the API) set an API key —
#    without this, /scan and /scan-file run UNAUTHENTICATED
export SHADOW_AI_API_KEY=$(openssl rand -hex 32)   # or put it in a .env file

# 3. Run the complete 4-stage pipeline
python main.py

# 4. Run with custom log count
python main.py --logs 5000 --output-dir ./results

# 5. Start the FastAPI detection server
python presidio_scanner.py
# → http://127.0.0.1:8000/docs

# 6. Run the test suite
pytest tests/ -v
```

---

## REST API

| Method | Path | Auth required? | Description |
|--------|------|-----------------|-------------|
| `GET` | `/health` | No | Liveness probe — Presidio status, rate limiter backend, auth status |
| `GET` | `/config` | No | Non-sensitive runtime config |
| `POST` | `/scan` | If `SHADOW_AI_API_KEY` set | Scan a JSON batch of proxy logs (`X-API-Key` header) |
| `POST` | `/scan-file` | If `SHADOW_AI_API_KEY` set | Scan a JSONL file under `SCAN_FILE_BASE_DIR` (`X-API-Key` header; path-traversal-safe) |
| `GET` | `/dashboard` | No | Live dashboard (see below) |
| `GET` | `/dashboard/stats` | No | Aggregate counts + charts data, honours the same filters as `/dashboard/alerts` |
| `GET` | `/dashboard/alerts` | No | Filtered/sorted/paginated alert list — backs the table |
| `GET` | `/dashboard/alerts/{id}` | No | Single alert detail — what makes a row "linkable" |
| `PATCH` | `/dashboard/alerts/{id}` | If `SHADOW_AI_API_KEY` set | Update incident status (NEW/ACKNOWLEDGED/RESOLVED) |
| `POST` | `/dashboard/simulate` | No | Generate N synthetic logs through the real pipeline (demo traffic button) |
| `GET` | `/docs` | No | Swagger UI |
| `GET` | `/redoc` | No | ReDoc UI |

See [SECURITY.md](./SECURITY.md) for the full authentication, rate-limiting,
and path-safety model — it is the authoritative, up-to-date reference; the
architecture diagram above is illustrative and may lag behind it.

---

## Live Dashboard

`GET /dashboard` — an interactive, dark/light-aware incident dashboard
(vendored Chart.js, no CDN dependency — keeps `Content-Security-Policy:
default-src 'self'` intact), backed by a **persistent SQLite store**
(`dashboard_store.py`, `config.DASHBOARD_DB_PATH`) so alert history and
totals survive a restart:

- **Filters** (multi-select) — severity, department, entity type, status —
  plus free-text search across user/department/destination/message, and
  sort (newest, oldest, highest score, severity). All filters apply across
  the stat tiles, charts, *and* the alert table together.
- **Linkable alert detail** — click any row to open a detail panel
  (full message, remediation, entities, threat score); the URL updates to
  `#alert=<id>`, so a specific alert has a shareable/bookmarkable link that
  reopens the same view on load.
- **Incident status workflow** — NEW → ACKNOWLEDGED → RESOLVED per alert,
  set from the detail panel.
- Sortable, paginated alert table (25/page) and a **"Generate Demo
  Traffic"** button that runs N synthetic logs through the real scan +
  policy pipeline.

`/scan` now runs every result through the same `ThreatPolicyEngine` +
`PolicyRuleSet` the CLI pipeline (`main.py`) uses — previously the REST
layer computed its own inline severity and never touched
`policy_engine.py`, so `threat_score`, remediation text, and the
department/after-hours/high-volume rules only ever fired for the CLI path.
Every `/scan` and `/scan-file` call now feeds the dashboard too.

**Auth model** (unchanged from the rest of the API — no separate dashboard
login): `GET /dashboard`, `/dashboard/stats`, `/dashboard/alerts`, and
`/dashboard/alerts/{id}` are intentionally **unauthenticated** even when
`SHADOW_AI_API_KEY` is set — they only ever surface aggregate counts,
`[REDACTED]` entity types, and demo user/department identifiers, never a
raw payload or PII value, so the live demo can be shown publicly. `PATCH
/dashboard/alerts/{id}` (status changes — a write), `/scan`, and
`/scan-file` all sit behind `X-API-Key`; set it once via the dashboard's
🔑 button (stored in `localStorage`, sent only to this origin) to use the
status workflow interactively. See [SECURITY.md](./SECURITY.md).

---

## Deployment

The repo ships a `Dockerfile`, `render.yaml`, and `.dockerignore` — see
**[DEPLOYMENT.md](./DEPLOYMENT.md)** for the exact click-through steps to
deploy to [Render](https://render.com) (free tier: connect the repo →
Render reads `render.yaml` → deploy). The default image skips the spaCy
language model (regex fallback only, fast build); `DEPLOYMENT.md` covers
enabling full Presidio NLP mode via a build arg.

The `Dockerfile` itself is platform-agnostic (reads `PORT`/`API_HOST` from
env — see `config.py`) and works the same way on Fly.io, Railway, or a
plain VM; `render.yaml` and the `TRUSTED_PROXIES=*` setting it configures
are Render-specific — re-read that setting's caveat in SECURITY.md before
reusing it elsewhere.

**Example — POST /scan:**
```json
{
  "logs": [
    {
      "timestamp":        "2026-01-15T14:32:00",
      "source_ip":        "10.0.0.12",
      "user_id":          "emp_0234",
      "department":       "Finance",
      "destination_url":  "api.openai.com",
      "http_method":      "POST",
      "path":             "/v1/chat/completions",
      "payload":          "Process refund for card 4111-1111-2222-3333",
      "response_code":    200,
      "response_time_ms": 340
    }
  ]
}
```

**Response:**
```json
{
  "total_logs_scanned": 1,
  "threats_detected":   1,
  "critical_alerts":    1,
  "results": [
    {
      "log_id":            "a3f9b2c1d4e5f6a7",
      "destination_url":   "api.openai.com",
      "entities_found": [
        {"entity_type": "CREDIT_CARD", "value": "[REDACTED]", "confidence": 0.98}
      ],
      "is_sensitive_to_ai": true,
      "severity":           "critical",
      "recommended_action": "BLOCK_AND_ALERT"
    }
  ]
}
```

---

## Project Structure

```
shadow_ai_detector/
│
├── main.py                  # Pipeline orchestrator (4-stage, timed)
├── models.py                # Single source of truth for all data contracts
├── config.py                # Pre-compiled patterns, entity weights, security config
├── presidio_scanner.py      # FastAPI app + Presidio/regex scanner + dashboard endpoints
├── presidio_recognizers.py  # Custom Presidio recognizers (API_KEY, GENERIC_PASSWORD)
├── dashboard_store.py       # In-memory rolling alert store backing /dashboard
├── policy_engine.py         # Stateless threat evaluation engine + 3 rules
├── telemetry_generator.py   # Synthetic proxy log generator
├── alert_output.py          # Terminal, JSON, JSONL, Loki export
├── requirements.txt         # Pinned, verified dependencies (full — incl. Presidio/spaCy)
├── requirements-deploy.txt  # Lean subset used by the default Docker build (no Presidio/spaCy)
├── SECURITY.md              # Authoritative security control reference
├── DEPLOYMENT.md            # Render deployment walkthrough
├── PROJECT_SUMMARY.md       # One-page narrative: what this is, how it was built
├── LICENSE                  # MIT
├── Dockerfile / render.yaml # Container build + Render Blueprint
│
├── static/                  # Dashboard frontend (vendored Chart.js, no CDN)
│   ├── dashboard.html
│   ├── dashboard.css
│   ├── dashboard.js
│   └── chart.min.js
│
├── .github/workflows/
│   └── ci.yml                # Tests + bandit/pip-audit security scan
│
├── tests/
│   └── test_pipeline.py     # Unit tests (pytest)
│
└── threat_model_output/     # Generated at runtime
    ├── proxy_logs.jsonl     # Stage 1 output
    ├── shadow_ai_alerts_*.json    # SIEM-ready JSON
    ├── shadow_ai_alerts_*.jsonl   # Line-delimited alerts
    ├── shadow_ai_alerts_*.loki.jsonl  # Grafana Loki push format
    └── audit.log            # Audit trail (NIST AU-12)
```

---

## NIST SP 800-53 Control Mapping

| Control | Description | Implementation |
|---------|-------------|----------------|
| AC-2 | Account Management | Department-scoped policy rules |
| AC-3 | Access Enforcement | AI endpoint denylist + policy engine |
| AC-4 | Information Flow | Egress PII detection pipeline |
| AU-2 | Audit Events | Every scan and alert logged |
| AU-3 | Audit Record Content | User, timestamp, entity type, action |
| AU-12 | Audit Generation | Tamper-evident `audit.log` |
| IR-4 | Incident Handling | BLOCK / ESCALATE automated actions |
| SC-7 | Boundary Protection | Localhost-only bind; CORS locked |
| SC-13 | Cryptographic Protection | TLS-ready via `cryptography` library |
| SI-4 | System Monitoring | Presidio ML-backed PII detection |

---

## Grafana Integration

Alerts export in Loki-push format out of the box:

```bash
# Push to Grafana Loki
curl -X POST http://loki:3100/loki/api/v1/push \
  -H "Content-Type: application/json" \
  --data-binary @threat_model_output/shadow_ai_alerts_*.loki.jsonl

# LogQL query for critical alerts
{job="shadow_ai_detector", threat_level="CRITICAL"} | json
```

---

## Bugs Fixed from Original

| Bug | Root Cause | Fix Applied |
|-----|-----------|-------------|
| `TypeError: AlertLevel not JSON serialisable` | `AlertLevel(Enum)` not a `str` subclass | Changed to `AlertLevel(str, Enum)` in `models.py` |
| `dict vs dataclass` crash in policy engine | Each module defined its own `ScanResult` | Single `ScanResult` in `models.py`; `to_policy_dict()` adapter |
| Presidio attribute access (`e.entity_type` vs `e["entity_type"]`) | `RecognizerResult` objects not converted to dicts | `_extract_entities()` normaliser handles both formats |
| Rate limiter never fired | `request_times.clear()` wiped list before filter | Replaced with `collections.deque` rolling-window |
| `main.py` pipeline crash — no scanner→policy conversion | `step3_apply_policies()` passed raw scan dicts to old dataclass engine | `ScanResult.to_policy_dict()` provides uniform conversion |
| Duplicate `elif` branch unreachable in `evaluate_threat` | Logic error (`is_ai and count > 0` tested twice) | Replaced with correct 4-branch decision tree |
| Regex patterns recompiled per request | Patterns defined as raw strings inside methods | All patterns compiled at module load in `config.py` |
| `scan_stream()` crashed once pending futures hit the back-pressure ceiling — the main `python main.py` path | `__import__("concurrent.futures").FIRST_COMPLETED` (no `fromlist`) resolves to the top-level `concurrent` package, not the submodule → `AttributeError` | Import `wait`/`FIRST_COMPLETED` directly in `scanner_worker.py` |
| `/scan-file` path traversal | `file_path` opened `Path(file_path)` directly, no containment check | Resolved against `config.SCAN_FILE_BASE_DIR`, rejected with `403` unless it stays inside |
| `/scan-file` 500'd on every call | Built `ScanRequest(max_logs=50_000)` against a Pydantic field capped at `le=10_000` | Capped to `min(MAX_LOGS_PER_REQUEST, 10_000)`; empty/oversized files now return a clean `400` |
| `API_KEY` / `GENERIC_PASSWORD` silently undetected by Presidio | Requested from `AnalyzerEngine` but no recognizer was ever registered for them (not Presidio built-ins) | `presidio_recognizers.py` registers `PatternRecognizer`s for both, reusing the same bounded regex as the fallback path |
| Regex fallback double-counted entities | Independent patterns matched the same/overlapping span, inflating `entity_count` and severity | `config.resolve_entity_overlaps()` makes the entity set span-disjoint (higher confidence / longer span wins) |
| Duplicate, partially-unbounded regex patterns in 3 modules | `ingestion.py` and `scanner_worker.py` each kept their own copy, including an unbounded `EMAIL_ADDRESS` pattern that backtracks catastrophically (9.4s @ 40KB adversarial payload) | Single bounded pattern set in `config.py` (`FALLBACK_PATTERNS`, `PII_QUICK_PATTERN`), imported everywhere |
| `X-Forwarded-For` rate-limit bypass | Header trusted unconditionally — a client could send a fresh fake IP per request | Only honoured when the direct TCP peer is in `config.TRUSTED_PROXIES` |
| `destination_url` rejected real proxy logs | Validator regex had no `https?://` branch | Now accepts bare hostnames and full schemed URLs |
| `/scan` could exhaust the thread pool | `asyncio.gather()` over an unbounded batch submitted every payload to `run_in_executor` at once | `asyncio.Semaphore(config.SCAN_CONCURRENCY_LIMIT)` bounds concurrent scans |
| Missing spaCy model crashed the whole module / poisoned the worker pool | `except ImportError` only — a missing language model raises `OSError` | Both `scanner_worker.py` and `presidio_scanner.py` also catch `OSError` and degrade to the regex fallback |
| `main.py --source <typo'd path>` silently scanned synthetic data, exit 0 | No existence check before falling back to `stage1_generate()` | Missing `--source` file now exits 1 with a clear error |
| Alert timestamps used host-local naive time | `datetime.now()` in `policy_engine.py` vs `datetime.utcnow()...+"Z"` everywhere else | All `PolicyAlert` timestamps are UTC, `Z`-suffixed |
| Rate limiter allowed a 2x burst across a window boundary | Pure fixed/tumbling window resets fully at each boundary | Redis limiter now weights the previous bucket by elapsed fraction (sliding-window-counter approximation) |
| `/scan` never applied the department/after-hours/volume policy rules | REST layer computed its own inline severity, never called `policy_engine.py` | `scan_logs()` now runs every result through `policy_rules.evaluate_all()`, same as the CLI pipeline |

---

## Production Hardening Checklist

- [x] Add authenticated endpoints — `X-API-Key` header, see [SECURITY.md](./SECURITY.md#authentication)
- [x] Distributed rate limiter — Redis-backed by default, deque fallback with a startup warning for single-worker-only use
- [x] Path-traversal protection on `/scan-file`
- [ ] Enable TLS: set `USE_HTTPS=True`, provide `CERT_FILE` / `KEY_FILE` in `config.py` (or terminate TLS at a reverse proxy — see [SECURITY.md](./SECURITY.md))
- [ ] Set `TRUSTED_PROXIES` to your load balancer's IP(s) before relying on `X-Forwarded-For`
- [ ] Set `API_WORKERS > 1` only after confirming stateless policy engine usage
- [ ] Forward `audit.log` to your SIEM (Splunk, Microsoft Sentinel, Elastic)
- [ ] Configure Grafana Loki push URL in CI/CD
- [ ] Run `pytest tests/ -v` in pre-deploy gate (see `.github/workflows/ci.yml`)
- [ ] Rotate `SHADOW_AI_API_KEY` periodically — there is no built-in rotation or per-caller key support yet

---

*Built for AI Security Engineering portfolio — Shadow AI detection, Microsoft Presidio, FastAPI, NIST SP 800-53, OWASP Top 10.*
