# Shadow AI Detector

Enterprise data leakage prevention pipeline that detects employees transmitting
sensitive PII to unsanctioned AI endpoints (OpenAI, Claude, HuggingFace, Gemini).

[![CI](https://github.com/singh-adi5/shadow-ai-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/singh-adi5/shadow-ai-detector/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![NIST SP 800-53](https://img.shields.io/badge/NIST-SP%20800--53-003087.svg)](#nist-control-mapping)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Top%2010-cc0000.svg)](#owasp-guardrails)
[![58 tests](https://img.shields.io/badge/tests-58%20passing-brightgreen.svg)](tests/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## What it does

When an employee sends a payload like this to `api.openai.com`:

```
"Process refund for card 4111-1111-2222-3333, customer: jane.smith@corp.com"
```

The pipeline detects it, scores it, and emits a structured alert:

```json
{
  "alert_id": "ALERT-emp_0234-1748823600000",
  "threat_level": "CRITICAL",
  "action": "BLOCK",
  "entity_types": ["CREDIT_CARD", "EMAIL_ADDRESS"],
  "threat_score": 100,
  "destination_url": "api.openai.com",
  "department": "Finance",
  "remediation": "Block egress. Notify CISO. Preserve pcap. Review entitlements."
}
```

Alerts export to JSON, JSONL, or Grafana Loki push format for SIEM ingestion.

---

## Architecture

```
HTTP Proxy Logs (JSONL)
        │
        ▼
┌───────────────────────┐
│  Ingestion layer       │  stream_jsonl() — line-by-line, O(1) heap
│  ingestion.py          │  Two-stage pre-filter drops clean traffic
└──────────┬────────────┘  before Presidio is ever invoked
           │ AI-endpoint or PII-like records only
           ▼
┌───────────────────────┐
│  Scanner worker pool   │  ProcessPoolExecutor — GIL bypassed
│  scanner_worker.py     │  Presidio AnalyzerEngine init once per process
└──────────┬────────────┘  scan_record() is a pure function, no shared state
           │ Normalised entity dicts
           ▼
┌───────────────────────┐
│  Data contract layer   │  models.py — single source of truth
│  models.py             │  ScanResult · EntityDetection · AlertLevel
└──────────┬────────────┘  to_policy_dict() adapter between stages
           │ ScanResult (Pydantic)
           ▼
┌───────────────────────┐
│  Policy engine         │  Stateless — safe for concurrent execution
│  policy_engine.py      │  3 rules: dept restriction, after-hours, volume
└──────────┬────────────┘  Threat score 0–100 (NIST risk model)
           │ List[PolicyAlert]
           ▼
┌───────────────────────┐
│  Alert output          │  Terminal · JSON · JSONL · Grafana Loki
│  alert_output.py       │
└───────────────────────┘

FastAPI (presidio_scanner.py)
  POST /scan      — async, run_in_executor offload
  POST /scan-file — JSONL file ingestion
  GET  /health    — liveness probe
  Redis rate limiter — shared across all uvicorn workers (per-IP)
```

---

## What we built across four revision cycles

The project started from a broken AI-generated scaffold and was systematically hardened through four rounds of architecture review and production-gap analysis. Here is what each cycle addressed.

**v1 → v2: Fixing what was broken**

The original code had four categories of failure. `AlertLevel` was a plain `Enum`, not a `str` subclass — `json.dumps()` raised `TypeError` on every alert export. Three modules each defined their own `ScanResult` class independently, so `presidio_scanner.py` returned Pydantic objects, `policy_engine.py` expected dataclasses, and `main.py` passed raw dicts — the pipeline crashed at every stage boundary. Presidio's `RecognizerResult` is an object with `.entity_type` as an attribute, but the code accessed it as `entity["entity_type"]` — a dict lookup on a non-dict. The rate limiter called `request_times.clear()` unconditionally before the filter, wiping itself on every request so it never triggered.

All four were root-cause fixed: `AlertLevel(str, Enum)` for native JSON serialisation; a single `models.py` as the data contract layer across all stages; a `_extract_entities()` normaliser that handles both objects and dicts; and a `collections.deque` rolling-window rate limiter.

**v2 → v3: Fixing production-scale gaps**

A senior architecture review identified three gaps that would cause failure under real load. The entire dataset was being materialised into heap memory via `json.load()` — O(N) allocation, GC pauses, OOM-killer risk on multi-GB enterprise log files. Presidio's NLP was running in a sequential `for` loop, saturating one CPU core while the rest sat idle. The policy engine tracked state in instance variables, making it unsafe for concurrent execution.

These were fixed with: a line-by-line JSONL streaming generator (`stream_jsonl()`) with a two-stage regex pre-filter that drops clean traffic before parsing; a `ProcessPoolExecutor` worker pool where Presidio's `AnalyzerEngine` is initialised once per worker process via the pool initialiser (not once per record); and a stateless `ThreatPolicyEngine` where every method reads only its arguments and module-level compiled constants.

**v3 → v4: Fixing deployment-layer gaps**

A second review identified three gaps specific to the FastAPI layer. Presidio's `AnalyzerEngine.analyze()` was being called directly inside `async def scan_logs()`, blocking the entire asyncio event loop during NLP inference — all other connections stall. The regex patterns used unbounded quantifiers on overlapping character classes, creating a ReDoS vector: a 100-byte crafted input could stall the regex engine for seconds. The rate limiter used `collections.deque` in process memory, meaning with `uvicorn --workers 4`, four separate counters exist — a client can bypass the limit by distributing requests across workers.

These were fixed with: `run_in_executor(None, _sync_scan, payload)` to offload Presidio to a `ThreadPoolExecutor` thread while the event loop stays free; bounded quantifiers (`{min,max}`) on all patterns, verified at < 0.05ms worst-case against adversarial inputs; and a Redis `INCR`/`EXPIRE` sliding-window counter shared across all worker processes, with in-process deque fallback and an explicit startup warning.

---

## Where the architecture is strong

**The data contract layer is the most important decision in the codebase.** A single `models.py` defines every type used across all pipeline stages. There is no ambiguity about what flows between components. The `to_policy_dict()` adapter on `ScanResult` provides a clean transformation between the Pydantic layer (external I/O) and the policy engine (internal logic). This pattern — strict types at boundaries, explicit adapters between layers — is what prevents interface-mismatch bugs from propagating silently.

**The stateless policy engine is correct for scale.** Because `ThreatPolicyEngine` holds no mutable state after `__init__`, it can be called from any number of concurrent threads, asyncio tasks, or worker processes without locks or synchronisation. The test `test_engine_has_no_instance_state_after_evaluation` compares `engine.__dict__` before and after 500 concurrent calls and asserts they are identical. This is not a cosmetic test — it guards a real invariant.

**The two-stage ingestion pre-filter is the right architecture for CPU budget.** Running Presidio's spaCy NLP on every record is expensive. The pre-filter runs a compiled regex against the raw JSON string before parsing — zero heap allocation, zero Pydantic overhead, zero Presidio invocation for clean traffic. In a typical enterprise log stream where 20–40% of records involve neither an AI endpoint nor PII, this avoids a significant fraction of the total inference cost.

**The ProcessPoolExecutor worker initialiser pattern is non-obvious and correct.** The `_worker_init()` function runs once when each worker process starts, constructing `AnalyzerEngine()` and storing it in a module-level variable. Without this, the 2–4 second Presidio startup cost would be paid on every `scan_record()` call — a 1000× performance regression. With it, the cost is amortised once per pool lifetime. Most engineers who add multiprocessing to a project miss this.

**The ReDoS analysis is genuine, not cosmetic.** The v3 patterns contained `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}` — an email pattern with unbounded `+` on overlapping character classes. This has known exponential backtracking behaviour. The v4 patterns decompose the same detection into bounded segments: `{1,64}` for the local part, `{1,63}` per domain label, `{0,4}` for label repetition. Worst-case timing is verified in the test suite against adversarial inputs.

---

## Scope and known extension points

This is a working detection pipeline, not a full DLP product. The following are deliberate scope decisions — each one has a clear production path if needed.

**Persistence.** Alerts export to JSONL and Grafana Loki. A production deployment would add a time-series store (InfluxDB, TimescaleDB) for historical querying and a relational store for per-user threat history. The stateless pipeline design makes that addition straightforward — the output layer is the only thing that changes.

**Detection model.** The pipeline detects explicit PII tokens in individual payloads using Presidio's NLP and a regex fallback. Extending to behavioural detection — gradual exfiltration across many clean requests, obfuscated PII, semantic leakage — would require session-level correlation and a separate aggregation layer upstream of the policy engine.

**Endpoint coverage.** AI domain patterns are compiled from a static list in `config.py`. In production this would be replaced with a feed from a threat intelligence source to cover new providers, self-hosted models, and corporate AI gateways as they emerge.

**Rate limiter identity.** The Redis counter currently keys on client IP. Behind a corporate proxy or NAT, keying on authenticated user identity is the correct production approach. The Redis layer makes that a one-line key change.

**Integration tests.** Component tests cover 58 cases. End-to-end tests that spin up the FastAPI app via `httpx.AsyncClient` and exercise the full middleware stack are the natural next addition to the test suite.

---

## Threat detection matrix

| Scenario | AI Endpoint | Entity | Rule | Alert | Action |
|----------|------------|--------|------|-------|--------|
| Credit card → OpenAI | ✅ | CREDIT_CARD | Core | CRITICAL | BLOCK |
| SSN → Claude AI | ✅ | US_SSN | Core | CRITICAL | BLOCK |
| API key → HuggingFace | ✅ | API_KEY | Core | CRITICAL | BLOCK |
| Email → OpenAI | ✅ | EMAIL_ADDRESS | Core | WARNING | ALERT |
| Sales / HR / Finance + PII → AI | ✅ | Any | Dept rule | CRITICAL | ESCALATE |
| ≥ 4 entities in one payload → AI | ✅ | Multiple | Volume rule | CRITICAL | BLOCK |
| After-hours AI access (UTC 22:00–06:00, weekends) | ✅ | Any | Hours rule | WARNING | ALERT |
| Clean payload → AI endpoint | ✅ | None | Core | INFO | LOG |
| Any payload → non-AI endpoint | ❌ | Any | Core | INFO | LOG |

---

## Threat score model

```
score = (entity_count × 15)
      + Σ entity_type_weight
      × AI_endpoint_multiplier (×2 if destination is an AI endpoint)
      capped at 100

Weights:
  GENERIC_PASSWORD / API_KEY  → +25
  CREDIT_CARD / US_SSN        → +20
  IBAN_CODE / CRYPTO          → +20
  EMAIL_ADDRESS               → +10
  PHONE_NUMBER                → +8
```

---

## NIST control mapping

| Control | Title | Implementation |
|---------|-------|----------------|
| AC-2 | Account Management | Department-scoped policy rules |
| AC-3 | Access Enforcement | AI endpoint denylist in policy engine |
| AC-4 | Information Flow | Egress PII detection across all AI endpoints |
| AU-2 | Audit Events | Every scan request and alert logged |
| AU-3 | Audit Record Content | User, timestamp, entity type, action, score |
| AU-12 | Audit Generation | Structured JSONL audit trail |
| IA-2 | Authentication | Redis rate limiting prevents enumeration |
| IR-4 | Incident Handling | Automated BLOCK / ESCALATE with remediation |
| SC-5 | DoS Protection | O(1) ingestion, bounded payloads, Redis rate limit |
| SC-7 | Boundary Protection | Localhost-only default; CORS locked |
| SC-13 | Cryptographic Protection | TLS-ready; SHA-256 log fingerprinting |
| SI-4 | System Monitoring | Presidio ML + regex PII detection |

---

## OWASP guardrails

| Control | Risk | Implementation |
|---------|------|----------------|
| A01 | Broken Access Control | Department-scoped rules; endpoint denylist |
| A03 | Injection | Pydantic strict validation at ingestion boundary |
| A04 | Insecure Design | ReDoS-safe patterns; stateless engine; secure defaults |
| A05 | Security Misconfiguration | Centralised config; security headers middleware |
| A07 | Auth Failures | Redis rate limiting per IP (multi-worker safe) |
| A09 | Logging Failures | Structured audit log; str-Enum native serialisation |

---

## Quick start

```bash
git clone https://github.com/singh-adi5/shadow-ai-detector.git
cd shadow-ai-detector

pip install -r requirements.txt
python -m spacy download en_core_web_lg

# Run the full 4-stage pipeline
python main.py

# Start the FastAPI server
python presidio_scanner.py
# → http://127.0.0.1:8000/docs

# Run tests
pytest tests/ -v
```

**Demo mode (no Presidio required):**

```bash
pip install -r requirements-deploy.txt
python presidio_scanner.py
# Regex fallback active — covers CREDIT_CARD, EMAIL_ADDRESS, US_SSN, API_KEY
```

**Docker:**

```bash
docker build -t shadow-ai-detector .
docker run -p 8000:8000 shadow-ai-detector
```

---

## Deploy to Render (free)

1. Fork this repo
2. Go to [render.com](https://render.com) → New Web Service → Connect repo
3. `render.yaml` is auto-detected — click Deploy
4. Your live API: `https://shadow-ai-detector.onrender.com/docs`
5. Open `dashboard.html` in a browser, set the URL, click Ping

---

## Project structure

```
shadow-ai-detector/
├── main.py                 # Pipeline orchestrator (4-stage, timed)
├── models.py               # Single data contract layer
├── config.py               # Pre-compiled patterns, weights, security config
├── presidio_scanner.py     # FastAPI app (async scan, Redis rate limiter)
├── policy_engine.py        # Stateless policy engine + 3 rules
├── ingestion.py            # O(1) JSONL streaming + pre-filter
├── scanner_worker.py       # ProcessPoolExecutor worker pool
├── telemetry_generator.py  # Synthetic proxy log generator
├── alert_output.py         # JSON / JSONL / Grafana Loki export
├── dashboard.html          # Standalone SOC dashboard (no server required)
├── requirements.txt        # Full dependencies (includes Presidio + spaCy)
├── requirements-deploy.txt # Lightweight deploy (regex fallback only)
├── Dockerfile
├── render.yaml
└── tests/
    └── test_pipeline.py    # 58 pytest tests
```

---

## Bugs fixed from the original scaffold

| Bug | Root cause | Fix |
|-----|-----------|-----|
| `TypeError: AlertLevel not JSON serialisable` | `Enum` not a `str` subclass | `AlertLevel(str, Enum)` |
| Pipeline crashes at every stage boundary | Three modules each defined their own `ScanResult` | Single `ScanResult` in `models.py` |
| `entity["entity_type"]` AttributeError | Presidio returns objects, not dicts | `_extract_entities()` normaliser |
| Rate limiter never triggered | `.clear()` wiped deque before the filter ran | Rolling `deque` with correct eviction logic |
| Event loop blocked during NLP inference | `_analyzer.analyze()` called inside `async def` | `run_in_executor` offload to thread pool |
| Multi-worker rate limit bypass | `deque` is per-process, not shared | Redis `INCR`/`EXPIRE` atomic counter |
| ReDoS on email/CC regex patterns | Unbounded `+` on overlapping character classes | Bounded `{min,max}` quantifiers, verified < 0.05ms |
| O(N) heap on large log files | `json.load()` materialises entire file | `stream_jsonl()` line-by-line generator |

---

## License

MIT
