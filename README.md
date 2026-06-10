# Shadow AI Detector

A pipeline that monitors HTTP proxy logs and detects when employees send sensitive data to unsanctioned AI endpoints.

[![CI](https://github.com/singh-adi5/shadow_ai/actions/workflows/ci.yml/badge.svg)](https://github.com/singh-adi5/shadow_ai/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## The problem

Most companies have a data handling policy. Very few have visibility into whether employees are following it when using AI tools.

Someone in Finance pastes customer card details into ChatGPT to speed up a task. Someone in HR drops employee records into Claude to reformat a spreadsheet. Neither is trying to cause a breach. Both just created one.

Traditional DLP tools watch for data going to file-sharing services, personal email, USB drives. They were not built for a world where employees have direct API access to a dozen AI services. The gap between what leaves the network and what security teams can see has widened considerably.

This project is a working attempt to close that gap for outbound AI traffic.

---

## What it does

Scans outbound HTTP proxy logs for PII in payloads destined for AI endpoints, applies a policy rule set, and emits structured alerts.

When a log entry like this arrives:

```
emp_0234 | Finance | api.openai.com | POST
"Process refund for card 4111-1111-2222-3333, customer: jane.smith@corp.com"
```

The pipeline produces:

```json
{
  "threat_level": "CRITICAL",
  "action": "BLOCK",
  "entity_types": ["CREDIT_CARD", "EMAIL_ADDRESS"],
  "threat_score": 100,
  "department": "Finance",
  "remediation": "Block egress. Notify CISO. Preserve pcap. Review entitlements."
}
```

Alerts export to JSON, JSONL, or Grafana Loki push format for SIEM ingestion.

---

## Pipeline

```
HTTP Proxy Logs (JSONL)
        │
        ▼
┌───────────────────────────────────────────────────┐
│  Ingestion                                         │
│  stream_jsonl() — line by line, O(1) heap          │
│  Pre-filter: regex on raw string before parsing    │
│  Drops clean records before any NLP is invoked     │
└──────────────────────┬────────────────────────────┘
                       │ AI-endpoint or PII-bearing records only
                       ▼
┌───────────────────────────────────────────────────┐
│  Scanner worker pool                               │
│  ProcessPoolExecutor — separate OS processes       │
│  Presidio AnalyzerEngine initialised once per      │
│  worker, not once per record                       │
│  scan_record() is a pure function, no shared state │
└──────────────────────┬────────────────────────────┘
                       │ Normalised entity dicts
                       ▼
┌───────────────────────────────────────────────────┐
│  Data contract layer  (models.py)                  │
│  Single ScanResult definition across all stages    │
│  to_policy_dict() adapter — Pydantic → policy dict │
└──────────────────────┬────────────────────────────┘
                       │
                       ▼
┌───────────────────────────────────────────────────┐
│  Policy engine                                     │
│  Stateless — no instance state after __init__      │
│  Three rules: department, after-hours, volume      │
│  Threat score 0–100                                │
└──────────────────────┬────────────────────────────┘
                       │ List[PolicyAlert]
                       ▼
┌───────────────────────────────────────────────────┐
│  Output                                            │
│  Terminal · JSON · JSONL · Grafana Loki            │
└───────────────────────────────────────────────────┘
```

**REST API** (`presidio_scanner.py`)

| Method | Path | Notes |
|--------|------|-------|
| POST | `/scan` | Batch scan. Presidio offloaded via `run_in_executor` — event loop never blocked |
| POST | `/scan-file` | JSONL file ingestion |
| GET | `/health` | Returns Presidio status and rate limiter backend |
| GET | `/docs` | Swagger UI |

Rate limiting uses Redis `INCR`/`EXPIRE` shared across all uvicorn workers. Falls back to an in-process deque with a startup warning if Redis is unavailable.

---

## Detection rules

| Scenario | Entity type | Rule | Alert | Action |
|----------|------------|------|-------|--------|
| Credit card → OpenAI | CREDIT_CARD | Core | CRITICAL | BLOCK |
| SSN → Claude | US_SSN | Core | CRITICAL | BLOCK |
| API key → HuggingFace | API_KEY | Core | CRITICAL | BLOCK |
| Email address → any AI endpoint | EMAIL_ADDRESS | Core | WARNING | ALERT |
| Sales / HR / Finance + any PII → AI | Any | Department | CRITICAL | ESCALATE |
| ≥ 4 entities in one payload → AI | Multiple | Volume | CRITICAL | BLOCK |
| AI endpoint access outside 06:00–22:00 UTC | Any | After-hours | WARNING | ALERT |
| Clean payload → AI endpoint | None | Core | INFO | LOG |

Threat score: `(entity_count × 15) + Σ entity_weights × 2` if AI endpoint, capped at 100.

---

## Scope

This is a working detection pipeline, not a full DLP product. The current implementation covers explicit PII in individual payloads. It does not attempt behavioural detection across sessions, obfuscated PII, or semantic leakage. The AI endpoint list is a static compiled set — in production this would be replaced with a threat intelligence feed. Alerts persist to files; a time-series store would be the addition for historical querying.

The deployed demo runs in regex-fallback mode (no Presidio/spaCy) to fit within free-tier RAM. The `/health` endpoint reports `presidio_active: false` in that configuration. Full Presidio detection requires `requirements.txt` and `python -m spacy download en_core_web_lg`.

---

## Security controls

**NIST SP 800-53**

| Control | Implementation |
|---------|----------------|
| AC-3 | AI endpoint denylist enforced at policy layer |
| AC-4 | Egress PII detection across all monitored AI endpoints |
| AU-3 | User, timestamp, entity type, action, score in every alert |
| IR-4 | Automated BLOCK / ESCALATE with remediation instructions |
| SC-5 | O(1) streaming ingestion, 10 KB payload cap, Redis rate limit |
| SC-7 | API binds to localhost by default; CORS locked to known origins |
| SI-4 | Presidio NLP + bounded regex PII detection |

**OWASP Top 10 (2021)**

| Risk | Implementation |
|------|----------------|
| A03 Injection | Pydantic v2 strict schema at ingestion boundary — IP, URL, method, payload size |
| A04 Insecure Design | ReDoS-safe patterns (bounded quantifiers, verified < 0.05ms); stateless engine |
| A05 Misconfiguration | Centralised config; security headers on every response via middleware |
| A07 Auth Failures | Redis sliding-window rate limit per client IP, shared across workers |
| A09 Logging Failures | Structured JSONL audit trail; `AlertLevel(str, Enum)` for native JSON serialisation |

---

## Quick start

```bash
git clone https://github.com/singh-adi5/shadow_ai.git
cd shadow_ai

# Full install (includes Presidio + spaCy NLP model ~800 MB)
pip install -r requirements.txt
python -m spacy download en_core_web_lg

# Run the pipeline
python main.py

# Start the API server
python presidio_scanner.py
# → http://127.0.0.1:8000/docs

# Tests
pytest tests/ -v
```

**Lightweight install (regex fallback, no spaCy):**

```bash
pip install -r requirements-deploy.txt
python presidio_scanner.py
```

**Docker:**

```bash
docker build -t shadow-ai-detector .
docker run -p 8000:8000 shadow-ai-detector
```

**Deploy to Render (free tier):** Fork the repo, connect to [render.com](https://render.com), `render.yaml` is auto-detected.

---

## Project structure

```
shadow_ai/
├── main.py                  # Pipeline orchestrator
├── models.py                # Data contracts — single source of truth
├── config.py                # Pre-compiled patterns, entity weights, security config
├── presidio_scanner.py      # FastAPI app
├── policy_engine.py         # Stateless policy engine + rules
├── ingestion.py             # O(1) streaming ingestion + pre-filter
├── scanner_worker.py        # ProcessPoolExecutor worker pool
├── telemetry_generator.py   # Synthetic log generator
├── alert_output.py          # Alert formatting and export
├── dashboard.html           # Standalone SOC dashboard
├── requirements.txt         # Full dependencies
├── requirements-deploy.txt  # Lightweight deploy dependencies
├── Dockerfile
├── render.yaml
└── tests/
    └── test_pipeline.py     # 58 tests
```

---

## What was debugged and fixed

| Bug | Root cause | Fix |
|-----|-----------|-----|
| `TypeError: AlertLevel not JSON serialisable` | `Enum` not a `str` subclass | `AlertLevel(str, Enum)` |
| Pipeline crashes at stage boundaries | Three modules each defined their own `ScanResult` | Single definition in `models.py` |
| `entity["entity_type"]` AttributeError | Presidio returns objects, not dicts | `_extract_entities()` normaliser |
| Rate limiter never triggered | `.clear()` wiped the deque before filtering | Rolling deque with correct eviction |
| Event loop blocked during NLP inference | `analyze()` called inside `async def` | `run_in_executor` offload |
| Multi-worker rate limit bypass | `deque` is per-process memory | Redis `INCR`/`EXPIRE` atomic counter |
| ReDoS on email/CC patterns | Unbounded `+` on overlapping character classes | Bounded `{min,max}` quantifiers |
| O(N) heap on large log files | `json.load()` materialises entire file | Line-by-line streaming generator |

---

## License

MIT
