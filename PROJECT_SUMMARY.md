# Shadow AI Detector — Project Summary

## What this project is

Shadow AI Detector is an enterprise data leakage prevention (DLP) pipeline built to detect employees transmitting sensitive PII — credit cards, SSNs, API keys, passwords — to unsanctioned AI endpoints. It was built across four revision cycles, starting from a broken AI-generated scaffold and hardened through successive rounds of architecture review, production-gap analysis, and explicit feedback from senior engineers.

The system has a FastAPI REST layer, a four-stage detection pipeline, a stateless policy engine with three built-in rules, and alert export to JSON, JSONL, and Grafana Loki format. A standalone SOC dashboard at `dashboard.html` makes system behaviour visible without running any code.

---

## The problem it solves

Most enterprise environments have no visibility into which AI endpoints employees are accessing or what data they are sending. Shadow AI — the use of unsanctioned AI tools — creates a data leakage surface that is not covered by traditional DLP tools, which inspect known destination categories like file-sharing services or personal email. As AI API adoption has accelerated, the gap between what employees send and what security teams can see has widened.

This pipeline addresses that gap: it monitors HTTP proxy logs, identifies requests destined for AI endpoints, scans the payload for PII using Microsoft Presidio, applies a policy rule set, and emits structured alerts with severity levels and remediation instructions.

---

## How it was built

**Starting point.** The original scaffold was AI-generated Python that had four categories of failure: a broken JSON serialiser (`AlertLevel` was not a `str` subclass), three independent `ScanResult` definitions across three modules that were mutually incompatible, Presidio entity access using dict syntax on objects that are not dicts, and a rate limiter that wiped itself on every request. None of these were minor bugs — they caused the pipeline to crash before producing a single alert.

**Fixing the foundations (v2).** The data contract issue was fixed by creating `models.py` as the single source of truth for all types. `AlertLevel(str, Enum)` fixed native JSON serialisation. A `_extract_entities()` normaliser handles both Presidio objects and plain dicts uniformly. The rate limiter was rebuilt with a correct `collections.deque` rolling window.

**Addressing production-scale gaps (v3).** A senior architecture review identified three gaps that the unit tests could not catch. The ingestion layer was loading entire files into heap memory — `json.load()` on a 50 GB enterprise log file causes OOM-killer termination. Presidio was running sequentially in a `for` loop, saturating one CPU core with Python's GIL preventing any parallelism. The policy engine held mutable instance state, making it unsafe for concurrent execution. These were addressed with a streaming `stream_jsonl()` generator with a two-stage pre-filter, a `ProcessPoolExecutor` worker pool with Presidio initialised once per worker process, and a fully stateless `ThreatPolicyEngine`.

**Hardening the API layer (v4).** A second round of review identified three gaps in the FastAPI layer. Presidio was being called directly inside `async def scan_logs()`, blocking the asyncio event loop during NLP inference. The regex patterns used unbounded quantifiers with overlapping character classes — a ReDoS vector. The rate limiter used `collections.deque` in process memory, which is bypassed by distributing requests across multiple uvicorn workers. These were fixed with `run_in_executor` for event loop safety, bounded `{min,max}` quantifiers across all patterns, and a Redis `INCR`/`EXPIRE` sliding-window counter shared across all worker processes.

**Deployment surface (final).** The API host was hardcoded to `127.0.0.1`, making it unreachable from any cloud platform. A `Dockerfile`, `render.yaml`, and `requirements-deploy.txt` (omitting Presidio for free-tier RAM constraints) were added to support one-click deployment to Render. `dashboard.html` — a standalone 994-line file with no server dependency — provides a public demonstration surface.

---

## Architectural decisions: what is good

**Single data contract layer.** `models.py` defines every type used across all pipeline stages. The `to_policy_dict()` adapter on `ScanResult` provides a clean boundary between the Pydantic layer (external I/O) and the policy engine (internal logic). This eliminates an entire category of runtime crashes that come from interface mismatch between components built independently.

**Stateless policy engine.** `ThreatPolicyEngine` holds no mutable state after `__init__`. Every method reads only its arguments and module-level compiled constants. The thread-safety test validates this with 500 concurrent calls, comparing `engine.__dict__` before and after. This design means the engine can be called from any number of concurrent threads, asyncio tasks, or OS processes without locks or synchronisation primitives.

**Worker initialiser pattern.** In `scanner_worker.py`, `_worker_init()` constructs `AnalyzerEngine()` once when each OS process starts and stores it in a module-level variable. Without this, Presidio's 2–4 second startup cost would be paid on every `scan_record()` call. The pool initialiser is the correct mechanism for expensive, one-time setup in `ProcessPoolExecutor` workers.

**Genuinely bounded regex patterns.** The ReDoS analysis is not cosmetic. The v3 email pattern had a known-vulnerable structure. The v4 replacement decomposes it into bounded segments verified at < 0.05ms worst-case. The test suite includes adversarial inputs specifically targeting exponential backtracking.

**Pre-filter before inference.** Running Presidio's NLP on every record is expensive. The pre-filter runs a compiled regex against the raw JSON string before parsing — no heap allocation, no Pydantic overhead, no Presidio call. This is the right architecture for a pipeline where clean traffic is the majority case.

---

## Architectural decisions: what is limited

**No persistence layer.** There is no database. Alerts are written to files. The system has no memory between runs, no ability to query historical alerts, no way to track per-user threat history, and no mechanism for alert aggregation or deduplication across time. This is the single biggest gap between this system and a production DLP deployment.

**Pattern-based detection only.** The system detects explicit PII tokens in individual payloads. It cannot detect gradual exfiltration across many requests (each individually clean), obfuscated PII, or semantic leakage where sensitive information is described but not literally present. Session-level correlation across requests is not implemented.

**Static AI endpoint denylist.** Seven domain patterns are hardcoded in `config.py`. New providers, self-hosted models, and corporate AI gateways are not covered. A production deployment would need this fed from an external threat intelligence source.

**Rate limiter keyed on IP, not identity.** Behind a corporate proxy or NAT, many users share one IP. The rate limit becomes a shared bucket. A production system would key on authenticated user identity. This is acknowledged in the `SECURITY.md` but not implemented.

**Regex fallback in demo mode misrepresents detection capability.** The deployed version omits Presidio to fit within free-tier RAM constraints. The regex fallback covers six common PII types but misses the contextual entities that spaCy's NLP catches. The `/health` endpoint reports `presidio_active: false`, but a recruiter testing the live API is seeing a reduced version of the detection capability.

**No integration tests for the FastAPI layer.** The 58 tests validate pipeline components in isolation. There are no end-to-end tests that spin up the application via `httpx.AsyncClient` and send real HTTP requests through middleware, rate limiter, and scan endpoint together.

---

## Honest score

The architecture review across development gave these assessments at each stage:

| Dimension | After v2 | After v3 | After v4 |
|-----------|----------|----------|----------|
| Architecture clarity | 9.0/10 | 9.0/10 | 9.0/10 |
| Execution readiness | 7.0/10 | 7.5/10 | 8.0/10 |
| Senior signal | 8.5/10 | 8.5/10 | 8.5/10 |

The architecture clarity score is high and stable because the structural decisions — data contract layer, stateless engine, streaming ingestion, worker pool — are genuinely strong. The execution readiness score is bounded by the absence of a persistence layer, no integration tests, and the reduced detection capability in demo mode. These are real limitations, not things that were missed.

The senior signal score reflects: debugging a non-trivial runtime issue (rate limiter), choosing the right fix over the common wrong one (`str` Enum instead of custom encoder), applying the worker initialiser pattern correctly, and documenting architecture tradeoffs honestly rather than claiming the system is more capable than it is.

---

## Tech stack

| Layer | Technology |
|-------|-----------|
| API | FastAPI + Uvicorn |
| PII detection | Microsoft Presidio + spaCy `en_core_web_lg` |
| Schema validation | Pydantic v2 |
| Parallelism | `ProcessPoolExecutor` (GIL bypass) |
| Rate limiting | Redis sliding-window (in-process fallback) |
| Observability | Grafana Loki + JSONL audit log |
| Testing | pytest (58 tests) |
| CI | GitHub Actions (Python 3.11 + 3.12) |
| Deployment | Docker + Render |
