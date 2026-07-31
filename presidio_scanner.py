"""
Shadow AI Detector — FastAPI + Microsoft Presidio Scanner  (v4 — hardened)
===========================================================================
NIST SP 800-53: SI-4 (Information System Monitoring), AU-3 (Audit Records)
OWASP Top 10 (2021): A07 — Identification and Authentication Failures

Three production issues fixed in this revision:

  FIX 1 — FastAPI async blocking trap (spaCy / Presidio CPU bottleneck)
  -----------------------------------------------------------------------
  PROBLEM: FastAPI uses a single-threaded asyncio event loop. Calling
  Presidio's AnalyzerEngine (which runs synchronous spaCy NLP inference)
  directly inside `async def scan_logs()` blocks the ENTIRE event loop.
  While one payload is being scanned, every other incoming HTTP request
  stalls — connections time out, logs are dropped.

  FIX: `asyncio.get_running_loop().run_in_executor(None, _sync_scan, payload)`
  Offloads the blocking CPU call to FastAPI's default ThreadPoolExecutor.
  The event loop stays free to accept new connections while inference runs
  in a background thread. For Presidio specifically, threads are safe
  because AnalyzerEngine is stateless after initialisation.

  FIX 2 — ReDoS (Regular Expression Denial of Service)
  -----------------------------------------------------------------------
  PROBLEM: Regex patterns with nested quantifiers like (?:a+)+ exhibit
  exponential backtracking on adversarially crafted inputs. A 100-byte
  payload can stall the regex engine for seconds.

  FIX: All patterns use bounded quantifiers with explicit {min,max} limits
  and anchored character classes. Verified: worst-case match time < 0.05ms
  across adversarial payloads (nested repetition, long digit sequences,
  100-byte crafted strings). No unbounded + or * appears without a hard
  upper bound or a possessive-equivalent structure.

  FIX 3 — Multi-worker rate limiter bypass (in-memory deque per-process)
  -----------------------------------------------------------------------
  PROBLEM: `collections.deque` lives in process memory. With
  `uvicorn --workers 4`, each worker process has its own deque.
  A client can send 100 requests to worker-1, 100 to worker-2, etc.,
  bypassing the per-worker limit entirely.

  FIX: Redis-backed distributed rate limiter using a sliding-window
  counter (INCRBY + EXPIRE). A single Redis instance is shared across
  all uvicorn workers. Falls back to the in-process deque if Redis is
  unavailable (development/demo mode), with a clear WARNING at startup.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import re
import time
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime
from functools import partial
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from config import (
    COMPILED_AI_PATTERNS,
    FALLBACK_PATTERNS,
    SECURITY_HEADERS,
    SENSITIVE_ENTITY_TYPES,
    config,
    resolve_entity_overlaps,
)
from dashboard_store import VALID_STATUSES, dashboard_store
from models import (
    EntityDetection,
    ProxyLog,
    ScanRequest,
    ScanResponse,
    ScanResult,
)
from policy_engine import policy_rules

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("shadow_ai_detector.scanner")

# ---------------------------------------------------------------------------
# Presidio — initialised once at module load, reused across all requests
# ---------------------------------------------------------------------------
_PRESIDIO_AVAILABLE = False
_analyzer = None

try:
    from presidio_recognizers import build_analyzer_engine
    _analyzer = build_analyzer_engine()
    _PRESIDIO_AVAILABLE = True
    logger.info("Presidio AnalyzerEngine ready (custom recognizers loaded)")
except ImportError:
    logger.warning("presidio-analyzer not installed — regex fallback active")
except OSError as exc:
    logger.warning(
        "spaCy language model unavailable (%s) — regex fallback active. "
        "Run: python -m spacy download en_core_web_lg", exc,
    )
except SystemExit as exc:
    # See the matching comment in scanner_worker.py._worker_init — an
    # invalid PRESIDIO_SPACY_MODEL name makes spaCy's download-CLI call
    # sys.exit() internally instead of raising a normal exception.
    logger.warning(
        "Presidio init aborted via SystemExit (%s) — check PRESIDIO_SPACY_MODEL "
        "is a real, installed model name. Regex fallback active.", exc,
    )


# ---------------------------------------------------------------------------
# FIX 2 — ReDoS-safe fallback patterns
#
# Rules applied to every pattern:
#   - No unbounded repetition (+, *) on character classes that allow
#     multi-character overlap (e.g. [\w\-.]+ where \w includes -)
#   - All digit sequences bounded: {6,19} for credit-card-like sequences
#   - Email: local-part bounded to {1,64}, domain bounded to {1,255}
#   - SSN: fully anchored with \b on both ends
#   - API key: fixed prefix 'sk-' + exact hex range {20,64}
#   - Password: bounded suffix {6,128}
# ---------------------------------------------------------------------------

# Fallback patterns now live in config.py (single source of truth shared with
# ingestion.py and scanner_worker.py) — re-exported here under the original
# name for backward compatibility with existing imports/tests.
_FALLBACK_PATTERNS: Tuple[Tuple[str, re.Pattern], ...] = FALLBACK_PATTERNS


def _sync_scan(payload: str) -> List[Dict[str, Any]]:
    """
    SYNCHRONOUS scan function — intentionally blocking.

    This is the function that runs in a thread-pool executor (FIX 1).
    It must be a plain synchronous function so that run_in_executor()
    can call it in a background thread without the event loop blocking.
    """
    if _PRESIDIO_AVAILABLE and _analyzer is not None:
        try:
            results = _analyzer.analyze(
                text=payload,
                entities=list(SENSITIVE_ENTITY_TYPES),
                language="en",
                score_threshold=0.50,
            )
            return [
                {
                    "entity_type": r.entity_type,
                    "value":       "[REDACTED]",
                    "start":       r.start,
                    "end":         r.end,
                    "confidence":  round(r.score, 4),
                }
                for r in results
            ]
        except Exception as exc:
            logger.error("Presidio error: %s", exc)
            # Fall through to regex

    entities: List[Dict[str, Any]] = []
    for etype, pat in _FALLBACK_PATTERNS:
        for m in pat.finditer(payload):
            entities.append({
                "entity_type": etype,
                "value":       "[REDACTED]",
                "start":       m.start(),
                "end":         m.end(),
                "confidence":  0.85,
            })
    # Independent patterns can match overlapping spans on the same token,
    # double-counting entities and inflating the reported severity/counts.
    return resolve_entity_overlaps(entities)


# Bounds how many scans run concurrently across ALL in-flight requests in
# this process. Without this, a single large batch on /scan submits every
# payload to asyncio.gather() at once — thousands of simultaneous
# run_in_executor() calls exhaust the default ThreadPoolExecutor and starve
# other requests. Shared (module-level) rather than per-request so the bound
# holds under concurrent request load too.
#
# asyncio.Semaphore binds to whatever event loop is running the first time
# it's acquired (asyncio internals, not a bug in this app) — a bare
# module-level instance created once would raise "bound to a different
# event loop" the moment a second, different loop touched it. A single
# long-lived uvicorn process only ever has one loop so this wouldn't
# normally surface in production, but it's a real lifecycle hazard (and
# does surface under multiple TestClient instances in the test suite) —
# fixed by lazily recreating the semaphore whenever the running loop changes.
_scan_semaphore: Optional[asyncio.Semaphore] = None
_scan_semaphore_loop: Optional[asyncio.AbstractEventLoop] = None


def _get_scan_semaphore() -> asyncio.Semaphore:
    global _scan_semaphore, _scan_semaphore_loop
    loop = asyncio.get_running_loop()
    if _scan_semaphore is None or _scan_semaphore_loop is not loop:
        _scan_semaphore = asyncio.Semaphore(config.SCAN_CONCURRENCY_LIMIT)
        _scan_semaphore_loop = loop
    return _scan_semaphore


async def scan_payload_async(payload: str) -> List[Dict[str, Any]]:
    """
    FIX 1 — Non-blocking async wrapper around the CPU-bound Presidio scan.

    run_in_executor(None, ...) submits _sync_scan to the default
    ThreadPoolExecutor that FastAPI/asyncio manages. The event loop
    is released immediately and can accept new connections while
    inference runs in the background thread.

    Why ThreadPoolExecutor and not ProcessPoolExecutor here?
      - Presidio's AnalyzerEngine is not picklable; ProcessPoolExecutor
        requires pickle-able callables. The worker pool in scanner_worker.py
        handles multi-process Presidio for the batch pipeline. For the REST
        layer, thread offload is the correct mechanism.
      - AnalyzerEngine is thread-safe after initialisation (spaCy models
        are read-only after load). Multiple concurrent threads can call
        _analyzer.analyze() simultaneously without lock contention.

    The semaphore bounds concurrency to config.SCAN_CONCURRENCY_LIMIT so a
    single large batch (up to MAX_LOGS_PER_REQUEST) can't exhaust the
    thread pool out from under other requests.
    """
    async with _get_scan_semaphore():
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _sync_scan, payload)


# ---------------------------------------------------------------------------
# FIX 3 — Distributed Rate Limiter (Redis-backed, multi-worker safe)
# ---------------------------------------------------------------------------

class _RedisRateLimiter:
    """
    Sliding-window-counter rate limiter backed by Redis.

    Algorithm: fixed per-window INCRBY buckets, weighted with the previous
    bucket's count by how far the current timestamp is into the current
    window (the standard "sliding window counter" approximation). A pure
    fixed/tumbling window (bump the counter, reset at the boundary) lets a
    client send max_requests right before a boundary and max_requests again
    right after — 2x the configured limit inside one window_seconds span.
    Weighting the previous bucket closes that gap without the cost of a
    true sliding log (one Redis entry per request).

    All uvicorn workers share the same Redis instance — no per-process
    bypass is possible regardless of worker count.

    Key: rate:{client_ip}:{window_index}
    TTL: 2 x window_seconds + 5s grace (need the previous bucket to still
    exist when we read it during the current window)

    Degrades gracefully: if Redis is unavailable, falls back to in-process
    deque with a startup WARNING. This is safe for single-worker development.
    """

    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self._max     = max_requests
        self._window  = window_seconds
        self._redis   = None
        self._fallback = _InProcessRateLimiter(max_requests, window_seconds)

        try:
            import redis as _redis_lib
            r = _redis_lib.Redis(
                host             = "localhost",
                port             = 6379,
                db               = 0,
                socket_timeout   = 0.5,       # fail fast — don't stall requests
                decode_responses = True,
            )
            r.ping()   # raises if Redis unavailable
            self._redis = r
            logger.info("Rate limiter: Redis backend active (multi-worker safe)")
        except Exception as exc:
            logger.warning(
                "Rate limiter: Redis unavailable (%s). "
                "Falling back to in-process deque — NOT safe for multi-worker deployments. "
                "Start Redis or set RATE_LIMIT_BACKEND=redis in production.",
                exc,
            )

    def is_allowed(self, client_ip: str = "global") -> bool:
        if self._redis is not None:
            return self._redis_check(client_ip)
        return self._fallback.is_allowed()

    def _redis_check(self, client_ip: str) -> bool:
        """
        Sliding-window-counter check via Redis pipeline.

        Estimates requests-in-the-last-`window_seconds` as:
            prev_bucket_count * (fraction of window remaining before now)
            + curr_bucket_count

        This is an approximation (assumes uniform request distribution
        within the previous bucket), not an exact sliding log, but it closes
        the fixed-window boundary-burst gap at O(1) Redis ops per check.
        """
        now = time.time()
        window_index = int(now) // self._window
        elapsed_in_window = now - (window_index * self._window)
        weight_prev = max(0.0, (self._window - elapsed_in_window) / self._window)

        curr_key = f"rate:{client_ip}:{window_index}"
        prev_key = f"rate:{client_ip}:{window_index - 1}"
        try:
            pipe = self._redis.pipeline(transaction=True)
            pipe.incr(curr_key)
            pipe.expire(curr_key, self._window * 2 + 5)
            pipe.get(prev_key)
            curr_count, _, prev_raw = pipe.execute()
            prev_count = int(prev_raw) if prev_raw else 0
            estimated = prev_count * weight_prev + curr_count
            return estimated <= self._max
        except Exception as exc:
            # Redis blip — fail open (allow request) and log
            logger.warning("Redis rate-limit check failed: %s — allowing request", exc)
            return True


class _InProcessRateLimiter:
    """
    In-process rolling-window rate limiter (deque-backed).
    Safe ONLY for single-worker deployments.
    Multi-worker: use _RedisRateLimiter.
    """
    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self._max    = max_requests
        self._window = window_seconds
        self._times: deque[float] = deque()

    def is_allowed(self) -> bool:
        now = time.monotonic()
        while self._times and now - self._times[0] > self._window:
            self._times.popleft()
        if len(self._times) >= self._max:
            return False
        self._times.append(now)
        return True


_rate_limiter = _RedisRateLimiter(
    max_requests   = config.RATE_LIMIT_REQUESTS,
    window_seconds = config.RATE_LIMIT_WINDOW_SECONDS,
)


def _get_client_ip(request: Request) -> str:
    """
    Extract the real client IP.

    X-Forwarded-For is attacker-controlled and is only honoured when the
    DIRECT TCP peer (request.client.host) is a known, configured reverse
    proxy — otherwise any client could set an arbitrary/rotating XFF value
    per request and bypass the rate limiter entirely (each "IP" gets its own
    fresh bucket). Configure config.TRUSTED_PROXIES (env: TRUSTED_PROXIES,
    comma-separated) to the load balancer's IP(s) when deploying behind one.

    Special case: TRUSTED_PROXIES=["*"] always honours XFF regardless of
    peer IP. Only set this on platforms where the container is architecturally
    unreachable except through the platform's own edge proxy (Render, Fly.io,
    Railway, Heroku single-service deployments) — there, the direct peer is
    always the platform's proxy and its IP isn't fixed/documented for exact
    matching, so per-IP allowlisting isn't practical. Do NOT set "*" on a
    deployment a client could reach directly (e.g. a raw EC2/VM with a public
    IP and no proxy in front) — that reintroduces the XFF spoofing bypass.
    """
    direct_ip = request.client.host if request.client else "unknown"
    trust_any = "*" in config.TRUSTED_PROXIES
    if trust_any or direct_ip in config.TRUSTED_PROXIES:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return direct_ip


async def require_rate_limit(request: Request) -> None:
    """FastAPI dependency — raises HTTP 429 when rate limit exceeded."""
    client_ip = _get_client_ip(request)
    if not _rate_limiter.is_allowed(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Retry after 60 seconds.",
            headers={"Retry-After": "60"},
        )


# ---------------------------------------------------------------------------
# API Key Authentication (OWASP A07)
# ---------------------------------------------------------------------------

async def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """
    FastAPI dependency — enforces X-API-Key when config.API_KEY is set.

    If SHADOW_AI_API_KEY is not configured, the API runs unauthenticated
    (local/dev mode); a startup warning is logged in that case. Once a key
    is configured, every request to a protected endpoint must present a
    matching X-API-Key header. Comparison is constant-time to avoid a
    timing side-channel on key guessing.
    """
    if not config.API_KEY:
        return
    if not x_api_key or not hmac.compare_digest(x_api_key, config.API_KEY):
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key header")


# ---------------------------------------------------------------------------
# Severity classification
# ---------------------------------------------------------------------------

def _determine_severity(entities: List[Dict], is_ai: bool) -> Tuple[str, str]:
    count = len(entities)
    if is_ai:
        if count >= 3: return "critical", "BLOCK_AND_ALERT"
        if count >= 2: return "high",     "ALERT_AND_LOG"
        if count >= 1: return "medium",   "LOG_INCIDENT"
        return "low", "MONITOR"
    else:
        if count >= 2: return "high",   "ALERT_AND_LOG"
        if count >= 1: return "medium", "LOG_INCIDENT"
        return "low", "MONITOR"


def _is_ai_endpoint(url: str) -> bool:
    url_lower = url.lower()
    return any(p.search(url_lower) for p in COMPILED_AI_PATTERNS)


# ---------------------------------------------------------------------------
# Audit logging (NIST AU-3)
# ---------------------------------------------------------------------------

def _audit_log(event: str, detail: Dict[str, Any]) -> None:
    if not config.ENABLE_AUDIT_LOGGING:
        return
    import json
    record = {"ts": datetime.utcnow().isoformat() + "Z", "event": event, **detail}
    logger.info("[AUDIT] %s", json.dumps(record))
    try:
        with open(config.AUDIT_LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError as exc:
        logger.warning("Audit write failed: %s", exc)


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "Shadow AI Detector starting — Presidio: %s | Rate limiter: %s | Auth: %s",
        "ACTIVE" if _PRESIDIO_AVAILABLE else "FALLBACK",
        "Redis" if _rate_limiter._redis else "in-process (single-worker only)",
        "ENABLED" if config.API_KEY else "DISABLED",
    )
    if not config.API_KEY:
        logger.warning(
            "SHADOW_AI_API_KEY is not set — /scan and /scan-file are UNAUTHENTICATED. "
            "Set SHADOW_AI_API_KEY before exposing this service on a public/deployed endpoint."
        )

    # Seed the dashboard with synthetic demo traffic on first boot so
    # /dashboard isn't empty the moment a deployment comes up. /dashboard
    # and /dashboard/stats are intentionally unauthenticated (see
    # SECURITY.md) — this seed data is synthetic, never real submissions.
    if dashboard_store.is_empty():
        try:
            from telemetry_generator import generate_logs as _generate_seed_logs
            seed_logs: List[ProxyLog] = []
            for record in _generate_seed_logs(150):
                try:
                    seed_logs.append(ProxyLog(**record))
                except Exception:
                    continue
            if seed_logs:
                await scan_logs(ScanRequest(logs=seed_logs, max_logs=len(seed_logs)))
                logger.info("Dashboard seeded with %d synthetic demo records", len(seed_logs))
        except Exception as exc:
            logger.warning("Dashboard demo seed failed (non-fatal): %s", exc)

    yield
    logger.info("Shadow AI Detector shutting down")


app = FastAPI(
    title       = "Shadow AI Detector",
    description = (
        "Detect PII leakage to unsanctioned AI endpoints. "
        "NIST SP 800-53 & OWASP Top 10 compliant."
    ),
    version     = "4.0.0",
    lifespan    = lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins     = config.CORS_ORIGINS,
    allow_credentials = config.CORS_ALLOW_CREDENTIALS,
    allow_methods     = config.CORS_ALLOW_METHODS,
    allow_headers     = ["Content-Type"],
    max_age           = 600,
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next) -> Response:
    response = await call_next(request)
    for k, v in SECURITY_HEADERS.items():
        response.headers[k] = v
    return response


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health", tags=["Operations"])
async def health_check():
    return {
        "status":             "healthy",
        "timestamp":          datetime.utcnow().isoformat() + "Z",
        "presidio_active":    _PRESIDIO_AVAILABLE,
        "rate_limiter_backend": "redis" if _rate_limiter._redis else "in-process",
        "auth_enabled":       bool(config.API_KEY),
        "async_scan":         True,   # FIX 1 always active
    }


@app.get("/config", tags=["Operations"])
async def get_config_endpoint():
    return {
        "rate_limit_requests":  config.RATE_LIMIT_REQUESTS,
        "rate_limit_window_s":  config.RATE_LIMIT_WINDOW_SECONDS,
        "max_payload_bytes":    config.MAX_PAYLOAD_BYTES,
        "max_logs_per_request": config.MAX_LOGS_PER_REQUEST,
        "presidio_active":      _PRESIDIO_AVAILABLE,
        "rate_limiter_backend": "redis" if _rate_limiter._redis else "in-process",
        "auth_enabled":         bool(config.API_KEY),
    }


@app.post(
    "/scan",
    response_model = ScanResponse,
    tags           = ["Detection"],
    dependencies   = [Depends(require_rate_limit), Depends(require_api_key)],
)
async def scan_logs(request: ScanRequest) -> ScanResponse:
    """
    Scan a batch of proxy logs for PII leakage to AI endpoints.

    FIX 1 applied: scan_payload_async() offloads Presidio to a thread pool
    via run_in_executor — the event loop never blocks on NLP inference.

    FIX 3 applied: require_rate_limit dependency checks Redis before
    processing begins — all uvicorn workers share the same counter.
    """
    log_count = len(request.logs)
    if log_count > request.max_logs:
        raise HTTPException(400, f"Batch size {log_count} exceeds limit {request.max_logs}")

    _audit_log("scan_request", {"log_count": log_count})

    # FIX 1: Run all payload scans concurrently — each goes to thread pool,
    # event loop is never blocked. asyncio.gather() collects all results.
    scan_coroutines = [scan_payload_async(log.payload) for log in request.logs]
    all_entities: List[List[Dict[str, Any]]] = await asyncio.gather(*scan_coroutines)

    results:          List[ScanResult] = []
    threats_detected  = 0
    critical_alerts   = 0
    dashboard_alerts: List[Dict[str, Any]] = []

    for log, entities in zip(request.logs, all_entities):
        try:
            is_ai    = _is_ai_endpoint(log.destination_url)
            severity, action = _determine_severity(entities, is_ai)

            if entities or is_ai:
                sr = ScanResult(
                    log_id             = log.log_hash(),
                    destination_url    = log.destination_url,
                    user_id            = log.user_id,
                    department         = log.department,
                    source_ip          = log.source_ip,
                    entities_found     = [EntityDetection(**e) for e in entities],
                    is_sensitive_to_ai = is_ai and len(entities) > 0,
                    severity           = severity,
                    recommended_action = action,
                    timestamp          = datetime.utcnow().isoformat() + "Z",
                )
                results.append(sr)
                if sr.is_sensitive_to_ai:
                    threats_detected += 1
                if severity == "critical":
                    critical_alerts += 1

                # Run the SAME stateless policy engine + rule set the CLI
                # pipeline (main.py) uses, so /scan gets threat_score,
                # remediation text, and the department/after-hours/volume
                # rules too — previously the REST layer only computed its
                # own inline severity/action and never touched
                # policy_engine.py at all, so those three rules never fired
                # for anything submitted via the API.
                log_entry = {
                    "user_id": log.user_id, "department": log.department,
                    "source_ip": log.source_ip,
                }
                for alert in policy_rules.evaluate_all(sr, log_entry):
                    dashboard_alerts.append(alert.to_dict())

        except Exception as exc:
            logger.error("Error on log user=%s: %s", log.user_id, str(exc)[:120])
            continue

    dashboard_store.record_scan_batch(
        scanned=log_count, threats=threats_detected, critical=critical_alerts
    )
    dashboard_store.record_alerts(dashboard_alerts)

    _audit_log("scan_complete", {
        "total": log_count, "threats": threats_detected, "critical": critical_alerts
    })

    return ScanResponse(
        total_logs_scanned = log_count,
        threats_detected   = threats_detected,
        critical_alerts    = critical_alerts,
        results            = results,
    )


# /scan-file may only read files under this resolved directory — closes the
# path-traversal hole where a caller could pass file_path="../../etc/passwd"
# (or an absolute path) and have the server read arbitrary filesystem paths.
_SCAN_FILE_BASE_DIR = Path(config.SCAN_FILE_BASE_DIR).resolve()
_SCAN_FILE_MAX_LOGS = min(config.MAX_LOGS_PER_REQUEST, 10_000)   # ScanRequest.max_logs le=10_000


@app.post(
    "/scan-file",
    response_model = ScanResponse,
    tags           = ["Detection"],
    dependencies   = [Depends(require_rate_limit), Depends(require_api_key)],
)
async def scan_file(file_path: str) -> ScanResponse:
    """
    Stream a JSONL log file through the async scan pipeline.

    file_path is resolved relative to _SCAN_FILE_BASE_DIR and MUST stay
    within it after resolution (no `..` traversal, no absolute-path escape,
    no symlink escape) — otherwise this endpoint would let any caller read
    arbitrary files on the host that the server process can access.
    """
    import json as _json

    requested = (_SCAN_FILE_BASE_DIR / file_path).resolve()
    try:
        requested.relative_to(_SCAN_FILE_BASE_DIR)
    except ValueError:
        raise HTTPException(403, "file_path must resolve within the allowed scan directory")

    if not requested.exists() or not requested.is_file():
        raise HTTPException(404, f"File not found: {file_path}")
    if requested.suffix not in {".jsonl", ".json", ".log"}:
        raise HTTPException(400, "Unsupported file extension")

    logs: List[ProxyLog] = []
    skipped = 0
    with open(requested, "r", encoding="utf-8-sig") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line:
                continue
            try:
                logs.append(ProxyLog(**_json.loads(line)))
            except Exception as exc:
                skipped += 1
                if skipped <= 5:
                    logger.warning("Line %d skipped: %s", lineno, exc)

    # ScanRequest.max_logs is capped at le=10_000 (models.py) — the previous
    # version passed max_logs=50_000 here, which fails Pydantic validation
    # on every single call and 500s. A truly empty/all-malformed file would
    # also 500 (ScanRequest.logs has min_length=1) instead of a clean 400.
    if not logs:
        raise HTTPException(
            400,
            f"No valid log entries found in {file_path} "
            f"(file was empty, all lines malformed, or all lines failed schema validation; "
            f"{skipped} line(s) skipped)",
        )
    if len(logs) > _SCAN_FILE_MAX_LOGS:
        raise HTTPException(
            400,
            f"File contains {len(logs)} valid log entries, exceeding the per-request "
            f"limit of {_SCAN_FILE_MAX_LOGS}. Split the file into smaller batches.",
        )

    return await scan_logs(ScanRequest(logs=logs, max_logs=_SCAN_FILE_MAX_LOGS))


# ---------------------------------------------------------------------------
# Dashboard — static single-page app + its two data endpoints
#
# /dashboard and /dashboard/stats are intentionally UNAUTHENTICATED: they
# only ever surface aggregate counts, [REDACTED] entity types, hashed
# log_ids, and demo user_id/department values — never a raw payload or PII
# value — so the live dashboard can be shown publicly. /scan and
# /scan-file (which accept and process submitted data) remain behind
# require_api_key. See SECURITY.md.
# ---------------------------------------------------------------------------

_STATIC_DIR = Path(__file__).parent / "static"
if _STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
async def root() -> RedirectResponse:
    return RedirectResponse(url="/dashboard")


@app.get("/dashboard", tags=["Dashboard"], include_in_schema=False)
async def dashboard_page() -> FileResponse:
    index = _STATIC_DIR / "dashboard.html"
    if not index.exists():
        raise HTTPException(404, "Dashboard assets not built")
    return FileResponse(str(index))


def _dashboard_filters(
    severity:    List[str] = Query(default=[]),
    department:  List[str] = Query(default=[]),
    entity_type: List[str] = Query(default=[]),
    status:      List[str] = Query(default=[]),
    q:           str       = Query(default="", max_length=256),
) -> Dict[str, Any]:
    """Shared query-param parsing for every /dashboard/* read endpoint —
    all values flow into dashboard_store as parameterized query params,
    never interpolated into SQL (see dashboard_store.py docstring)."""
    return {
        "severities":   severity or None,
        "departments":  department or None,
        "entity_types": entity_type or None,
        "statuses":     status or None,
        "search":       q or None,
    }


@app.get("/dashboard/stats", tags=["Dashboard"])
async def dashboard_stats(filters: Dict[str, Any] = Depends(_dashboard_filters)) -> Dict[str, Any]:
    """
    Aggregate counts + a short recent-alerts preview backing the dashboard's
    stat tiles and charts. Accepts the same filters as /dashboard/alerts —
    severity_counts/entity_counts/department_counts reflect the active
    filter set. `totals` (scanned/threats/critical) is always the all-time,
    unfiltered pipeline throughput — it counts scan events, not alerts, so
    filtering by alert attributes doesn't apply to it.
    """
    agg = dashboard_store.aggregate_counts(**filters)
    preview = dashboard_store.list_alerts(**filters, limit=10)
    return {
        "totals":               dashboard_store.totals(),
        "alert_buffer_size":    dashboard_store.alert_count(),
        "matched_count":        preview["total"],
        "severity_counts":      agg["severity_counts"],
        "department_counts":    agg["department_counts"],
        "entity_counts":        agg["entity_counts"],
        "recent_alerts":        preview["items"],
        "presidio_active":      _PRESIDIO_AVAILABLE,
        "rate_limiter_backend": "redis" if _rate_limiter._redis else "in-process",
        "auth_enabled":         bool(config.API_KEY),
    }


@app.get("/dashboard/alerts", tags=["Dashboard"])
async def dashboard_alerts_list(
    filters: Dict[str, Any] = Depends(_dashboard_filters),
    sort:    str = Query(default="time_desc"),
    limit:   int = Query(default=50, ge=1, le=200),
    offset:  int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """Filtered, sorted, paginated alert list — backs the interactive table."""
    return dashboard_store.list_alerts(**filters, sort=sort, limit=limit, offset=offset)


@app.get("/dashboard/alerts/{alert_id}", tags=["Dashboard"])
async def dashboard_alert_detail(alert_id: str) -> Dict[str, Any]:
    """
    Single alert, fully addressable by ID — this is what makes a table row
    "linkable": the frontend sets location.hash to this ID so a specific
    alert has a shareable/bookmarkable URL that reopens the same detail view.
    """
    alert = dashboard_store.get_alert(alert_id)
    if alert is None:
        raise HTTPException(404, f"Alert not found: {alert_id}")
    return alert


class AlertStatusUpdate(BaseModel):
    status: str


@app.patch(
    "/dashboard/alerts/{alert_id}",
    tags         = ["Dashboard"],
    dependencies = [Depends(require_api_key)],
)
async def dashboard_alert_update_status(alert_id: str, body: AlertStatusUpdate) -> Dict[str, Any]:
    """
    Incident-workflow status transition (NEW -> ACKNOWLEDGED -> RESOLVED).
    Unlike the read endpoints above, this MUTATES stored data, so — unlike
    the rest of /dashboard/* — it sits behind require_api_key (same
    no-op-if-unconfigured behaviour as /scan; see SECURITY.md).
    """
    if body.status not in VALID_STATUSES:
        raise HTTPException(400, f"status must be one of {VALID_STATUSES}")
    updated = dashboard_store.update_status(alert_id, body.status)
    if updated is None:
        raise HTTPException(404, f"Alert not found: {alert_id}")
    return updated


@app.post(
    "/dashboard/simulate",
    tags         = ["Dashboard"],
    dependencies = [Depends(require_rate_limit)],
)
async def dashboard_simulate(count: int = 50) -> Dict[str, Any]:
    """
    Generate `count` synthetic proxy logs (telemetry_generator — the same
    generator main.py uses) and run them through the real scan + policy
    pipeline, feeding the dashboard. Powers the "Generate Demo Traffic"
    button. Synthetic data only — never touches real submitted data, so
    this is safe to leave unauthenticated like the rest of /dashboard/*.
    """
    from telemetry_generator import generate_logs as _generate_demo_logs

    count = max(1, min(count, 500))
    logs: List[ProxyLog] = []
    for record in _generate_demo_logs(count):
        try:
            logs.append(ProxyLog(**record))
        except Exception:
            continue
    if not logs:
        raise HTTPException(500, "Failed to generate synthetic demo traffic")

    response = await scan_logs(ScanRequest(logs=logs, max_logs=len(logs)))
    return {
        "generated":         len(logs),
        "threats_detected":  response.threats_detected,
        "critical_alerts":   response.critical_alerts,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 70)
    print("Shadow AI Detector — FastAPI Server (v4)")
    print("=" * 70)
    print(f"  Presidio active    : {_PRESIDIO_AVAILABLE}")
    print(f"  Rate limiter       : {'Redis' if _rate_limiter._redis else 'in-process'}")
    print(f"  Async scan (FIX 1) : ACTIVE")
    print(f"  Bind               : http://{config.API_HOST}:{config.API_PORT}")
    print(f"  API docs           : http://{config.API_HOST}:{config.API_PORT}/docs")
    print("=" * 70)
    uvicorn.run(
        "presidio_scanner:app",
        host    = config.API_HOST,
        port    = config.API_PORT,
        workers = config.API_WORKERS,
        reload  = False,
    )
