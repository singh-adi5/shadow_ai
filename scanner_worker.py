"""
Shadow AI Detector — Multiprocessing Scanner Worker Pool
=========================================================
NIST SP 800-53: SI-4 (System Monitoring), SC-5 (Denial of Service Protection)

ProcessPoolExecutor — each worker is a separate OS process,
             bypassing the GIL completely. Presidio's spaCy models run
             in parallel across all available CPU cores.
             Throughput scales linearly with core count.
Workers are pure functions — no shared mutable state whatsoever.
     Each OS process has its own memory space (no dict race conditions).
     The Presidio AnalyzerEngine is initialised ONCE per worker process
     via the pool initialiser — not recreated per record (expensive).

Design contract:
  - scan_record(record: dict) → ScanResult | None   (pure function)
  - Called by executor.map() — embarrassingly parallel
  - Returns None for records with no entities AND no AI endpoint
  - Caller collects results via as_completed() for streaming output
"""

from __future__ import annotations

import hashlib
import logging
import multiprocessing
import os
import re
import time
from concurrent.futures import (
    FIRST_COMPLETED, Future, ProcessPoolExecutor, as_completed, wait,
)
from typing import Any, Callable, Dict, Generator, Iterator, List, Optional, Tuple

from config import COMPILED_AI_PATTERNS, FALLBACK_PATTERNS, resolve_entity_overlaps

logger = logging.getLogger("shadow_ai_detector.worker")

# Fallback patterns and AI-domain patterns are defined ONCE in config.py and
# imported here — this module previously kept its own duplicate copy of
# _FALLBACK_PATTERNS with an unbounded EMAIL_ADDRESS pattern that backtracks
# catastrophically on adversarial input (~105ms per 10KB payload, and this
# was the path main.py actually exercises via ScannerWorkerPool).
_FALLBACK_PATTERNS: Tuple[Tuple[str, re.Pattern], ...] = FALLBACK_PATTERNS
_AI_DOMAIN_PATTERNS: Tuple[re.Pattern, ...] = COMPILED_AI_PATTERNS

# ---------------------------------------------------------------------------
# Worker process initialiser — runs ONCE per worker, not per record.
# Presidio AnalyzerEngine startup takes ~2-4s; initialising it here means
# the cost is paid once at pool startup, not amortised into every scan call.
# ---------------------------------------------------------------------------

_worker_analyzer = None   # module-level singleton per worker process


def _worker_init() -> None:
    """
    Process pool initialiser. Called once when each worker process starts.
    Sets up the Presidio AnalyzerEngine (expensive) in worker-local memory.
    No shared state — each OS process has its own isolated copy.
    """
    global _worker_analyzer
    pid = os.getpid()
    try:
        from presidio_recognizers import build_analyzer_engine
        _worker_analyzer = build_analyzer_engine()
        logger.info("[Worker PID=%d] Presidio AnalyzerEngine ready (custom recognizers loaded)", pid)
    except ImportError:
        logger.warning("[Worker PID=%d] presidio-analyzer not installed — regex fallback active", pid)
        _worker_analyzer = None
    except OSError as exc:
        logger.warning(
            "[Worker PID=%d] spaCy language model unavailable (%s) — regex fallback active. "
            "Run: python -m spacy download en_core_web_lg", pid, exc,
        )
        _worker_analyzer = None
    except SystemExit as exc:
        # A completely invalid PRESIDIO_SPACY_MODEL name (not just "not
        # downloaded yet") makes spaCy's own download-CLI call sys.exit()
        # internally rather than raising a normal exception — confirmed by
        # direct reproduction. Caught here so a config typo degrades to the
        # regex fallback instead of killing the worker process outright.
        logger.warning(
            "[Worker PID=%d] Presidio init aborted via SystemExit (%s) — "
            "check PRESIDIO_SPACY_MODEL is a real, installed model name. "
            "Regex fallback active.", pid, exc,
        )
        _worker_analyzer = None


# ---------------------------------------------------------------------------
# Pure scan function — no global mutable state, safe for concurrent execution
# ---------------------------------------------------------------------------

def _regex_scan(payload: str) -> List[Dict[str, Any]]:
    """Regex fallback when Presidio is unavailable. Returns normalised entity dicts."""
    found = []
    for etype, pat in _FALLBACK_PATTERNS:
        for m in pat.finditer(payload):
            found.append({
                "entity_type": etype,
                "value":       "[REDACTED]",
                "start":       m.start(),
                "end":         m.end(),
                "confidence":  0.85,
            })
    # Independent patterns can match overlapping spans on the same token
    # (e.g. a long digit run satisfying both CREDIT_CARD and PHONE_NUMBER),
    # double-counting entities and inflating severity/threat_score.
    return resolve_entity_overlaps(found)


def scan_record(record: dict) -> Optional[Dict[str, Any]]:
    """
    Scan a single proxy log record for PII entities.

    This is the unit of work dispatched to each worker process.
    It is a PURE FUNCTION — reads only its argument and module-level
    compiled constants. No shared mutable state. No I/O. No side effects.

    Returns None if the record has no entities AND is not an AI endpoint
    (i.e. it is provably safe — the caller can skip it).

    Returns a plain dict (not a Pydantic model) because Pydantic objects
    are not picklable across process boundaries without custom serialisers.
    The orchestrator reconstructs ScanResult from the returned dict.
    """
    try:
        payload     = record.get("payload", "")
        destination = record.get("destination_url", "").lower()
        is_ai       = any(p.search(destination) for p in _AI_DOMAIN_PATTERNS)

        # Run Presidio if available, otherwise regex
        if _worker_analyzer is not None:
            try:
                raw = _worker_analyzer.analyze(
                    text=payload,
                    entities=[
                        "CREDIT_CARD", "EMAIL_ADDRESS", "US_SSN",
                        "GENERIC_PASSWORD", "API_KEY", "PHONE_NUMBER",
                        "IBAN_CODE", "CRYPTO",
                    ],
                    language="en",
                    score_threshold=0.50,
                )
                entities = [
                    {
                        "entity_type": r.entity_type,
                        "value":       "[REDACTED]",
                        "start":       r.start,
                        "end":         r.end,
                        "confidence":  round(r.score, 4),
                    }
                    for r in raw
                ]
            except Exception:
                entities = _regex_scan(payload)
        else:
            entities = _regex_scan(payload)

        # Skip provably safe records — no entity, not an AI endpoint
        if not entities and not is_ai:
            return None

        # Severity classification
        count = len(entities)
        if is_ai:
            if count >= 3:   severity, action = "critical", "BLOCK_AND_ALERT"
            elif count >= 2: severity, action = "high",     "ALERT_AND_LOG"
            elif count >= 1: severity, action = "medium",   "LOG_INCIDENT"
            else:            severity, action = "low",      "MONITOR"
        else:
            if count >= 2:   severity, action = "high",     "ALERT_AND_LOG"
            elif count >= 1: severity, action = "medium",   "LOG_INCIDENT"
            else:            severity, action = "low",      "MONITOR"

        # SHA-256 log ID — no raw PII stored
        raw_id = f"{record.get('timestamp','')}:{record.get('source_ip','')}:{record.get('user_id','')}"
        log_id = hashlib.sha256(raw_id.encode()).hexdigest()[:16]

        return {
            "log_id":             log_id,
            "destination_url":    record.get("destination_url", ""),
            "user_id":            record.get("user_id", "UNKNOWN"),
            "department":         record.get("department", "UNKNOWN"),
            "source_ip":          record.get("source_ip", "0.0.0.0"),  # nosec B104
            "entities_found":     entities,
            "is_sensitive_to_ai": is_ai and count > 0,
            "severity":           severity,
            "recommended_action": action,
            "timestamp":          record.get("timestamp", ""),
            "entity_count":       count,
            "_worker_pid":        os.getpid(),   # telemetry: which worker handled it
        }

    except Exception as exc:
        # Worker must never crash — return None and let the orchestrator skip
        logger.error("Worker scan error: %s", str(exc)[:120])
        return None


# ---------------------------------------------------------------------------
# Worker Pool Orchestrator
# ---------------------------------------------------------------------------

class ScannerWorkerPool:
    """
    Manages a ProcessPoolExecutor for parallel Presidio scanning.

    Usage:
        with ScannerWorkerPool(workers=4) as pool:
            for result in pool.scan_stream(micro_batches):
                process(result)

    Worker count defaults to min(cpu_count, 8) — bounded to avoid
    exhausting system resources on large machines.
    """

    def __init__(self, workers: Optional[int] = None) -> None:
        cpu = multiprocessing.cpu_count()
        self.workers = workers or min(cpu, 8)
        self._pool: Optional[ProcessPoolExecutor] = None
        logger.info("ScannerWorkerPool: %d workers (available CPUs: %d)", self.workers, cpu)

    def __enter__(self) -> "ScannerWorkerPool":
        self._pool = ProcessPoolExecutor(
            max_workers  = self.workers,
            initializer  = _worker_init,
        )
        return self

    def __exit__(self, *_) -> None:
        if self._pool:
            self._pool.shutdown(wait=True)
            self._pool = None

    def scan_stream(
        self,
        batches: Iterator[List[dict]],
        *,
        on_result: Optional[Callable[[Dict], None]] = None,
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Submit micro-batches to the worker pool and yield results as they complete.

        This is a streaming generator — it never accumulates all results in memory.
        Results arrive in completion order (not submission order) for maximum
        throughput. If ordering matters, add a sequence number to each record.

        Args:
            batches:   Iterator of micro-batches from ingestion.micro_batch().
            on_result: Optional callback invoked for each non-None result
                       (useful for real-time metrics / dashboards).

        Yields:
            dict — scan result for each record that has entities or is an AI endpoint.
        """
        if self._pool is None:
            raise RuntimeError("ScannerWorkerPool must be used as a context manager")

        pending: List[Future] = []
        MAX_IN_FLIGHT = self.workers * 4   # back-pressure limit

        for batch in batches:
            # Submit each record in the batch as an independent future
            for record in batch:
                future = self._pool.submit(scan_record, record)
                pending.append(future)

            # Drain completed futures when we hit the back-pressure ceiling
            while len(pending) >= MAX_IN_FLIGHT:
                done, _ = wait(pending, return_when=FIRST_COMPLETED)
                for f in done:
                    pending.remove(f)
                    result = f.result()
                    if result is not None:
                        if on_result:
                            on_result(result)
                        yield result

        # Drain remaining futures after all batches submitted
        for future in as_completed(pending):
            result = future.result()
            if result is not None:
                if on_result:
                    on_result(result)
                yield result

    def scan_batch_sync(self, records: List[dict]) -> List[Dict[str, Any]]:
        """
        Convenience method: scan a list synchronously via executor.map().
        Preserves input order. Used in tests and CLI demo mode.
        """
        if self._pool is None:
            raise RuntimeError("Must be used as context manager")
        results = list(self._pool.map(scan_record, records))
        return [r for r in results if r is not None]


# ---------------------------------------------------------------------------
# Single-process fallback (used when worker pool is unavailable / tests)
# ---------------------------------------------------------------------------

def scan_record_local(record: dict) -> Optional[Dict[str, Any]]:
    """
    Single-process version of scan_record. Used when multiprocessing
    is unavailable (e.g. interactive interpreter, some CI environments).
    Initialises Presidio lazily on first call.
    """
    global _worker_analyzer
    if _worker_analyzer is None:
        _worker_init()
    return scan_record(record)


if __name__ == "__main__":
    # Smoke test
    from telemetry_generator import generate_logs

    print("Running worker pool smoke test...")
    logs = generate_logs(100)

    with ScannerWorkerPool(workers=2) as pool:
        from ingestion import micro_batch, stream_from_list
        results = pool.scan_batch_sync(logs[:20])

    threats = sum(1 for r in results if r.get("is_sensitive_to_ai"))
    print(f"Scanned 20 records → {len(results)} with entities, {threats} threats")
    print("Worker pool smoke test: PASS")
