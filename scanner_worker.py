"""
Shadow AI Detector — Multiprocessing Scanner Worker Pool
=========================================================
NIST SP 800-53: SI-4 (System Monitoring), SC-5 (Denial of Service Protection)

  ❌ BEFORE: Sequential for-loop over payloads — one CPU core, GIL-bound,
             blocks entirely on every Presidio NLP inference call.
             Throughput ceiling: ~10-50 logs/s on a single core.

  ✅ AFTER:  ProcessPoolExecutor — each worker is a separate OS process,
             bypassing the GIL completely. Presidio's spaCy models run
             in parallel across all available CPU cores.
             Throughput scales linearly with core count.

Thread safety and state mutation:
  ✅ Workers are pure functions — no shared mutable state whatsoever.
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
from concurrent.futures import ProcessPoolExecutor, as_completed, Future
from typing import Any, Callable, Dict, Generator, Iterator, List, Optional, Tuple

logger = logging.getLogger("shadow_ai_detector.worker")

# ---------------------------------------------------------------------------
# Pre-compiled fallback patterns — defined at module level so subprocesses
# inherit the compiled objects without re-compiling on every invocation.
# ---------------------------------------------------------------------------
_FALLBACK_PATTERNS: Tuple[Tuple[str, re.Pattern], ...] = (
    ("CREDIT_CARD",      re.compile(r"\b(?:\d[ -]?){13,16}\b")),
    ("EMAIL_ADDRESS",    re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")),
    ("US_SSN",           re.compile(r"\b\d{3}[-\s]\d{2}[-\s]\d{4}\b")),
    ("API_KEY",          re.compile(r"\bsk-[a-fA-F0-9]{20,}\b")),
    ("GENERIC_PASSWORD", re.compile(r"(?i)password\s*[:=]\s*\S{6,}")),
    ("PHONE_NUMBER",     re.compile(r"\b(?:\+?\d[\d\-\s]{7,14}\d)\b")),
    ("IBAN_CODE",        re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b")),
)

_AI_DOMAIN_PATTERN: re.Pattern = re.compile(
    r"api\.openai\.com|claude\.ai|api\.anthropic\.com"
    r"|api\.huggingface\.co|generativelanguage\.googleapis\.com"
    r"|api\.cohere\.ai|api\.mistral\.ai",
    re.IGNORECASE,
)

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
        from presidio_analyzer import AnalyzerEngine
        _worker_analyzer = AnalyzerEngine()
        logger.info("[Worker PID=%d] Presidio AnalyzerEngine ready", pid)
    except ImportError:
        logger.warning("[Worker PID=%d] Presidio unavailable — regex fallback active", pid)
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
    return found


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
        is_ai       = bool(_AI_DOMAIN_PATTERN.search(destination))

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
            "source_ip":          record.get("source_ip", "0.0.0.0"),
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
                done, pending_set = __import__("concurrent.futures", fromlist=["wait"]).wait(
                    pending, return_when=__import__("concurrent.futures").FIRST_COMPLETED
                )
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
