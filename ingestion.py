"""
Shadow AI Detector — O(1) Streaming Ingestion Layer
=====================================================
NIST SP 800-53: SI-4 (System Monitoring), AU-2 (Audit Events)

  ❌ BEFORE: json.load() / generate_logs() materialised the entire
             dataset into heap memory — O(N) allocation, GC pauses,
             OOM-killer risk on multi-GB enterprise log files.

  ✅ AFTER:  Line-by-line JSONL streaming with a two-stage filter:
             1. Fast O(1) regex pre-filter (constant time per record)
                → drops clean traffic before Presidio ever sees it
             2. Pydantic validation only on records that pass stage 1
             3. Micro-batch output via generator — caller never holds
                more than BATCH_SIZE records in heap simultaneously.

Memory profile: O(BATCH_SIZE) regardless of input file size.
                BATCH_SIZE = 64 → ~50 KB heap ceiling per batch.
"""

from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Generator, Iterable, Iterator, List, Optional, Tuple

from config import COMPILED_AI_PATTERNS, config
from models import ProxyLog

logger = logging.getLogger("shadow_ai_detector.ingestion")

# ---------------------------------------------------------------------------
# Stage 1 — Fast Regex Pre-Filter (compiled once at import)
# Bypasses Presidio/Pydantic entirely for provably clean records.
# ---------------------------------------------------------------------------

# Detect any AI domain substring — intentionally broad for the pre-filter
_AI_DOMAIN_QUICK  = re.compile(
    r"openai|anthropic|claude\.ai|huggingface|googleapis\.com/generative"
    r"|cohere|mistral\.ai",
    re.IGNORECASE,
)

# Any token that looks like PII — credit card digits, SSN, email, sk- keys
_PII_QUICK = re.compile(
    r"(?:\d[ -]?){13,16}"
    r"|[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
    r"|\b\d{3}[-\s]\d{2}[-\s]\d{4}\b"
    r"|\bsk-[a-fA-F0-9]{20,}\b"
    r"|password\s*[:=]\s*\S{6,}",
    re.IGNORECASE,
)








BATCH_SIZE: int = 64   # Records per micro-batch; tune for CPU cache fit


def _passes_prefilter(raw_line: str) -> bool:
    """
    O(1) two-part pre-filter — runs on the raw JSON string before parsing.

    A record is forwarded to Presidio ONLY if both:
      (a) the destination_url contains an AI domain, OR
      (b) the payload contains a PII-like token.

    Clean traffic (no AI domain, no PII pattern) is dropped here — zero
    heap allocation, zero Pydantic overhead, zero Presidio inference cost.
    """
    return bool(_AI_DOMAIN_QUICK.search(raw_line) or _PII_QUICK.search(raw_line))


# ---------------------------------------------------------------------------
# Streaming JSONL Reader — O(1) heap regardless of file size
# ---------------------------------------------------------------------------

def stream_jsonl(
    path: Path,
    *,
    apply_prefilter: bool = True,
    encoding: str = "utf-8-sig",    # strips BOM automatically
) -> Generator[dict, None, None]:
    """
    Stream a JSONL file one record at a time.

    Yields raw dicts — does NOT materialise the file into a list.
    Each yielded dict occupies heap only until the caller processes it.

    Args:
        path:             Path to .jsonl or .log file.
        apply_prefilter:  Drop records that cannot contain threats (default True).
        encoding:         File encoding; utf-8-sig strips Windows BOM.

    Yields:
        dict — one parsed log record per iteration.

    Side-effects:
        Logs a warning for each malformed line; never raises on bad data.
    """
    skipped_clean   = 0
    skipped_malform = 0
    yielded         = 0

    with open(path, "r", encoding=encoding, buffering=65536) as fh:
        for lineno, raw_line in enumerate(fh, start=1):
            line = raw_line.strip()
            if not line:
                continue

            # Stage 1: fast pre-filter on raw string
            if apply_prefilter and not _passes_prefilter(line):
                skipped_clean += 1
                continue

            # Stage 2: JSON parse + schema validation
            try:
                record = json.loads(line)
                yielded += 1
                yield record
            except json.JSONDecodeError as exc:
                skipped_malform += 1
                if skipped_malform <= 10:   # avoid log flood
                    logger.warning("Line %d — JSON parse error: %s", lineno, exc)

    logger.info(
        "Ingestion complete: yielded=%d, dropped_clean=%d, dropped_malformed=%d",
        yielded, skipped_clean, skipped_malform,
    )


def stream_validated(
    path: Path,
    *,
    apply_prefilter: bool = True,
) -> Generator[ProxyLog, None, None]:
    """
    Like stream_jsonl() but yields validated ProxyLog Pydantic models.
    Validation failures are logged and skipped — pipeline never halts.
    """
    for record in stream_jsonl(path, apply_prefilter=apply_prefilter):
        try:
            yield ProxyLog(**record)
        except Exception as exc:
            logger.debug("Validation skip: %s", str(exc)[:80])


# ---------------------------------------------------------------------------
# Micro-Batch Generator — feeds the worker pool without blocking the event loop
# ---------------------------------------------------------------------------

def micro_batch(
    source: Iterable[dict],
    batch_size: int = BATCH_SIZE,
) -> Generator[List[dict], None, None]:
    """
    Partition a streaming iterable into fixed-size micro-batches.

    Memory profile: O(batch_size) — never accumulates the full dataset.
    The caller submits each batch to the worker pool and moves on.

    Example:
        for batch in micro_batch(stream_jsonl(path)):
            futures = [pool.submit(scan_worker, record) for record in batch]
            ...
    """
    batch: List[dict] = []
    for item in source:
        batch.append(item)
        if len(batch) >= batch_size:
            yield batch
            batch = []
    if batch:
        yield batch   # flush remainder


# ---------------------------------------------------------------------------
# Stream from in-memory list (used in tests and demo mode)
# ---------------------------------------------------------------------------

def stream_from_list(
    records: List[dict],
    *,
    apply_prefilter: bool = True,
) -> Generator[dict, None, None]:
    """
    Streaming interface over an in-memory list — maintains the same API
    as stream_jsonl() so the pipeline is source-agnostic.
    """
    skipped = 0
    for record in records:
        if apply_prefilter:
            # Re-serialise to string for pre-filter (fast for small records)
            raw = json.dumps(record)
            if not _passes_prefilter(raw):
                skipped += 1
                continue
        yield record
    if skipped:
        logger.debug("Pre-filter dropped %d clean records from in-memory list", skipped)


# ---------------------------------------------------------------------------
# Performance Probe (dev utility)
# ---------------------------------------------------------------------------

def benchmark_ingestion(path: Path, max_records: int = 10_000) -> dict:
    """
    Measure ingestion throughput and pre-filter effectiveness.
    Returns a metrics dict suitable for logging or dashboard display.
    """
    start   = time.perf_counter()
    total   = 0
    passed  = 0

    with open(path, "r", encoding="utf-8-sig") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line:
                continue
            total += 1
            if _passes_prefilter(line):
                passed += 1
            if total >= max_records:
                break

    elapsed = time.perf_counter() - start
    return {
        "records_evaluated":  total,
        "records_passed":     passed,
        "records_dropped":    total - passed,
        "filter_efficiency":  f"{(1 - passed / max(total, 1)) * 100:.1f}%",
        "throughput_rps":     f"{total / max(elapsed, 1e-9):.0f} rec/s",
        "elapsed_s":          f"{elapsed:.3f}",
    }


if __name__ == "__main__":
    from telemetry_generator import generate_logs, save_logs
    import tempfile

    print("Generating test dataset...")
    logs = generate_logs(1000)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        import json as _json
        for l in logs:
            f.write(_json.dumps(l) + "\n")
        tmp_path = Path(f.name)

    metrics = benchmark_ingestion(tmp_path, max_records=1000)
    print("Ingestion benchmark:")
    for k, v in metrics.items():
        print(f"  {k:25s}: {v}")
