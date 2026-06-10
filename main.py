"""
Shadow AI Detector — Production Pipeline Orchestrator 
=========================================================
NIST SP 800-53: IR-1 (Incident Response Planning), SI-4 (System Monitoring)

Architecture (addressing all three production gaps from review):

      stream_jsonl() reads JSONL line-by-line. Heap footprint = O(BATCH_SIZE).
    Multi-GB enterprise log files processed without OOM risk.

      ProcessPoolExecutor dispatches scan_record() across all CPU cores.
    Presidio AnalyzerEngine initialised once per worker process (not per record).
    Throughput scales linearly with core count.

      scan_record() is a pure function — zero shared state between workers.
    Each OS process has isolated memory. No dict races, no GIL contention.
    Policy engine remains stateless (unchanged from ).

Execution model:
  Ingestion (O(1) streaming)
    → Pre-filter (regex, drops clean traffic in O(1))
    → Micro-batch (BATCH_SIZE records per submission)
    → Worker pool (parallel Presidio NLP across cores)
    → Policy engine (stateless, applied per result)
    → Alert output (streaming — alerts written as they arrive)
"""

from __future__ import annotations

import argparse
import json
import logging
import multiprocessing
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("shadow_ai_detector.main")

# ---------------------------------------------------------------------------
# Dependency guard
# ---------------------------------------------------------------------------
try:
    from config import config, COMPILED_AI_PATTERNS
    from models import (
        AlertLevel, EntityDetection, PolicyAlert, ScanResult
    )
    from telemetry_generator import generate_logs, save_logs
    from ingestion import stream_from_list, stream_jsonl, micro_batch, BATCH_SIZE
    from scanner_worker import ScannerWorkerPool, scan_record_local
    from policy_engine import policy_rules, ThreatPolicyEngine
    from alert_output import AlertOutputter
except ImportError as exc:
    print(f"❌ Import error: {exc}")
    print("   pip install -r requirements.txt")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Execution telemetry decorator
# ---------------------------------------------------------------------------

import functools

def _timed(label: str):
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*a, **kw):
            t0     = time.perf_counter()
            result = fn(*a, **kw)
            elapsed = time.perf_counter() - t0
            logger.info("[MTTP] %s: %.3fs", label, elapsed)
            print(f"  ⏱  [{label}] {elapsed:.3f}s")
            return result
        return wrapper
    return deco


# ---------------------------------------------------------------------------
# Result → ScanResult adapter
# ---------------------------------------------------------------------------

def _dict_to_scan_result(d: Dict[str, Any]) -> ScanResult:
    """Convert a worker result dict to a ScanResult Pydantic model."""
    return ScanResult(
        log_id             = d["log_id"],
        destination_url    = d["destination_url"],
        user_id            = d["user_id"],
        department         = d["department"],
        source_ip          = d["source_ip"],
        entities_found     = [
            EntityDetection(**e) for e in d.get("entities_found", [])
        ],
        is_sensitive_to_ai = d.get("is_sensitive_to_ai", False),
        severity           = d.get("severity", "low"),
        recommended_action = d.get("recommended_action", "MONITOR"),
        timestamp          = d.get("timestamp", datetime.utcnow().isoformat()),
    )


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

class ShadowAIDetectorPipeline:
    """
    Production-grade 4-stage detection pipeline.

    Memory model:
      - Stage 1 output: O(BATCH_SIZE) at any point in time
      - Stage 2 output: streamed — alerts written as workers complete
      - Stage 3/4:      O(total_alerts) — alerts are small (< 1 KB each)
    """

    def __init__(
        self,
        output_dir:  Path         = Path(config.OUTPUT_DIR),
        workers:     Optional[int]= None,
        use_pool:    bool         = True,
    ) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self._workers   = workers
        self._use_pool  = use_pool
        self._engine    = ThreatPolicyEngine()
        self._outputter = AlertOutputter(self.output_dir)

        # Runtime counters — reset per pipeline.run() call
        self._n_scanned  = 0
        self._n_threats  = 0
        self._n_critical = 0
        self._alerts:  List[PolicyAlert] = []

        cpu = multiprocessing.cpu_count()
        effective_workers = workers or min(cpu, 8)
        print(f"  Pipeline config: {effective_workers} worker(s), "
              f"batch_size={BATCH_SIZE}, "
              f"{'ProcessPool' if use_pool else 'single-process'}")

    # ------------------------------------------------------------------
    # Stage 1: Synthetic Telemetry (or load from file)
    # ------------------------------------------------------------------

    @_timed("Stage 1 — Telemetry")
    def stage1_generate(self, num_logs: int = 1_000) -> Path:
        print("\n" + "=" * 72)
        print("STAGE 1 — SYNTHETIC TELEMETRY GENERATION")
        print("=" * 72)

        logs      = generate_logs(num_logs)
        logs_path = self.output_dir / "proxy_logs.jsonl"
        save_logs(logs, logs_path)

        sensitive = sum(1 for l in logs if l.get("threat_model_label") == "SENSITIVE_DATA_TO_AI")
        ai_all    = sum(1 for l in logs if l.get("threat_model_label") in {"SENSITIVE_DATA_TO_AI", "NORMAL_AI"})
        print(f"  ✓ {num_logs} logs → {logs_path}")
        print(f"  Clean traffic         : {num_logs - ai_all}")
        print(f"  Benign AI usage       : {ai_all - sensitive}")
        print(f"  Shadow AI (threats)   : {sensitive}")

        return logs_path

    # ------------------------------------------------------------------
    # Stage 2 + 3: Parallel scan → policy evaluation (streaming)
    # ------------------------------------------------------------------

    @_timed("Stage 2+3 — Scan + Policy")
    def stage2_3_scan_and_evaluate(self, source_path: Path) -> List[PolicyAlert]:
        """
        Stream the JSONL file through the worker pool and policy engine.

        This stage intentionally fuses scanning and policy evaluation into
        one streaming pass — results flow from worker → policy engine → alert
        list without accumulating intermediate ScanResult objects in heap.
        """
        print("\n" + "=" * 72)
        print("STAGE 2+3 — PARALLEL SCAN + POLICY EVALUATION")
        print(f"           Source: {source_path}")
        print("=" * 72)

        alerts:    List[PolicyAlert] = []
        processed  = 0
        threats    = 0
        critical   = 0

        # O(1) streaming source — file is never fully loaded into memory
        record_stream = stream_jsonl(source_path, apply_prefilter=True)
        batches       = micro_batch(record_stream, batch_size=BATCH_SIZE)

        def _handle_result(result_dict: Dict[str, Any]) -> None:
            """
            Called by the worker pool for each completed scan result.
            Runs in the MAIN PROCESS — safe to mutate alerts[].
            """
            nonlocal processed, threats, critical

            processed += 1
            sr = _dict_to_scan_result(result_dict)

            # Build minimal log_entry context for policy engine
            log_entry = {
                "user_id":    sr.user_id,
                "department": sr.department,
                "source_ip":  sr.source_ip,
            }

            batch_alerts = policy_rules.evaluate_all(sr, log_entry)
            alerts.extend(batch_alerts)

            if sr.is_sensitive_to_ai:
                threats += 1

            for a in batch_alerts:
                if a.threat_level.value in {"CRITICAL", "BLOCK"}:
                    critical += 1
                    # Stream critical alerts to stdout immediately
                    print(
                        f"  🔴 CRITICAL [{a.alert_id[:20]}] "
                        f"{a.user_id}@{a.destination_url} "
                        f"({a.entity_count} entities)"
                    )

            if processed % 100 == 0:
                logger.info(
                    "Progress: processed=%d threats=%d critical=%d",
                    processed, threats, critical,
                )

        if self._use_pool:
            with ScannerWorkerPool(workers=self._workers) as pool:
                for result in pool.scan_stream(batches, on_result=None):
                    _handle_result(result)
        else:
            # Fallback: single-process (useful for debugging)
            for batch in batches:
                for record in batch:
                    result = scan_record_local(record)
                    if result:
                        _handle_result(result)

        self._n_scanned  = processed
        self._n_threats  = threats
        self._n_critical = critical
        self._alerts     = alerts

        print(f"\n  ✓ Records processed : {processed}")
        print(f"  Threats detected    : {threats}")
        print(f"  🔴 CRITICAL alerts  : {critical}")
        print(f"  Total alerts        : {len(alerts)}")

        return alerts

    # ------------------------------------------------------------------
    # Stage 4: Output & Export
    # ------------------------------------------------------------------

    @_timed("Stage 4 — Output")
    def stage4_output(self) -> None:
        print("\n" + "=" * 72)
        print("STAGE 4 — ALERT OUTPUT & EXPORT")
        print("=" * 72)

        if not self._alerts:
            print("  ✓ No alerts to export.")
            return

        self._outputter.ingest(self._alerts)
        self._outputter.display_critical(max_shown=5)
        exported = self._outputter.export_all(prefix="shadow_ai_alerts")
        self._outputter.print_summary()

        print("\n  📁 Exported artefacts:")
        for fmt, path in exported.items():
            print(f"     {fmt.upper():8s} → {path}")

    # ------------------------------------------------------------------
    # Full Pipeline
    # ------------------------------------------------------------------

    def run(self, num_logs: int = 1_000, source_file: Optional[Path] = None) -> int:
        wall_start = time.perf_counter()

        print("\n" + "=" * 72)
        print("🔒  SHADOW AI DETECTOR — PRODUCTION PIPELINE ")
        print("=" * 72)
        print(f"    Output dir  : {self.output_dir.absolute()}")
        print(f"    Started     : {datetime.utcnow().isoformat()}Z")
        print("=" * 72)

        try:
            if source_file and source_file.exists():
                logs_path = source_file
                print(f"\n  ℹ Using existing log file: {logs_path}")
            else:
                logs_path = self.stage1_generate(num_logs)

            self.stage2_3_scan_and_evaluate(logs_path)
            self.stage4_output()

        except KeyboardInterrupt:
            print("\n❌ Pipeline interrupted.")
            return 1
        except Exception as exc:
            import traceback
            logger.error("Pipeline error: %s", exc, exc_info=True)
            print(f"\n❌ Pipeline error: {exc}")
            traceback.print_exc()
            return 1

        elapsed = time.perf_counter() - wall_start
        rps = self._n_scanned / max(elapsed, 1e-9)

        print(f"\n{'=' * 72}")
        print(f"✅  PIPELINE COMPLETE")
        print(f"    Wall-clock : {elapsed:.2f}s")
        print(f"    Throughput : {rps:.0f} records/s")
        print(f"    Records    : {self._n_scanned}")
        print(f"    Threats    : {self._n_threats}")
        print(f"    Critical   : {self._n_critical}")
        print(f"{'=' * 72}")
        return 0


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Shadow AI Detector — production detection pipeline"
    )
    parser.add_argument("--logs",       type=int,  default=1_000,
                        help="Number of synthetic proxy logs (default: 1000)")
    parser.add_argument("--workers",    type=int,  default=None,
                        help="Worker process count (default: cpu_count)")
    parser.add_argument("--output-dir", type=str,  default=config.OUTPUT_DIR,
                        help="Output directory for artefacts")
    parser.add_argument("--source",     type=str,  default=None,
                        help="Existing JSONL log file to scan instead of generating")
    parser.add_argument("--no-pool",    action="store_true",
                        help="Disable ProcessPoolExecutor (single-process debug mode)")
    args = parser.parse_args()

    pipeline = ShadowAIDetectorPipeline(
        output_dir = Path(args.output_dir),
        workers    = args.workers,
        use_pool   = not args.no_pool,
    )
    source = Path(args.source) if args.source else None
    return pipeline.run(num_logs=args.logs, source_file=source)


if __name__ == "__main__":
    sys.exit(main())
