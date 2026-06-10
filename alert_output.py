"""
Shadow AI Detector — Alert Output & Export System
===================================================
NIST SP 800-53: AU-3 (Content of Audit Records), AU-12 (Audit Generation)
OWASP Top 10 (2021): A09 — Logging and Monitoring Failures

Key fixes over original:
  1. PolicyAlert.to_dict() produces JSON-safe output (str-Enums = no TypeError).
  2. asdict() result is passed through .to_dict() — no manual enum patching needed.
  3. Loki export uses PolicyAlert.to_loki_stream() from models.py.
  4. Rich is optional — plain-text fallback requires zero additional deps.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import List

from models import AlertLevel, PolicyAction, PolicyAlert

# ---------------------------------------------------------------------------
# Optional Rich dependency
# ---------------------------------------------------------------------------
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    _HAS_RICH = True
except ImportError:
    _HAS_RICH = False

_SEVERITY_COLOURS = {
    AlertLevel.CRITICAL: "bold red",
    AlertLevel.BLOCK:    "bold red",
    AlertLevel.WARNING:  "yellow",
    AlertLevel.INFO:     "green",
}

_SEVERITY_EMOJI = {
    AlertLevel.CRITICAL: "🔴",
    AlertLevel.BLOCK:    "🔴",
    AlertLevel.WARNING:  "🟡",
    AlertLevel.INFO:     "🟢",
}


# ============================================================================
# Alert Formatter
# ============================================================================

class AlertFormatter:
    """
    Formats PolicyAlert objects for terminal, JSON, and JSONL (Grafana Loki) output.
    """

    def __init__(self) -> None:
        self._console: Console | None = Console() if _HAS_RICH else None
        self._alerts:  List[PolicyAlert] = []

    # ------------------------------------------------------------------
    # Accumulator
    # ------------------------------------------------------------------

    def add_alert(self, alert: PolicyAlert) -> None:
        self._alerts.append(alert)

    def clear(self) -> None:
        self._alerts.clear()

    @property
    def alerts(self) -> List[PolicyAlert]:
        return list(self._alerts)

    # ------------------------------------------------------------------
    # Terminal Output
    # ------------------------------------------------------------------

    def print_alert(self, alert: PolicyAlert, *, verbose: bool = True) -> None:
        if self._console and _HAS_RICH:
            self._print_rich(alert, verbose=verbose)
        else:
            self._print_plain(alert, verbose=verbose)

    def _print_rich(self, alert: PolicyAlert, *, verbose: bool) -> None:
        assert self._console is not None
        colour  = _SEVERITY_COLOURS.get(alert.threat_level, "white")
        emoji   = _SEVERITY_EMOJI.get(alert.threat_level, "⚪")
        title   = f"[{colour}]{emoji} {alert.threat_level.value} — {alert.alert_id}[/{colour}]"

        body = (
            f"[bold]Timestamp   :[/bold] {alert.timestamp}\n"
            f"[bold]User        :[/bold] {alert.user_id} ({alert.department})\n"
            f"[bold]Destination :[/bold] {alert.destination_url}\n"
            f"[bold]Threat      :[/bold] {alert.message}\n"
            f"[bold]Entities    :[/bold] {', '.join(alert.entity_types) or 'None'}\n"
            f"[bold]Count       :[/bold] {alert.entity_count}\n"
            f"[bold]Score       :[/bold] {alert.threat_score}/100\n"
            f"[bold]Action      :[/bold] {alert.action.value}\n"
        )
        if verbose:
            body += f"[bold]Remediation :[/bold] {alert.remediation}\n"

        self._console.print(Panel(body, title=title, border_style=colour, expand=False))

    def _print_plain(self, alert: PolicyAlert, *, verbose: bool) -> None:
        emoji = _SEVERITY_EMOJI.get(alert.threat_level, "⚪")
        print("\n" + "=" * 72)
        print(f"{emoji} [{alert.threat_level.value}] {alert.alert_id}")
        print(f"  Timestamp   : {alert.timestamp}")
        print(f"  User        : {alert.user_id} ({alert.department})")
        print(f"  Destination : {alert.destination_url}")
        print(f"  Threat      : {alert.message}")
        print(f"  Entities    : {', '.join(alert.entity_types) or 'None'}")
        print(f"  Count       : {alert.entity_count}   Score: {alert.threat_score}/100")
        print(f"  Action      : {alert.action.value}")
        if verbose:
            print(f"  Remediation : {alert.remediation}")
        print("=" * 72)

    # ------------------------------------------------------------------
    # Summary Statistics
    # ------------------------------------------------------------------

    def print_summary(self) -> None:
        counts = {level: 0 for level in AlertLevel}
        for a in self._alerts:
            counts[a.threat_level] += 1

        print("\n" + "=" * 72)
        print("📊  ALERT SUMMARY")
        print("=" * 72)
        print(f"  Total alerts   : {len(self._alerts)}")
        print(f"  🔴 CRITICAL    : {counts[AlertLevel.CRITICAL]}")
        print(f"  🔴 BLOCK       : {counts[AlertLevel.BLOCK]}")
        print(f"  🟡 WARNING     : {counts[AlertLevel.WARNING]}")
        print(f"  🟢 INFO        : {counts[AlertLevel.INFO]}")

        if self._alerts:
            avg_score = sum(a.threat_score for a in self._alerts) / len(self._alerts)
            max_score = max(a.threat_score for a in self._alerts)
            print(f"  Avg threat score : {avg_score:.1f}/100")
            print(f"  Max threat score : {max_score}/100")
        print("=" * 72)

    # ------------------------------------------------------------------
    # Export: JSON (SIEM-ready)
    # ------------------------------------------------------------------

    def export_json(self, filepath: Path) -> None:
        """
        Export all alerts to a JSON array.
        PolicyAlert.to_dict() guarantees JSON serialisability
        (str-Enums serialise natively — no TypeError).
        """
        filepath.parent.mkdir(parents=True, exist_ok=True)
        payload = [a.to_dict() for a in self._alerts]
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
        print(f"✓ Exported {len(self._alerts)} alerts → {filepath}")

    # ------------------------------------------------------------------
    # Export: JSONL (Grafana Loki)
    # ------------------------------------------------------------------

    def export_jsonl(self, filepath: Path) -> None:
        """JSONL line-per-alert format compatible with Grafana Loki push API."""
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as fh:
            for alert in self._alerts:
                fh.write(json.dumps(alert.to_dict(), ensure_ascii=False) + "\n")
        print(f"✓ Exported {len(self._alerts)} alerts (JSONL) → {filepath}")

    # ------------------------------------------------------------------
    # Export: Grafana Loki Push Format
    # ------------------------------------------------------------------

    def export_loki_push(self, filepath: Path) -> None:
        """
        Writes a Loki-compatible push-API payload for each alert.
        Use with: curl -X POST http://loki:3100/loki/api/v1/push
                       --data-binary @<filepath>
        """
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as fh:
            for alert in self._alerts:
                fh.write(json.dumps(alert.to_loki_stream(), ensure_ascii=False) + "\n")
        print(f"✓ Exported {len(self._alerts)} Loki streams → {filepath}")


# ============================================================================
# High-Level Outputter (used by main.py)
# ============================================================================

class AlertOutputter:
    """
    Orchestrates terminal display and multi-format export for a list of alerts.
    """

    def __init__(self, output_dir: Path = Path("./threat_model_output")) -> None:
        self.output_dir = Path(output_dir)
        self.formatter  = AlertFormatter()

    def ingest(self, alerts: List[PolicyAlert]) -> None:
        """Load alerts into the formatter queue."""
        for a in alerts:
            self.formatter.add_alert(a)

    def display_critical(self, max_shown: int = 10) -> None:
        """Print the top N critical alerts to the terminal."""
        critical = [
            a for a in self.formatter.alerts
            if a.threat_level in (AlertLevel.CRITICAL, AlertLevel.BLOCK)
        ]
        if not critical:
            print("✓ No CRITICAL alerts in this batch.")
            return

        count = min(len(critical), max_shown)
        print(f"\n🚨 Displaying {count} of {len(critical)} CRITICAL alerts:\n")
        for alert in critical[:count]:
            self.formatter.print_alert(alert, verbose=True)

        if len(critical) > max_shown:
            print(f"\n  … and {len(critical) - max_shown} more critical alerts.\n")

    def display_all(self) -> None:
        """Print every alert regardless of severity."""
        for alert in self.formatter.alerts:
            self.formatter.print_alert(alert, verbose=False)

    def export_all(
        self,
        *,
        prefix: str = "alerts",
    ) -> dict[str, Path]:
        """Write JSON, JSONL, and Loki-push exports. Returns paths written."""
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        paths = {
            "json":  self.output_dir / f"{prefix}_{ts}.json",
            "jsonl": self.output_dir / f"{prefix}_{ts}.jsonl",
            "loki":  self.output_dir / f"{prefix}_{ts}.loki.jsonl",
        }
        self.formatter.export_json(paths["json"])
        self.formatter.export_jsonl(paths["jsonl"])
        self.formatter.export_loki_push(paths["loki"])
        return paths

    def print_summary(self) -> None:
        self.formatter.print_summary()


if __name__ == "__main__":
    print("Alert Output System ready — Rich:", _HAS_RICH)
