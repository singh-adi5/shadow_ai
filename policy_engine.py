"""
Shadow AI Detector — Policy Logic Engine
==========================================
NIST SP 800-53: AC-2 (Account Management), AC-3 (Access Enforcement),
                IR-4 (Incident Handling)
OWASP Top 10 (2021): A01 — Broken Access Control

Key architectural fixes over original:
  1. Uses shared models.py types — no local ScanResult dataclass.
  2. Entity access via .get("entity_type") — handles both Pydantic .model_dump()
     output AND raw Presidio RecognizerResult dicts uniformly.
  3. AlertLevel / PolicyAction inherit from str → JSON-serialisable natively.
  4. Engine is fully stateless — safe for asyncio / threaded execution.
  5. score_threat() and evaluate_threat() accept Dict[str, Any] — no dataclass
     vs dict confusion.
  6. Pre-compiled AI-domain patterns imported from config (never re-compiled).
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from config import (
    COMPILED_AI_PATTERNS,
    ENTITY_SCORE_PER_COUNT,
    ENTITY_SCORE_WEIGHTS,
    AI_ENDPOINT_SCORE_MULTIPLIER,
    HIGH_RISK_ENTITY_TYPES,
    MAX_THREAT_SCORE,
)
from models import AlertLevel, PolicyAction, PolicyAlert, ScanResult


# ============================================================================
# Core Policy Engine — STATELESS
# ============================================================================

class ThreatPolicyEngine:
    """
    Stateless threat evaluation engine.

    All methods operate exclusively on their arguments — no instance state
    is mutated, making this class safe for concurrent use without locks.
    """

    # ------------------------------------------------------------------
    # AI Endpoint Detection (uses pre-compiled patterns from config.py)
    # ------------------------------------------------------------------

    @staticmethod
    def is_ai_endpoint(destination_url: str) -> bool:
        """
        O(k) pattern match against pre-compiled AI domain regex set.
        k = number of patterns (constant), independent of payload size.
        """
        url_lower = destination_url.lower()
        return any(p.search(url_lower) for p in COMPILED_AI_PATTERNS)

    # ------------------------------------------------------------------
    # Entity Extraction Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_entity_type(entity: Dict[str, Any]) -> str:
        """
        Normalise entity dicts from multiple sources:
          - Presidio RecognizerResult.__dict__  → {"entity_type": ..., "score": ...}
          - Pydantic EntityDetection.to_dict()  → {"entity_type": ..., "confidence": ...}
          - Legacy demo dict                    → {"type": ...}   (fallback)
        """
        return (
            entity.get("entity_type")
            or entity.get("type")
            or "UNKNOWN"
        )

    @classmethod
    def _extract_entities(cls, scan_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Pull entities_found out of any dict format used in the pipeline."""
        raw = scan_dict.get("entities_found", [])
        # Presidio may return RecognizerResult objects rather than dicts
        normalised = []
        for e in raw:
            if isinstance(e, dict):
                normalised.append(e)
            else:
                # RecognizerResult or similar — convert to dict
                normalised.append({
                    "entity_type": getattr(e, "entity_type", "UNKNOWN"),
                    "value":       "[REDACTED]",
                    "start":       getattr(e, "start", 0),
                    "end":         getattr(e, "end", 0),
                    "confidence":  getattr(e, "score", 0.0),
                })
        return normalised

    # ------------------------------------------------------------------
    # Threat Score (NIST: Risk = Likelihood × Impact)
    # ------------------------------------------------------------------

    def score_threat(self, scan_dict: Dict[str, Any]) -> int:
        """
        Calculate a normalised threat score in [0, 100].

        Scoring model:
          base = count × ENTITY_SCORE_PER_COUNT
                 + Σ ENTITY_SCORE_WEIGHTS[entity_type]
          if AI endpoint: base × AI_ENDPOINT_SCORE_MULTIPLIER
          final = min(base, MAX_THREAT_SCORE)
        """
        entities      = self._extract_entities(scan_dict)
        destination   = scan_dict.get("destination_url", "")

        score = len(entities) * ENTITY_SCORE_PER_COUNT

        for e in entities:
            etype  = self._get_entity_type(e)
            score += ENTITY_SCORE_WEIGHTS.get(etype, 5)

        if self.is_ai_endpoint(destination):
            score *= AI_ENDPOINT_SCORE_MULTIPLIER

        return min(score, MAX_THREAT_SCORE)

    # ------------------------------------------------------------------
    # Core 10-Line Threat Evaluation Policy
    # ------------------------------------------------------------------

    def evaluate_threat(
        self,
        scan_dict: Dict[str, Any],
        log_entry: Dict[str, Any],
    ) -> PolicyAlert:
        """
        SHADOW AI DETECTION POLICY:

        1.  Normalise scan_dict → extract destination_url, entities, log_id
        2.  Test destination_url against AI endpoint pattern matrix
        3.  Count entities and identify HIGH_RISK types
        4.  IF ai_endpoint AND entities AND high_risk_type → CRITICAL / BLOCK
        5.  ELIF ai_endpoint AND entities              → WARNING / ALERT
        6.  ELSE                                       → INFO    / LOG
        7.  Calculate threat_score
        8.  Build PolicyAlert with full audit fields
        9.  Return alert (caller persists / dispatches)
        10. Engine remains stateless — no side effects
        """
        destination    = scan_dict.get("destination_url", "")
        entities       = self._extract_entities(scan_dict)
        log_id         = scan_dict.get("log_id", "UNKNOWN")
        entity_count   = len(entities)

        is_ai          = self.is_ai_endpoint(destination)
        high_risk      = any(
            self._get_entity_type(e) in HIGH_RISK_ENTITY_TYPES
            for e in entities
        )

        # Policy decision tree
        if is_ai and entity_count > 0 and high_risk:
            threat_level = AlertLevel.CRITICAL
            action       = PolicyAction.BLOCK
            message      = (
                f"SHADOW AI EXFILTRATION: {entity_count} high-risk PII entities "
                f"transmitted to AI endpoint [{destination}]"
            )
            remediation  = (
                "Block egress connection immediately. Notify CISO and Security Ops. "
                "Preserve network pcap for forensic review. Review user entitlements."
            )

        elif is_ai and entity_count > 0:
            threat_level = AlertLevel.WARNING
            action       = PolicyAction.ALERT
            message      = (
                f"Sensitive entity detected in payload destined for AI endpoint "
                f"[{destination}] — {entity_count} entity/entities found"
            )
            remediation  = (
                "Investigate user intent. Log incident to SIEM. "
                "Check whether AI endpoint is on the approved Shadow AI register."
            )

        elif is_ai:
            threat_level = AlertLevel.INFO
            action       = PolicyAction.LOG
            message      = f"AI endpoint access observed: {destination} — no PII detected"
            remediation  = "No immediate action. Retain log for baseline analytics."

        else:
            threat_level = AlertLevel.INFO
            action       = PolicyAction.LOG
            message      = "Normal business endpoint activity — no anomaly detected"
            remediation  = "Continue monitoring."

        threat_score = self.score_threat(scan_dict)

        return PolicyAlert(
            alert_id       = (
                f"ALERT-{log_entry.get('user_id', 'UNKNOWN')}"
                f"-{int(datetime.now().timestamp() * 1000)}"
            ),
            timestamp      = datetime.now().isoformat(),
            log_id         = log_id,
            user_id        = log_entry.get("user_id", "UNKNOWN"),
            department     = log_entry.get("department", "UNKNOWN"),
            destination_url= destination,
            entity_types   = [self._get_entity_type(e) for e in entities],
            entity_count   = entity_count,
            threat_level   = threat_level,
            action         = action,
            message        = message,
            remediation    = remediation,
            threat_score   = threat_score,
        )


# ============================================================================
# Policy Rule Engine — extensible plug-in framework
# ============================================================================

class PolicyRuleSet:
    """
    Composable rule engine that chains additional policy rules on top of
    the core ThreatPolicyEngine.evaluate_threat() baseline.

    Rules are callables with the signature:
        rule(scan_dict: dict, log_entry: dict, engine: ThreatPolicyEngine)
            -> Optional[PolicyAlert]

    None return → rule did not fire (predicate not satisfied).
    """

    def __init__(self) -> None:
        self.rules:         List[Callable] = []
        self.policy_engine: ThreatPolicyEngine = ThreatPolicyEngine()

    def add_rule(self, rule_func: Callable) -> "PolicyRuleSet":
        """Fluent builder — policy_rules.add_rule(r1).add_rule(r2)"""
        self.rules.append(rule_func)
        return self

    def evaluate_all(
        self,
        scan_result: ScanResult | Dict[str, Any],
        log_entry:   Dict[str, Any],
    ) -> List[PolicyAlert]:
        """
        Evaluate the baseline policy and all registered rules.

        Accepts either a ScanResult Pydantic model or a plain dict —
        normalisation happens here so callers need not convert manually.
        """
        # Normalise: Pydantic model → dict for uniform downstream handling
        if isinstance(scan_result, ScanResult):
            scan_dict = scan_result.to_policy_dict()
        else:
            scan_dict = scan_result

        alerts: List[PolicyAlert] = []

        # 1. Baseline policy
        alerts.append(self.policy_engine.evaluate_threat(scan_dict, log_entry))

        # 2. Custom rules
        for rule in self.rules:
            alert: Optional[PolicyAlert] = rule(
                scan_dict, log_entry, self.policy_engine
            )
            if alert is not None:
                alerts.append(alert)

        return alerts


# ============================================================================
# Predefined Policy Rules
# ============================================================================

def rule_department_restriction(
    scan_dict:  Dict[str, Any],
    log_entry:  Dict[str, Any],
    engine:     ThreatPolicyEngine,
) -> Optional[PolicyAlert]:
    """
    OWASP A01 — Broken Access Control
    Sales department must not transmit any entity data to unsanctioned AI endpoints.
    """
    department   = log_entry.get("department", "")
    destination  = scan_dict.get("destination_url", "")
    entities     = ThreatPolicyEngine._extract_entities(scan_dict)
    log_id       = scan_dict.get("log_id", "UNKNOWN")

    restricted_depts = {"Sales", "HR", "Finance"}

    if department in restricted_depts and engine.is_ai_endpoint(destination) and entities:
        return PolicyAlert(
            alert_id       = f"POLICY-DEPT-{int(datetime.now().timestamp() * 1000)}",
            timestamp      = datetime.now().isoformat(),
            log_id         = log_id,
            user_id        = log_entry.get("user_id", "UNKNOWN"),
            department     = department,
            destination_url= destination,
            entity_types   = [
                ThreatPolicyEngine._get_entity_type(e) for e in entities
            ],
            entity_count   = len(entities),
            threat_level   = AlertLevel.CRITICAL,
            action         = PolicyAction.ESCALATE,
            message        = (
                f"POLICY VIOLATION: Restricted department [{department}] transmitted "
                f"PII to AI endpoint [{destination}]"
            ),
            remediation    = (
                "Escalate to CISO immediately. Suspend user session. "
                "Initiate DLP incident ticket. Review department AI usage policy."
            ),
            threat_score   = 100,
        )
    return None


def rule_after_hours_access(
    scan_dict:  Dict[str, Any],
    log_entry:  Dict[str, Any],
    engine:     ThreatPolicyEngine,
) -> Optional[PolicyAlert]:
    """
    NIST AU-3 — Content of Audit Records
    AI endpoint access outside business hours (UTC 06:00–22:00, Mon–Fri) is anomalous.
    """
    destination = scan_dict.get("destination_url", "")
    entities    = ThreatPolicyEngine._extract_entities(scan_dict)
    log_id      = scan_dict.get("log_id", "UNKNOWN")

    now      = datetime.utcnow()
    hour     = now.hour
    weekday  = now.weekday()   # 0=Mon … 6=Sun

    is_weekend    = weekday >= 5
    is_after_hours = hour < 6 or hour >= 22

    if (is_weekend or is_after_hours) and engine.is_ai_endpoint(destination):
        period = "weekend" if is_weekend else "after-hours"
        return PolicyAlert(
            alert_id       = f"POLICY-HOURS-{int(datetime.now().timestamp() * 1000)}",
            timestamp      = datetime.now().isoformat(),
            log_id         = log_id,
            user_id        = log_entry.get("user_id", "UNKNOWN"),
            department     = log_entry.get("department", "UNKNOWN"),
            destination_url= destination,
            entity_types   = [
                ThreatPolicyEngine._get_entity_type(e) for e in entities
            ],
            entity_count   = len(entities),
            threat_level   = AlertLevel.WARNING,
            action         = PolicyAction.ALERT,
            message        = (
                f"Anomalous {period} AI endpoint access detected — "
                f"UTC {now.strftime('%H:%M')} {now.strftime('%A')}"
            ),
            remediation    = (
                "Review user activity log for account compromise indicators. "
                "Cross-reference with VPN authentication records."
            ),
            threat_score   = engine.score_threat(scan_dict),
        )
    return None


def rule_high_volume_exfiltration(
    scan_dict:  Dict[str, Any],
    log_entry:  Dict[str, Any],
    engine:     ThreatPolicyEngine,
) -> Optional[PolicyAlert]:
    """
    Volume-based exfiltration heuristic: ≥ 4 entities in a single payload
    warrants an independent escalation regardless of entity type.
    """
    destination  = scan_dict.get("destination_url", "")
    entities     = ThreatPolicyEngine._extract_entities(scan_dict)
    log_id       = scan_dict.get("log_id", "UNKNOWN")

    HIGH_VOLUME_THRESHOLD = 4

    if (
        engine.is_ai_endpoint(destination)
        and len(entities) >= HIGH_VOLUME_THRESHOLD
    ):
        return PolicyAlert(
            alert_id       = f"POLICY-VOL-{int(datetime.now().timestamp() * 1000)}",
            timestamp      = datetime.now().isoformat(),
            log_id         = log_id,
            user_id        = log_entry.get("user_id", "UNKNOWN"),
            department     = log_entry.get("department", "UNKNOWN"),
            destination_url= destination,
            entity_types   = [
                ThreatPolicyEngine._get_entity_type(e) for e in entities
            ],
            entity_count   = len(entities),
            threat_level   = AlertLevel.CRITICAL,
            action         = PolicyAction.BLOCK,
            message        = (
                f"HIGH-VOLUME EXFILTRATION: {len(entities)} PII entities in a single "
                f"request to AI endpoint [{destination}]"
            ),
            remediation    = (
                "Block user session. Capture request payload for forensic analysis. "
                "File P1 DLP incident. Notify Legal if GDPR-relevant data confirmed."
            ),
            threat_score   = min(engine.score_threat(scan_dict) + 20, 100),
        )
    return None


# ============================================================================
# Module-level singletons
# ============================================================================

policy_engine = ThreatPolicyEngine()

policy_rules = PolicyRuleSet()
policy_rules.add_rule(rule_department_restriction)
policy_rules.add_rule(rule_after_hours_access)
policy_rules.add_rule(rule_high_volume_exfiltration)


if __name__ == "__main__":
    print("Policy Engine initialised — 3 rules loaded.")
    print(f"AI detection patterns: {len(COMPILED_AI_PATTERNS)}")
    print(f"High-risk entity types: {HIGH_RISK_ENTITY_TYPES}")
