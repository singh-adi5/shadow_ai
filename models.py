"""
Shadow AI Detector — Shared Data Models
========================================
Single source of truth for all data contracts between pipeline stages.
Resolves the #1 root cause of the original crashes: each module defined
its own ScanResult independently, creating incompatible type hierarchies.

Design principles:
  - Pydantic  models for all external I/O (FastAPI, file ingestion)
  - Plain dataclasses for pure-Python internal objects (policy engine)
  - Enums serialise to their .value string (JSON-safe by default via model_config)
  - No duplicate model definitions anywhere in the codebase
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ============================================================================
# Enums — both JSON-serialisable (value is a plain str)
# ============================================================================

class AlertLevel(str, Enum):
    """
    Severity levels for policy alerts.
    Inherits from str so json.dumps() works without a custom encoder.
    """
    INFO     = "INFO"
    WARNING  = "WARNING"
    CRITICAL = "CRITICAL"
    BLOCK    = "BLOCK"


class PolicyAction(str, Enum):
    """
    Remediation actions emitted by the policy engine.
    Inherits from str — fully JSON serialisable.
    """
    LOG        = "LOG"
    ALERT      = "ALERT"
    QUARANTINE = "QUARANTINE"
    BLOCK      = "BLOCK"
    ESCALATE   = "ESCALATE"


# ============================================================================
# Pydantic Models — FastAPI request/response contracts (external I/O)
# ============================================================================

class ProxyLog(BaseModel):
    """
    A single HTTP proxy log entry ingested from JSONL or the REST API.
    All validators run before data reaches the Presidio scanner.
    OWASP A05: Security Misconfiguration — strict type enforcement at boundary.
    """
    model_config = ConfigDict(str_strip_whitespace=True)

    timestamp:          str
    source_ip:          str
    user_id:            str
    department:         str
    destination_url:    str
    http_method:        str
    path:               str
    payload:            str
    response_code:      int
    response_time_ms:   int
    threat_model_label: Optional[str] = None

    @field_validator("destination_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        import re
        # Accept bare hostname (e.g. api.openai.com) or full URL
        if not re.match(r"^[a-zA-Z0-9.\-]+(:[0-9]+)?(/.*)?$", v):
            raise ValueError(f"Invalid destination_url: {v!r}")
        if len(v) > 2048:
            raise ValueError("destination_url exceeds 2048 characters")
        return v.lower()

    @field_validator("payload")
    @classmethod
    def validate_payload(cls, v: str) -> str:
        if len(v.encode()) > 10_000:
            raise ValueError("Payload exceeds 10 KB limit (OWASP DoS prevention)")
        return v

    @field_validator("source_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        parts = v.split(".")
        if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            raise ValueError(f"Invalid IPv4 address: {v!r}")
        return v

    @field_validator("http_method")
    @classmethod
    def validate_method(cls, v: str) -> str:
        allowed = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
        if v.upper() not in allowed:
            raise ValueError(f"Unsupported HTTP method: {v!r}")
        return v.upper()

    def log_hash(self) -> str:
        """SHA-256 fingerprint for de-duplication (never exposes raw PII)."""
        raw = f"{self.timestamp}:{self.source_ip}:{self.user_id}:{self.destination_url}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


class ScanRequest(BaseModel):
    """Batch scan request submitted to POST /scan."""
    logs:     List[ProxyLog] = Field(..., min_length=1)
    max_logs: int            = Field(1000, ge=1, le=10_000)


class EntityDetection(BaseModel):
    """
    A single detected PII/sensitive entity returned by the Presidio scanner.
    The 'value' field is ALWAYS '[REDACTED]' — raw PII is never propagated.
    """
    entity_type: str
    value:       str = "[REDACTED]"   # Data-minimisation guarantee (GDPR)
    start:       int
    end:         int
    confidence:  float

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class ScanResult(BaseModel):
    """
    Output contract for a single scanned log entry.
    This is the canonical ScanResult used by BOTH the REST layer AND the
    policy engine — eliminates the dict/dataclass mismatch that crashed main.py.
    """
    log_id:            str
    destination_url:   str
    user_id:           str
    department:        str
    source_ip:         str
    entities_found:    List[EntityDetection]
    is_sensitive_to_ai: bool
    severity:          str
    recommended_action: str
    timestamp:         str

    def entity_dicts(self) -> List[Dict[str, Any]]:
        """Returns entities as plain dicts for policy engine consumption."""
        return [e.to_dict() for e in self.entities_found]

    def to_policy_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dict compatible with ThreatPolicyEngine methods."""
        d = self.model_dump()
        # Flatten entities to the dict format policy_engine expects
        d["entities_found"] = self.entity_dicts()
        return d


class ScanResponse(BaseModel):
    """Aggregate response returned from POST /scan."""
    total_logs_scanned: int
    threats_detected:   int
    critical_alerts:    int
    results:            List[ScanResult]


# ============================================================================
# Dataclass — internal policy engine output (kept as dataclass for lightweight
# in-memory chaining; converted to dict for JSON export)
# ============================================================================

@dataclass
class PolicyAlert:
    """
    Alert generated by ThreatPolicyEngine.
    AlertLevel and PolicyAction are str-Enums, so they serialise natively
    via json.dumps() — no TypeError on AlertLevel serialisation.
    """
    alert_id:       str
    timestamp:      str
    log_id:         str
    user_id:        str
    department:     str
    destination_url: str
    entity_types:   List[str]
    entity_count:   int
    threat_level:   AlertLevel
    action:         PolicyAction
    message:        str
    remediation:    str
    threat_score:   int = 0

    def to_dict(self) -> Dict[str, Any]:
        """JSON-safe dict — Enum values are already plain strings."""
        d = asdict(self)
        # str-Enum fields are already strings; explicit cast ensures robustness
        d["threat_level"] = self.threat_level.value
        d["action"]       = self.action.value
        return d

    def to_loki_stream(self) -> Dict[str, Any]:
        """Grafana Loki push-compatible structure."""
        return {
            "streams": [{
                "stream": {
                    "job":          "shadow_ai_detector",
                    "threat_level": self.threat_level.value,
                    "department":   self.department,
                    "action":       self.action.value,
                },
                "values": [[
                    str(int(datetime.now().timestamp() * 1e9)),
                    __import__("json").dumps({
                        "alert_id":    self.alert_id,
                        "user_id":     self.user_id,
                        "destination": self.destination_url,
                        "message":     self.message,
                        "entities":    self.entity_types,
                        "score":       self.threat_score,
                        "remediation": self.remediation,
                    }),
                ]],
            }]
        }
