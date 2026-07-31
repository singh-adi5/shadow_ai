"""
Shadow AI Detector — Security Configuration
============================================
NIST SP 800-53 Controls: CM-2 (Baseline Configuration), SC-7 (Boundary Protection),
                          SC-13 (Cryptographic Protection)
OWASP Top 10 (2021): A05 — Security Misconfiguration

All AI-domain detection patterns are pre-compiled at module load time (O(1) lookup).
Mutable config fields are protected via __post_init__ defaults, never mutated at runtime.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Tuple

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Pre-compiled AI Endpoint Detection Matrix
# Compiled ONCE at import time — never re-compiled inside hot paths.
# ---------------------------------------------------------------------------
_RAW_AI_DOMAIN_PATTERNS: Tuple[str, ...] = (
    r"api\.openai\.com",
    r"claude\.ai",
    r"api\.anthropic\.com",
    r"api\.huggingface\.co",
    r"generativelanguage\.googleapis\.com",
    r"api\.cohere\.ai",
    r"api\.mistral\.ai",
)

# Immutable tuple of compiled patterns — protects against execution-phase mutation
COMPILED_AI_PATTERNS: Tuple[re.Pattern, ...] = tuple(
    re.compile(p, re.IGNORECASE) for p in _RAW_AI_DOMAIN_PATTERNS
)

# Human-readable display set (for logging/alerts — no compiled objects)
AI_DOMAIN_DISPLAY: FrozenSet[str] = frozenset(
    p.replace(r"\.", ".") for p in _RAW_AI_DOMAIN_PATTERNS
)

# ---------------------------------------------------------------------------
# Single source of truth for regex-fallback entity detection.
#
# These patterns back BOTH the O(1) ingestion pre-filter (ingestion.py) and
# the regex fallback scanners (scanner_worker.py, presidio_scanner.py) used
# when Presidio/spaCy is unavailable. Previously each of those three modules
# defined its own copy — two of which (ingestion.py, scanner_worker.py) used
# unbounded quantifiers on overlapping character classes in EMAIL_ADDRESS
# (e.g. `[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`), which backtracks catastrophically
# on adversarial input (measured: 9.4s on a 40KB payload). All patterns here
# use explicit {min,max} bounds and disjoint character classes — no pattern
# may contain an unbounded quantifier without a hard upper bound.
# ---------------------------------------------------------------------------
_RAW_FALLBACK_PATTERNS: Tuple[Tuple[str, str, int], ...] = (
    # Credit card: 13-19 digits with optional single-char separators. Bounded.
    ("CREDIT_CARD",      r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{1,7}\b", 0),
    # Email: local {1,64} @ domain labels {1,63} each, {0,4} extra labels, TLD {2,6}.
    ("EMAIL_ADDRESS",    r"\b[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9\-]{1,63}"
                          r"(?:\.[a-zA-Z0-9\-]{1,63}){0,4}\.[a-zA-Z]{2,6}\b", 0),
    # SSN: strictly anchored NNN-NN-NNNN — no ambiguity, O(1).
    ("US_SSN",           r"\b\d{3}-\d{2}-\d{4}\b", 0),
    # API key: sk- prefix + 20-64 hex chars — bounded.
    ("API_KEY",          r"\bsk-[a-fA-F0-9]{20,64}\b", 0),
    # Password: keyword + separator + value bounded to {6,128}.
    ("GENERIC_PASSWORD", r"password\s{0,4}[:=]\s{0,4}\S{6,128}", re.IGNORECASE),
    # Phone: international or domestic, bounded repetition.
    ("PHONE_NUMBER",     r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", 0),
    # IBAN: 2-letter country + 2 check digits + up to 30 bounded alnum chars.
    ("IBAN_CODE",        r"\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b", 0),
    # Crypto: Bitcoin-style base58 wallet address, bounded length.
    ("CRYPTO",           r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", 0),
)

FALLBACK_PATTERNS: Tuple[Tuple[str, re.Pattern], ...] = tuple(
    (etype, re.compile(pattern, flags)) for etype, pattern, flags in _RAW_FALLBACK_PATTERNS
)

# Single combined pattern for the O(1) ingestion pre-filter — a fast, cheap
# superset check ("might contain PII") run before any per-entity matching.
PII_QUICK_PATTERN: re.Pattern = re.compile(
    "|".join(f"(?:{pattern})" for _etype, pattern, _flags in _RAW_FALLBACK_PATTERNS),
    re.IGNORECASE,
)


def resolve_entity_overlaps(entities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Drop lower-priority matches whose [start, end) span overlaps a
    higher-priority match already kept.

    Regex fallback scanning runs every entity pattern independently over the
    same payload, so a single token (e.g. a long digit run) can satisfy more
    than one pattern and be reported twice — inflating entity_count, which
    feeds directly into severity classification and threat_score. This makes
    the entity set span-disjoint, matching how Presidio's own conflict
    resolution behaves.

    Priority: higher confidence first, then longer span (ties broken by
    original order). Output is re-sorted by start position for readability.
    """
    indexed = list(enumerate(entities))
    ordered = sorted(
        indexed,
        key=lambda pair: (
            -pair[1].get("confidence", 0.0),
            -(pair[1].get("end", 0) - pair[1].get("start", 0)),
            pair[0],
        ),
    )

    kept: List[Dict[str, Any]] = []
    occupied: List[Tuple[int, int]] = []
    for _, entity in ordered:
        start, end = entity.get("start", 0), entity.get("end", 0)
        if any(start < occ_end and end > occ_start for occ_start, occ_end in occupied):
            continue
        occupied.append((start, end))
        kept.append(entity)

    kept.sort(key=lambda e: e.get("start", 0))
    return kept


# ---------------------------------------------------------------------------
# PII Entity Configuration
# ---------------------------------------------------------------------------
SENSITIVE_ENTITY_TYPES: Tuple[str, ...] = (
    "CREDIT_CARD",
    "EMAIL_ADDRESS",
    "US_SSN",
    "GENERIC_PASSWORD",
    "API_KEY",
    "PHONE_NUMBER",
    "CRYPTO",
    "IBAN_CODE",
)

HIGH_RISK_ENTITY_TYPES: FrozenSet[str] = frozenset({
    "CREDIT_CARD",
    "US_SSN",
    "GENERIC_PASSWORD",
    "API_KEY",
    "IBAN_CODE",
    "CRYPTO",
})

# Threat-score weights per entity type (NIST: Risk = Likelihood × Impact)
ENTITY_SCORE_WEIGHTS: dict[str, int] = {
    "CREDIT_CARD":       20,
    "US_SSN":            20,
    "GENERIC_PASSWORD":  25,
    "API_KEY":           25,
    "CRYPTO":            20,
    "IBAN_CODE":         20,
    "EMAIL_ADDRESS":     10,
    "PHONE_NUMBER":       8,
}

ENTITY_SCORE_PER_COUNT: int = 15   # Added per detected entity
AI_ENDPOINT_SCORE_MULTIPLIER: int = 2
MAX_THREAT_SCORE: int = 100
PRESIDIO_CONFIDENCE_THRESHOLD: float = 0.50


# ---------------------------------------------------------------------------
# API / Runtime Configuration
# ---------------------------------------------------------------------------
@dataclass
class SecurityConfig:
    """
    Centralised runtime security configuration.
    Never modify at runtime — treat as read-only after initialisation.
    """

    # Network. Localhost-only by default (NIST SC-7) — safe for local dev.
    # Container platforms (Render, Fly.io, ...) require binding 0.0.0.0 and
    # typically inject the listen port via a PORT env var; both are
    # overridable so the secure local default doesn't have to change to
    # deploy. Set API_HOST=0.0.0.0 explicitly (e.g. in render.yaml) — it is
    # never inferred automatically.
    API_HOST: str = field(default_factory=lambda: os.environ.get("API_HOST", "127.0.0.1"))
    API_PORT: int = field(default_factory=lambda: int(os.environ.get("PORT", os.environ.get("API_PORT", "8000"))))
    API_WORKERS: int = field(default_factory=lambda: int(os.environ.get("API_WORKERS", "1")))
    API_TIMEOUT: int = 30

    # Rate Limiting  (OWASP A07 — prevent brute-force / DoS)
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW_SECONDS: int = 60

    # Trusted reverse proxies (OWASP A01) — X-Forwarded-For is ONLY honoured
    # when the direct TCP peer is in this list. Anyone else's XFF header is
    # ignored, so a client can no longer spoof a fresh IP per request to
    # bypass the rate limiter. Populate via TRUSTED_PROXIES env var
    # (comma-separated) when deploying behind a load balancer / reverse proxy.
    TRUSTED_PROXIES: List[str] = field(default_factory=lambda: [
        p.strip() for p in os.environ.get("TRUSTED_PROXIES", "").split(",") if p.strip()
    ])

    # API authentication (OWASP A07). If unset, the API runs UNAUTHENTICATED
    # (local/dev mode) — a startup warning is logged. Set SHADOW_AI_API_KEY
    # before exposing /scan or /scan-file on a public/deployed endpoint.
    API_KEY: str | None = field(default_factory=lambda: os.environ.get("SHADOW_AI_API_KEY") or None)

    # Bound on concurrent in-flight Presidio/regex scans per process, to stop
    # a single large batch request from exhausting the thread pool.
    SCAN_CONCURRENCY_LIMIT: int = 32

    # Input Validation
    MAX_PAYLOAD_BYTES: int = 10_000
    MAX_LOGS_PER_REQUEST: int = 1_000
    MAX_URL_LENGTH: int = 2_048

    # /scan-file is restricted to files under this directory (resolved,
    # symlink-safe). Prevents path traversal to arbitrary filesystem paths.
    SCAN_FILE_BASE_DIR: str = "./threat_model_output"

    # SQLite-backed dashboard/incident store — durable across restarts.
    # Env-overridable so a mounted persistent-disk path can be supplied on
    # a container platform (see DEPLOYMENT.md — Render's filesystem is
    # ephemeral on redeploy without one).
    DASHBOARD_DB_PATH: str = field(default_factory=lambda: os.environ.get(
        "DASHBOARD_DB_PATH", "./threat_model_output/dashboard.db"
    ))

    # Data Minimisation (GDPR / OWASP)
    STORE_ORIGINAL_DATA: bool = False    # Never persist raw PII
    LOG_SENSITIVE_VALUES: bool = False   # Never write actual PII to logs
    USE_HASHING_FOR_TRACKING: bool = True

    # TLS (NIST SC-13) — enable in production
    USE_HTTPS: bool = False
    CERT_FILE: str | None = None
    KEY_FILE: str | None = None

    # Output / Audit Paths (NIST AU-3, AU-12)
    AUDIT_LOG_FILE: str = "./audit.log"
    ALERT_LOG_FILE: str = "./alerts.jsonl"
    ENABLE_AUDIT_LOGGING: bool = True
    OUTPUT_DIR: str = "./threat_model_output"

    # CORS — localhost-only by default (NIST SC-7)
    CORS_ORIGINS: List[str] = field(default_factory=lambda: [
        "http://localhost",
        "http://127.0.0.1",
        "http://localhost:8000",
    ])
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: List[str] = field(default_factory=lambda: ["POST", "GET"])


# Global singleton — import and use, never reinstantiate in hot paths
config = SecurityConfig()

# ---------------------------------------------------------------------------
# Security Headers (applied by FastAPI middleware)
# ---------------------------------------------------------------------------
SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options":            "nosniff",
    "X-Frame-Options":                   "DENY",
    "X-XSS-Protection":                  "1; mode=block",
    "Strict-Transport-Security":         "max-age=31536000; includeSubDomains",
    "Content-Security-Policy":           "default-src 'self'",
    "Referrer-Policy":                   "no-referrer",
    "Permissions-Policy":                "geolocation=(), microphone=()",
}


# ---------------------------------------------------------------------------
# NIST / OWASP Control Mapping (documentation artefact)
# ---------------------------------------------------------------------------
NIST_CONTROLS: dict[str, str] = {
    "AC-2":  "Account Management — user-level department restrictions enforced",
    "AC-3":  "Access Enforcement — AI endpoint access gated by policy engine",
    "AC-4":  "Information Flow Enforcement — data exfiltration detection pipeline",
    "AU-2":  "Audit Events — every scan and alert event is logged",
    "AU-3":  "Content of Audit Records — user, timestamp, action, entity type captured",
    "AU-12": "Audit Generation — comprehensive, tamper-evident audit trail",
    "IA-2":  "Authentication — rate limiting prevents brute-force enumeration",
    "SC-7":  "Boundary Protection — API bound to localhost; CORS locked down",
    "SC-13": "Cryptographic Protection — TLS-ready via cryptography library",
    "SI-4":  "Information System Monitoring — Presidio ML-backed entity detection",
    "IR-1":  "Incident Response Planning — PolicyAlert generation and escalation",
    "IR-4":  "Incident Handling — automated BLOCK / ESCALATE actions",
}

OWASP_CONTROLS: dict[str, str] = {
    "A01": "Broken Access Control — department-scoped AI endpoint restrictions",
    "A02": "Cryptographic Failures — TLS support + cryptography package",
    "A04": "Insecure Design — secure defaults, no remote access by default",
    "A05": "Security Misconfiguration — config module, no hardcoded secrets",
    "A07": "Identification & Auth Failures — rate limiting + input validation",
    "A09": "Logging & Monitoring Failures — structured audit logging pipeline",
}


if __name__ == "__main__":
    print("=== Security Configuration ===")
    print(f"AI detection patterns loaded: {len(COMPILED_AI_PATTERNS)}")
    print(f"Sensitive entity types:       {len(SENSITIVE_ENTITY_TYPES)}")
    print(f"High-risk entity types:       {len(HIGH_RISK_ENTITY_TYPES)}")
    print(f"API bind address:             {config.API_HOST}:{config.API_PORT}")
    print(f"Rate limit:                   {config.RATE_LIMIT_REQUESTS} req / {config.RATE_LIMIT_WINDOW_SECONDS}s")
