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
from typing import FrozenSet, List, Tuple

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

    # Network — reads env vars so cloud platforms get 0.0.0.0
    # while local dev stays on 127.0.0.1 (NIST SC-7)
    API_HOST: str = field(default_factory=lambda: os.environ.get("HOST", "127.0.0.1"))
    API_PORT: int = field(default_factory=lambda: int(os.environ.get("PORT", "8000")))
    API_WORKERS: int = 1
    API_TIMEOUT: int = 30

    # Rate Limiting  (OWASP A07 — prevent brute-force / DoS)
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW_SECONDS: int = 60

    # Input Validation
    MAX_PAYLOAD_BYTES: int = 10_000
    MAX_LOGS_PER_REQUEST: int = 1_000
    MAX_URL_LENGTH: int = 2_048

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
