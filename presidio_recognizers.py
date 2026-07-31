"""
Shadow AI Detector — Custom Presidio Recognizers
===================================================
NIST SP 800-53: SI-4 (System Monitoring)

Presidio ships built-in recognizers for CREDIT_CARD, EMAIL_ADDRESS, US_SSN,
IBAN_CODE, PHONE_NUMBER and CRYPTO — but NOT for GENERIC_PASSWORD or API_KEY,
since neither is a standard PII category. Both scanner_worker.py and
presidio_scanner.py requested these two entity types from AnalyzerEngine
without ever registering a recognizer for them, so every scan silently
returned zero matches for the two highest-weighted HIGH_RISK entity types
(score weight 25 each — see config.ENTITY_SCORE_WEIGHTS) whenever Presidio
was active. Regex-only fallback mode masked this, since it always ran the
GENERIC_PASSWORD / API_KEY patterns directly.

This module registers PatternRecognizer instances for both, reusing the
same bounded regex patterns from config.FALLBACK_PATTERNS so behaviour is
identical regardless of whether Presidio or the regex fallback is active.
"""

from __future__ import annotations

from typing import List

from config import FALLBACK_PATTERNS


def build_custom_recognizers() -> List["PatternRecognizer"]:  # noqa: F821
    """Build PatternRecognizer instances for entity types Presidio lacks natively."""
    from presidio_analyzer import Pattern, PatternRecognizer

    patterns_by_type = dict(FALLBACK_PATTERNS)

    api_key_recognizer = PatternRecognizer(
        supported_entity="API_KEY",
        patterns=[Pattern(
            name="api_key_sk_prefix",
            regex=patterns_by_type["API_KEY"].pattern,
            score=0.85,
        )],
        context=["api", "key", "token", "secret", "credential", "auth"],
    )

    password_recognizer = PatternRecognizer(
        supported_entity="GENERIC_PASSWORD",
        patterns=[Pattern(
            name="password_key_value",
            regex=patterns_by_type["GENERIC_PASSWORD"].pattern,
            score=0.75,
        )],
        context=["password", "passwd", "pwd", "credential"],
    )

    return [api_key_recognizer, password_recognizer]


def build_analyzer_engine() -> "AnalyzerEngine":  # noqa: F821
    """
    Construct a Presidio AnalyzerEngine with the custom recognizers registered
    on top of the built-in registry. Raises ImportError if presidio-analyzer
    is not installed, OSError if the spaCy language model is missing.
    """
    from presidio_analyzer import AnalyzerEngine

    engine = AnalyzerEngine()
    for recognizer in build_custom_recognizers():
        engine.registry.add_recognizer(recognizer)
    return engine
