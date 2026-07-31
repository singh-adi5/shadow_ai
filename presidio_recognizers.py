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


def build_analyzer_engine(model_name: str | None = None) -> "AnalyzerEngine":  # noqa: F821
    """
    Construct a Presidio AnalyzerEngine with the custom recognizers registered
    on top of the built-in registry. Raises ImportError if presidio-analyzer
    is not installed, OSError if the requested spaCy language model is missing.

    model_name defaults to config.PRESIDIO_SPACY_MODEL (env: PRESIDIO_SPACY_MODEL,
    default "en_core_web_lg"). Explicitly configuring this via NlpEngineProvider
    matters: AnalyzerEngine() with NO nlp_engine argument defaults to
    en_core_web_lg internally regardless of what's actually installed, and —
    confirmed locally — will silently attempt to auto-download that ~400MB
    model on first use if the process has network access, rather than
    raising OSError. That's surprising/slow in a demo process and can hang
    or blow past a CI job's expectations. Passing the model explicitly makes
    "which model, and is it actually present" an intentional decision, not
    an implicit fallback: NlpEngineProvider(...).create_engine() raises
    OSError immediately if model_name isn't installed, matching the
    ImportError/OSError contract the rest of this app's Presidio init
    already expects (see scanner_worker.py, presidio_scanner.py).
    """
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    if model_name is None:
        from config import config
        model_name = config.PRESIDIO_SPACY_MODEL

    nlp_engine = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": model_name}],
    }).create_engine()

    engine = AnalyzerEngine(nlp_engine=nlp_engine)
    for recognizer in build_custom_recognizers():
        engine.registry.add_recognizer(recognizer)
    return engine
