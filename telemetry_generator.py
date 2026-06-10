"""
Shadow AI Detector — Synthetic Telemetry Generator
====================================================
NIST SP 800-53: AU-2 (Audit Events) — synthetic data only, no real PII.
OWASP: No hardcoded secrets, no actual user data.

Generates realistic HTTP proxy logs representing the three Shadow AI threat
scenarios that the detection pipeline is designed to surface:
  A. Clean traffic (normal SaaS endpoints, no PII)
  B. Benign AI usage (AI endpoint, no PII — behavioural baseline)
  C. Shadow AI exfiltration (AI endpoint + PII payload — primary threat)
"""

from __future__ import annotations

import json
import random
import uuid
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import List

NUM_LOGS = 1_000
OUTPUT_FILE = Path("proxy_logs.jsonl")

# ---------------------------------------------------------------------------
# Employees and Departments
# ---------------------------------------------------------------------------
EMPLOYEE_IDS  = [f"emp_{i:04d}" for i in range(1, 51)]
DEPARTMENTS   = ["Engineering", "Sales", "Finance", "Marketing", "HR"]

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
AI_ENDPOINTS: dict[str, str] = {
    "api.openai.com":                       "/v1/chat/completions",
    "claude.ai":                            "/api/v1/messages",
    "api.huggingface.co":                   "/v1/models/gpt2/predict",
    "api.anthropic.com":                    "/v1/complete",
    "generativelanguage.googleapis.com":    "/v1beta/models/gemini-pro:generateContent",
}

NORMAL_ENDPOINTS: dict[str, str] = {
    "api.github.com":    "/repos/{user}/issues",
    "api.slack.com":     "/api/chat.postMessage",
    "cloud.google.com":  "/storage/v1/b/{bucket}/o",
    "api.jira.com":      "/rest/api/3/issue",
    "api.datadog.com":   "/api/v1/metrics",
}

# ---------------------------------------------------------------------------
# PII Generators — SYNTHETIC ONLY (OWASP data minimisation)
# ---------------------------------------------------------------------------

def _fake_email() -> str:
    return f"user{random.randint(1, 9999)}@company-internal.com"

def _fake_credit_card() -> str:
    # Luhn-invalid prefix 4111 — clearly test data
    return f"4111-1111-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}"

def _fake_ssn() -> str:
    return f"{random.randint(100, 999)}-{random.randint(10, 99)}-{random.randint(1000, 9999)}"

def _fake_api_key() -> str:
    return "sk-" + hashlib.sha256(uuid.uuid4().bytes).hexdigest()[:32]

def _fake_password() -> str:
    return "password=" + uuid.uuid4().hex[:12]

# ---------------------------------------------------------------------------
# Payload Templates
# ---------------------------------------------------------------------------
_SENSITIVE_TEMPLATES = [
    "Summarise the account profile for {email}",
    "Process refund for card {cc}",
    "Verify identity: SSN {ssn}",
    "Rotate integration key: {api_key}",
    "Customer profile — email: {email}, SSN: {ssn}",
    "Payment details: {cc}, expiry 12/26",
    "Generate quarterly report for {email} (ID: {ssn})",
    "Auth token refresh — {api_key} — {email}",
    "Bulk update: card {cc}, contact {email}, ref {ssn}",
    "{password} for service account {email}",
]

_NORMAL_TEMPLATES = [
    "What is the capital of France?",
    "Summarise the Q3 product roadmap.",
    "Explain microservices architecture.",
    "Best practices for REST API versioning.",
    "How do I optimise a PostgreSQL query?",
    "Draft a meeting agenda for sprint planning.",
    "Translate 'hello world' into Spanish.",
    "Review this Python function for readability.",
    "What are the OWASP Top 10 vulnerabilities?",
    "Explain the difference between TCP and UDP.",
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE"]

# ---------------------------------------------------------------------------
# Log Entry Factory
# ---------------------------------------------------------------------------

def _generate_log(
    *,
    is_sensitive: bool,
    target_ai:    bool,
    base_time:    datetime,
) -> dict:
    """
    Produce a single proxy log entry.

    Args:
        is_sensitive: Embed synthetic PII in payload.
        target_ai:    Route request to an AI endpoint.
        base_time:    Reference timestamp for realistic time offsets.
    """
    ts = base_time - timedelta(minutes=random.randint(0, 1_440))

    if target_ai:
        dest, path = random.choice(list(AI_ENDPOINTS.items()))
    else:
        dest, path = random.choice(list(NORMAL_ENDPOINTS.items()))
        path = path.format(user="emp", bucket="corp-data")

    if target_ai and is_sensitive:
        template = random.choice(_SENSITIVE_TEMPLATES)
        payload  = template.format(
            email   = _fake_email(),
            cc      = _fake_credit_card(),
            ssn     = _fake_ssn(),
            api_key = _fake_api_key(),
            password= _fake_password(),
        )
        label = "SENSITIVE_DATA_TO_AI"
    else:
        payload = random.choice(_NORMAL_TEMPLATES)
        label   = "NORMAL_AI" if target_ai else "NORMAL"

    return {
        "timestamp":          ts.isoformat(),
        "source_ip":          f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "user_id":            random.choice(EMPLOYEE_IDS),
        "department":         random.choice(DEPARTMENTS),
        "destination_url":    dest,
        "http_method":        random.choice(HTTP_METHODS),
        "path":               path,
        "payload":            payload,
        "response_code":      random.choice([200, 201, 400, 401, 429, 500]),
        "response_time_ms":   random.randint(50, 5_000),
        "threat_model_label": label,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_logs(num_logs: int = NUM_LOGS) -> List[dict]:
    """
    Generate a shuffled mix of proxy logs.

    Distribution (aligns with real-world Shadow AI prevalence estimates):
      20% — clean traffic (non-AI endpoints, no PII)
      50% — benign AI usage (AI endpoints, no PII)
      30% — shadow AI exfiltration (AI endpoints + PII)
    """
    base_time  = datetime.utcnow()
    normal     = int(num_logs * 0.20)
    normal_ai  = int(num_logs * 0.50)
    sensitive  = num_logs - normal - normal_ai

    logs: List[dict] = []
    logs.extend(_generate_log(is_sensitive=False, target_ai=False, base_time=base_time) for _ in range(normal))
    logs.extend(_generate_log(is_sensitive=False, target_ai=True,  base_time=base_time) for _ in range(normal_ai))
    logs.extend(_generate_log(is_sensitive=True,  target_ai=True,  base_time=base_time) for _ in range(sensitive))

    random.shuffle(logs)
    return logs


def save_logs(logs: List[dict], output_file: Path = OUTPUT_FILE) -> int:
    """Write logs to JSONL format. Returns count written."""
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as fh:
        for log in logs:
            fh.write(json.dumps(log) + "\n")
    return len(logs)


def load_logs(input_file: Path = OUTPUT_FILE) -> List[dict]:
    """
    Load and validate JSONL proxy logs from disk.
    Malformed lines are skipped with a warning (OWASP: graceful degradation).
    """
    logs   = []
    skipped = 0
    with open(input_file, "r", encoding="utf-8-sig") as fh:
        for lineno, raw_line in enumerate(fh, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                logs.append(json.loads(line))
            except json.JSONDecodeError:
                skipped += 1
    if skipped:
        print(f"[WARNING] Skipped {skipped} malformed lines in {input_file}")
    return logs


if __name__ == "__main__":
    print("=" * 70)
    print("Shadow AI Detector — Telemetry Generator")
    print("=" * 70)

    logs = generate_logs(NUM_LOGS)
    save_logs(logs, OUTPUT_FILE)

    sensitive = sum(1 for l in logs if l["threat_model_label"] == "SENSITIVE_DATA_TO_AI")
    ai_all    = sum(1 for l in logs if l["threat_model_label"] in {"SENSITIVE_DATA_TO_AI", "NORMAL_AI"})

    print(f"Generated : {len(logs)} logs → {OUTPUT_FILE}")
    print(f"  Clean traffic           : {len(logs) - ai_all}")
    print(f"  Benign AI usage         : {ai_all - sensitive}")
    print(f"  Shadow AI exfiltration  : {sensitive}  ← PRIMARY THREAT")
    print("=" * 70)
