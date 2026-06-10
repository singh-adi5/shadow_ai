# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| v4.x    | ✅ Active  |
| < v4    | ❌ EOL     |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email: security@[your-domain].com  
Response SLA: 48 hours

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested remediation (optional)

## Security Design Principles

This project is built against NIST SP 800-53 and OWASP Top 10 (2021).
Key controls implemented:

| Control | Implementation |
|---------|---------------|
| Input validation | Pydantic v2 strict schema at every ingestion boundary |
| Rate limiting | Redis sliding-window counter (multi-worker safe) |
| Data minimisation | Raw PII never stored; SHA-256 log IDs only |
| Boundary protection | API bound to 127.0.0.1; CORS localhost-only |
| Audit trail | Structured JSONL audit log (NIST AU-3, AU-12) |
| ReDoS prevention | All regex patterns bounded; < 0.05ms worst-case |
| Async safety | CPU-bound NLP offloaded via run_in_executor |

## Scope

In scope: API endpoints, ingestion pipeline, policy engine, regex patterns  
Out of scope: Third-party dependencies (report upstream), deployment infrastructure
