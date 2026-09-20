"""Secret detection rules."""

import re
from collections.abc import Iterable

from .models import Finding


PATTERNS: tuple[tuple[str, str, str, str], ...] = (
    ("github_token", r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b", "high", "Revoke the credential and rotate it immediately."),
    ("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b", "high", "Rotate the AWS credential and review its permissions."),
    ("private_key", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "critical", "Remove the private key, rotate related credentials, and invalidate the exposed key."),
    ("generic_api_key_assignment", r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token)\b\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+=]{16,})", "high", "Rotate the credential and remove it from source control."),
    ("database_url", r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s\"']+", "high", "Rotate database credentials and remove the connection string from source control."),
    ("google_api_key", r"\bAIza[0-9A-Za-z_-]{35}\b", "high", "Restrict or rotate the Google API key and remove it from source control."),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", "medium", "Verify whether the token is live, revoke it if applicable, and remove it from source control."),
)


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    visible = min(4, len(value) // 3)
    return f"{value[:visible]}{'*' * min(16, max(4, len(value) - visible - 2))}{value[-2:]}"


def scan_text(text: str, path: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()

    for line_number, line in enumerate(text.splitlines(), start=1):
        for detector, pattern, severity, recommendation in PATTERNS:
            match = re.search(pattern, line)
            if not match:
                continue
            value = match.group(1) if match.lastindex else match.group(0)
            key = (detector, line_number)
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(detector, severity, path, line_number, _redact(value), recommendation))

    return findings


def scan_files(files: Iterable[tuple[str, str]]) -> list[Finding]:
    findings: list[Finding] = []
    for path, content in files:
        findings.extend(scan_text(content, path))
    return findings
