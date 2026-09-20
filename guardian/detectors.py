"""Secret detection rules.

Detectors return redacted matches only. They must never expose the full
credential value.
"""

import re
from collections.abc import Iterable

from .models import Finding


PATTERNS: tuple[tuple[str, str, str], ...] = (
    (
        "github_token",
        r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b",
        "Revoke the credential and rotate it immediately.",
    ),
    (
        "aws_access_key",
        r"\bAKIA[0-9A-Z]{16}\b",
        "Rotate the AWS credential and review its permissions.",
    ),
    (
        "private_key",
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        "Remove the private key, rotate related credentials, and invalidate the exposed key.",
    ),
    (
        "generic_api_key_assignment",
        r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token)\b\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+=]{16,})",
        "Rotate the credential and remove it from source control.",
    ),
)


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * min(12, len(value) - 6)}{value[-2:]}"


def scan_text(text: str, path: str) -> list[Finding]:
    findings: list[Finding] = []

    for line_number, line in enumerate(text.splitlines(), start=1):
        for detector, pattern, recommendation in PATTERNS:
            match = re.search(pattern, line)
            if not match:
                continue

            value = match.group(1) if match.lastindex else match.group(0)
            findings.append(
                Finding(
                    detector=detector,
                    severity="high",
                    path=path,
                    line=line_number,
                    redacted_match=_redact(value),
                    recommendation=recommendation,
                )
            )

    return findings


def scan_files(files: Iterable[tuple[str, str]]) -> list[Finding]:
    findings: list[Finding] = []
    for path, content in files:
        findings.extend(scan_text(content, path))
    return findings
