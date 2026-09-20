"""Stable report formatting."""

import json
from .models import Finding

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.path, f.line))

def to_json(findings: list[Finding]) -> str:
    return json.dumps(
        {"count": len(findings), "findings": [f.to_dict() for f in sort_findings(findings)]},
        indent=2,
    )
