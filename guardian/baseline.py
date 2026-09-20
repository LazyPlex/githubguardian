"""Baseline support for accepting known findings while surfacing new ones."""

from __future__ import annotations

import json
from pathlib import Path

from .models import Finding


def _key(finding: Finding) -> tuple[str, str, int, str]:
    return finding.detector, finding.path, finding.line, finding.redacted_match


def load_baseline(path: str) -> set[tuple[str, str, int, str]]:
    file = Path(path)
    if not file.exists():
        return set()
    data = json.loads(file.read_text(encoding="utf-8"))
    findings = data.get("findings", data if isinstance(data, list) else [])
    if not isinstance(findings, list):
        raise ValueError("Baseline must contain a findings list.")
    result = set()
    for item in findings:
        if not isinstance(item, dict):
            continue
        try:
            result.add((str(item["detector"]), str(item["path"]), int(item["line"]), str(item["redacted_match"])))
        except (KeyError, TypeError, ValueError):
            continue
    return result


def apply_baseline(findings: list[Finding], baseline: set[tuple[str, str, int, str]]) -> list[Finding]:
    return [finding for finding in findings if _key(finding) not in baseline]


def write_baseline(path: str, findings: list[Finding]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    document = {"version": 1, "findings": [finding.to_dict() for finding in findings]}
    output.write_text(json.dumps(document, indent=2), encoding="utf-8")
