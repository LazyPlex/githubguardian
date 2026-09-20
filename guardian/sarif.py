"""SARIF 2.1.0 output."""

import json

from .models import Finding
from .report import sort_findings

LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def to_sarif(findings: list[Finding]) -> str:
    rules = {}
    results = []
    for finding in sort_findings(findings):
        rules.setdefault(finding.detector, {
            "id": finding.detector,
            "name": finding.detector,
            "shortDescription": {"text": finding.detector.replace("_", " ").title()},
            "help": {"text": finding.recommendation},
        })
        results.append({
            "ruleId": finding.detector,
            "level": LEVELS.get(finding.severity, "warning"),
            "message": {"text": f"Potential {finding.detector} detected. Match: {finding.redacted_match}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.path}, "region": {"startLine": finding.line}}}],
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "GitHub Guardian", "version": "0.6.0", "rules": list(rules.values())}}, "results": results}],
    }, indent=2)
