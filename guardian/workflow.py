"""Static GitHub Actions security checks."""

from __future__ import annotations

import re


def analyze_workflow(path: str, content: str) -> list[dict]:
    findings: list[dict] = []
    lower = content.lower()

    if "pull_request_target" in lower:
        findings.append({"id": "workflow-pull-request-target", "status": "warning", "path": path,
                         "message": "pull_request_target is present; review untrusted-code boundaries carefully."})

    if re.search(r"permissions\s*:\s*write-all\b", lower) or re.search(r"permissions\s*:\s*\n\s*write-all\b", lower):
        findings.append({"id": "workflow-write-all", "status": "warning", "path": path,
                         "message": "Workflow grants write-all permissions."})

    if re.search(r"pull-requests\s*:\s*write\b", lower):
        findings.append({"id": "workflow-pr-write", "status": "warning", "path": path,
                         "message": "Workflow grants pull-request write permission."})

    if re.search(r"run\s*:\s*[^\n]*(curl|wget)[^\n]*\|\s*(bash|sh)\b", lower):
        findings.append({"id": "workflow-pipe-shell", "status": "warning", "path": path,
                         "message": "Workflow pipes downloaded content directly into a shell."})

    for line_no, line in enumerate(content.splitlines(), 1):
        if re.search(r"uses:\s*[^\s@]+@(main|master|latest|v?\d+)$", line.strip(), re.I):
            findings.append({"id": "workflow-unpinned-action", "status": "info", "path": path,
                             "line": line_no,
                             "message": "Third-party action reference uses a mutable tag; pin trusted actions to a commit SHA for stronger supply-chain integrity."})
    return findings
