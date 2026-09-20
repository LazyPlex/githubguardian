"""Static GitHub Actions security checks."""

from __future__ import annotations

import re


def analyze_workflow(path: str, content: str) -> list[dict]:
    findings: list[dict] = []
    lower = content.lower()

    if "pull_request_target" in lower:
        findings.append({"id": "workflow-pull-request-target", "status": "warning", "path": path,
                         "message": "pull_request_target is present; review untrusted-code boundaries carefully."})

    if re.search(r"(?m)^\s*permissions\s*:\s*write-all\s*$", lower) or re.search(
        r"(?m)^\s*permissions\s*:\s*\n\s*write-all\s*$", lower
    ):
        findings.append({"id": "workflow-write-all", "status": "warning", "path": path,
                         "message": "Workflow grants write-all permissions."})

    if re.search(r"(?m)^\s*pull-requests\s*:\s*write\s*$", lower):
        findings.append({"id": "workflow-pr-write", "status": "warning", "path": path,
                         "message": "Workflow grants pull-request write permission."})

    if re.search(r"run\s*:\s*[^\n]*(?:curl|wget)[^\n]*\|\s*(?:bash|sh)\b", lower):
        findings.append({"id": "workflow-pipe-shell", "status": "warning", "path": path,
                         "message": "Workflow pipes downloaded content directly into a shell."})

    for line_no, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if not stripped.startswith("uses:") or "@" not in stripped:
            continue
        ref = stripped.rsplit("@", 1)[1].strip()
        if re.fullmatch(r"(?:main|master|latest|v?\d+(?:\.\d+)*)", ref, re.I):
            findings.append({"id": "workflow-unpinned-action", "status": "info", "path": path,
                             "line": line_no,
                             "message": "Third-party action reference uses a mutable tag; pin trusted actions to a commit SHA for stronger supply-chain integrity."})
    return findings
