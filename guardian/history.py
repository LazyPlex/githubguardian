"""Historical and pull request scanning."""

from __future__ import annotations

from .detectors import scan_text
from .github import GitHubClient
from .models import Finding


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen = set()
    result = []
    for finding in findings:
        key = (finding.detector, finding.path, finding.line, finding.redacted_match)
        if key not in seen:
            seen.add(key)
            result.append(finding)
    return result


def scan_history(client: GitHubClient, owner: str, repo: str, ref: str | None, limit: int | None) -> list[Finding]:
    if limit is not None and limit <= 0:
        return []
    findings: list[Finding] = []
    commits = client.commits(owner, repo, ref, limit)
    for commit in commits:
        sha = commit["sha"]
        details = client.commit(owner, repo, sha)
        for file in details.get("files", []):
            patch = file.get("patch") or ""
            if not patch:
                continue
            findings.extend(scan_text(patch, f"{file.get('filename', 'unknown')} @ {sha[:8]}"))
    return _dedupe(findings)


def scan_pull_request(client: GitHubClient, owner: str, repo: str, number: int) -> list[Finding]:
    if number <= 0:
        return []
    findings: list[Finding] = []
    for file in client.pull_request_files(owner, repo, number):
        patch = file.get("patch") or ""
        if patch:
            findings.extend(scan_text(patch, f"{file.get('filename', 'unknown')} @ PR#{number}"))
    return _dedupe(findings)
