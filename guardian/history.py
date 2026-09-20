"""Historical and pull request scanning."""

from __future__ import annotations

from .detectors import scan_text
from .github import GitHubClient
from .models import Finding


def scan_history(client: GitHubClient, owner: str, repo: str, ref: str | None, limit: int) -> list[Finding]:
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
    return findings


def scan_pull_request(client: GitHubClient, owner: str, repo: str, number: int) -> list[Finding]:
    findings: list[Finding] = []
    for file in client.pull_request_files(owner, repo, number):
        patch = file.get("patch") or ""
        if patch:
            findings.extend(scan_text(patch, f"{file.get('filename', 'unknown')} @ PR#{number}"))
    return findings
