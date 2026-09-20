"""Historical commit scanning helpers."""

from __future__ import annotations

from collections.abc import Iterable

from .detectors import scan_text
from .github import GitHubClient
from .models import Finding


def scan_commit_files(client: GitHubClient, owner: str, repo: str, commit_sha: str,
                      paths: Iterable[str], max_file_bytes: int = 1_000_000) -> list[Finding]:
    findings: list[Finding] = []
    tree = client.tree(owner, repo, commit_sha)
    by_path = {item.get("path"): item for item in tree if item.get("type") == "blob"}
    for path in paths:
        entry = by_path.get(path)
        if not entry or entry.get("size", 0) > max_file_bytes:
            continue
        content = client.blob_text(owner, repo, entry["sha"], max_file_bytes)
        if content is not None:
            findings.extend(scan_text(content, path))
    return findings
