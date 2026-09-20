"""GitHub REST client used by GitHub Guardian."""

from __future__ import annotations

import base64
import os
from typing import Any

import requests

API_ROOT = "https://api.github.com"
API_VERSION = "2022-11-28"


class GitHubError(RuntimeError):
    pass


class GitHubClient:
    def __init__(self, token: str | None = None, timeout: int = 20) -> None:
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "githubguardian/0.5.0",
        })
        token = token or os.getenv("GITHUB_TOKEN")
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"

    def _get(self, path: str, **params: Any) -> Any:
        response = self.session.get(f"{API_ROOT}{path}", params=params or None, timeout=self.timeout)
        if response.status_code == 403:
            raise GitHubError("GitHub returned 403. Check rate limits or token permissions.")
        if response.status_code == 404:
            raise GitHubError("Repository or resource was not found.")
        if not response.ok:
            raise GitHubError(f"GitHub API error {response.status_code}: {response.text[:300]}")
        return response.json()

    def repository(self, owner: str, repo: str) -> dict[str, Any]:
        return self._get(f"/repos/{owner}/{repo}")

    def tree(self, owner: str, repo: str, ref: str) -> list[dict[str, Any]]:
        data = self._get(f"/repos/{owner}/{repo}/git/trees/{ref}", recursive="true")
        if data.get("truncated"):
            raise GitHubError("Repository tree is too large for one recursive request.")
        return data.get("tree", [])

    def blob_text(self, owner: str, repo: str, sha: str, max_bytes: int) -> str | None:
        data = self._get(f"/repos/{owner}/{repo}/git/blobs/{sha}")
        if data.get("size", 0) > max_bytes or data.get("encoding") != "base64":
            return None
        raw = base64.b64decode(data["content"], validate=False)
        if b"\x00" in raw:
            return None
        return raw.decode("utf-8", errors="replace")

    def commits(self, owner: str, repo: str, ref: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
        limit = min(max(limit, 1), 1000)
        results: list[dict[str, Any]] = []
        page = 1
        while len(results) < limit:
            batch = self._get(
                f"/repos/{owner}/{repo}/commits",
                sha=ref,
                per_page=min(100, limit - len(results)),
                page=page,
            )
            if not batch:
                break
            results.extend(batch)
            if len(batch) < 100:
                break
            page += 1
        return results[:limit]

    def commit(self, owner: str, repo: str, sha: str) -> dict[str, Any]:
        return self._get(f"/repos/{owner}/{repo}/commits/{sha}")

    def pull_request(self, owner: str, repo: str, number: int) -> dict[str, Any]:
        return self._get(f"/repos/{owner}/{repo}/pulls/{number}")

    def pull_request_files(self, owner: str, repo: str, number: int, limit: int = 100) -> list[dict[str, Any]]:
        return self._get(f"/repos/{owner}/{repo}/pulls/{number}/files", per_page=min(max(limit, 1), 100))

    def workflow_file(self, owner: str, repo: str, path: str, ref: str | None = None) -> str | None:
        data = self._get(f"/repos/{owner}/{repo}/contents/{path}", **({"ref": ref} if ref else {}))
        if data.get("encoding") != "base64":
            return None
        return base64.b64decode(data["content"]).decode("utf-8", errors="replace")


def parse_repository(value: str) -> tuple[str, str]:
    cleaned = value.strip().rstrip("/")
    if cleaned.startswith("https://github.com/"):
        cleaned = cleaned.removeprefix("https://github.com/").split("#", 1)[0]
    cleaned = cleaned.removesuffix(".git")
    parts = [part for part in cleaned.split("/") if part]
    if len(parts) != 2:
        raise ValueError("Repository must be owner/name or a github.com/owner/name URL.")
    return parts[0], parts[1]
