"""Scanning orchestration and repository policy."""

from collections.abc import Iterable

from .detectors import scan_files
from .github import GitHubClient
from .models import Finding


DEFAULT_MAX_FILE_BYTES = 1_000_000
DEFAULT_MAX_FILES = 500
SKIP_DIRS = (".git/", "node_modules/", "vendor/", "dist/", "build/", ".venv/", "venv/")
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tar",
    ".7z", ".mp4", ".mov", ".mp3", ".woff", ".woff2", ".ttf", ".eot", ".exe", ".dll", ".so",
}


def should_scan(path: str) -> bool:
    lower = path.lower()
    if any(lower.startswith(prefix) or f"/{prefix}" in lower for prefix in SKIP_DIRS):
        return False
    return not any(lower.endswith(ext) for ext in SKIP_EXTENSIONS)


def scan(files: Iterable[tuple[str, str]]) -> list[Finding]:
    return scan_files(files)


def scan_repository(client: GitHubClient, owner: str, repo: str, ref: str | None = None,
                    max_files: int = DEFAULT_MAX_FILES,
                    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES) -> tuple[dict, list[Finding]]:
    metadata = client.repository(owner, repo)
    ref = ref or metadata["default_branch"]
    entries = client.tree(owner, repo, ref)
    candidates = [
        entry for entry in entries
        if entry.get("type") == "blob"
        and should_scan(entry.get("path", ""))
        and entry.get("size", 0) <= max_file_bytes
    ][:max_files]

    files: list[tuple[str, str]] = []
    for entry in candidates:
        content = client.blob_text(owner, repo, entry["sha"], max_file_bytes)
        if content is not None:
            files.append((entry["path"], content))
    return metadata, scan(files)
