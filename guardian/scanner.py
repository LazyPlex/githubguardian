"""Scanning orchestration."""

from collections.abc import Iterable

from .detectors import scan_files
from .models import Finding


def scan(files: Iterable[tuple[str, str]]) -> list[Finding]:
    """Scan text files and return normalized security findings."""
    return scan_files(files)
