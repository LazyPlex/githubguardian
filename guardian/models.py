"""Core data models for GitHub Guardian."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    detector: str
    severity: str
    path: str
    line: int
    redacted_match: str
    recommendation: str
