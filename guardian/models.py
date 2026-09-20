"""Core data models for GitHub Guardian."""

from dataclasses import dataclass, asdict
from typing import Any


@dataclass(frozen=True)
class Finding:
    detector: str
    severity: str
    path: str
    line: int
    redacted_match: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
