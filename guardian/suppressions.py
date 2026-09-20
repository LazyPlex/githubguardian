"""Simple line based finding suppression."""

from pathlib import Path


def load_suppressions(path: str = ".githubguardianignore") -> set[str]:
    file = Path(path)
    if not file.exists():
        return set()
    return {
        line.strip()
        for line in file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }


def is_suppressed(finding, rules: set[str]) -> bool:
    keys = {
        finding.detector,
        f"{finding.detector}:{finding.path}",
        f"{finding.path}:{finding.line}",
        f"{finding.detector}:{finding.path}:{finding.line}",
    }
    return bool(keys & rules)


def apply_suppressions(findings, rules):
    return [f for f in findings if not is_suppressed(f, rules)]
