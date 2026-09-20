"""Lightweight repository security health checks."""

from pathlib import PurePosixPath


def analyze_repository_paths(paths: list[str]) -> list[dict]:
    normalized = {p.lower() for p in paths}
    checks = []
    checks.append({
        "id": "secret-policy",
        "status": "pass" if "security.md" in normalized else "warning",
        "message": "SECURITY.md is present." if "security.md" in normalized else "SECURITY.md is missing.",
    })
    checks.append({
        "id": "dependency-manifest",
        "status": "pass" if any(p in normalized for p in ("requirements.txt", "pyproject.toml", "package.json", "go.mod", "pom.xml", "cargo.toml")) else "info",
        "message": "A common dependency manifest is present." if any(p in normalized for p in ("requirements.txt", "pyproject.toml", "package.json", "go.mod", "pom.xml", "cargo.toml")) else "No supported dependency manifest detected.",
    })
    workflow_paths = [p for p in normalized if p.startswith(".github/workflows/") and p.endswith((".yml", ".yaml"))]
    checks.append({
        "id": "actions",
        "status": "info" if workflow_paths else "info",
        "message": f"{len(workflow_paths)} GitHub Actions workflow file(s) detected.",
    })
    checks.append({
        "id": "readme",
        "status": "pass" if "readme.md" in normalized else "warning",
        "message": "README.md is present." if "readme.md" in normalized else "README.md is missing.",
    })
    return checks


def security_score(findings, checks) -> int:
    deductions = {"critical": 30, "high": 20, "medium": 8, "low": 3}
    score = 100 - sum(deductions.get(f.severity, 0) for f in findings)
    for check in checks:
        if check["status"] == "warning":
            score -= 5
    return max(0, min(100, score))
