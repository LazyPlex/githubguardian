"""Lightweight repository security health checks."""

def analyze_repository_paths(paths: list[str], workflow_findings: list[dict] | None = None) -> list[dict]:
    normalized = {p.lower() for p in paths}
    checks = []
    checks.append({
        "id": "secret-policy",
        "status": "pass" if "security.md" in normalized else "warning",
        "message": "SECURITY.md is present." if "security.md" in normalized else "SECURITY.md is missing.",
    })
    manifests = ("requirements.txt", "pyproject.toml", "package.json", "go.mod", "pom.xml", "cargo.toml")
    checks.append({
        "id": "dependency-manifest",
        "status": "pass" if any(p in normalized for p in manifests) else "info",
        "message": "A common dependency manifest is present." if any(p in normalized for p in manifests) else "No supported dependency manifest detected.",
    })
    workflow_paths = [p for p in normalized if p.startswith(".github/workflows/") and p.endswith((".yml", ".yaml"))]
    checks.append({
        "id": "actions",
        "status": "pass" if workflow_paths else "info",
        "message": f"{len(workflow_paths)} GitHub Actions workflow file(s) detected.",
    })
    if workflow_findings:
        warning_count = sum(1 for item in workflow_findings if item.get("status") == "warning")
        checks.append({
            "id": "actions-security",
            "status": "warning" if warning_count else "pass",
            "message": f"{warning_count} workflow security warning(s) detected." if warning_count else "No high-risk workflow patterns detected.",
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
