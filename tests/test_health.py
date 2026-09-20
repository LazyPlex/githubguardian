from guardian.health import analyze_repository_paths, security_score


def test_health_checks():
    checks = analyze_repository_paths(["README.md", "SECURITY.md", "requirements.txt"])
    assert all(c["status"] != "warning" for c in checks)


def test_score_is_bounded():
    assert 0 <= security_score([], []) <= 100
