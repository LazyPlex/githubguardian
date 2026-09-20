from guardian.detectors import scan_text


def test_detects_github_token_without_exposing_full_value():
    token = "ghp_" + "A" * 32
    findings = scan_text(f"TOKEN={token}", "config.env")

    assert len(findings) == 1
    assert findings[0].detector == "github_token"
    assert token not in findings[0].redacted_match


def test_detects_aws_access_key():
    findings = scan_text("AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF", ".env")

    assert len(findings) == 1
    assert findings[0].detector == "aws_access_key"


def test_detects_database_url():
    findings = scan_text("DATABASE_URL=postgres://demo:fakepass@localhost:5432/app", ".env")

    assert len(findings) == 1
    assert findings[0].detector == "database_url"


def test_detects_private_key_header():
    findings = scan_text("-----BEGIN RSA PRIVATE KEY-----", "key.txt")

    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_ignores_normal_text():
    findings = scan_text("This project has no credentials.", "README.md")

    assert findings == []
