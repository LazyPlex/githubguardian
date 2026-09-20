from guardian.scanner import scan


def test_scanner_returns_findings():
    findings = scan([
        ("config.env", "API_KEY=abcdefghijklmnopqrstuvwxyz123456"),
    ])

    assert len(findings) == 1
    assert findings[0].severity == "high"
