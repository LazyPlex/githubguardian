from guardian.detectors import scan_text

def test_secret_detectors():
    text = """
github=ghp_abcdefghijklmnopqrstuvwxyz123456
stripe=sk_live_1234567890abcdef
npm=npm_abcdefghijklmnopqrstuvwxyz123
slack=xoxb-1234567890-abcdefghij
"""
    findings = scan_text(text, "config.txt")
    detectors = {f.detector for f in findings}
    assert {"github_token", "stripe_secret_key", "npm_token", "slack_token"} <= detectors
    assert all("*" in f.redacted_match for f in findings)

def test_private_key_is_critical():
    findings = scan_text("-----BEGIN PRIVATE KEY-----", "key.txt")
    assert findings[0].severity == "critical"
