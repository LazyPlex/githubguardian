import json
from guardian.models import Finding
from guardian.sarif import to_sarif


def test_sarif_document():
    data = json.loads(to_sarif([Finding("x", "high", "a.py", 3, "abcd****ef", "fix")]))
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["results"][0]["ruleId"] == "x"
