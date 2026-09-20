from guardian.models import Finding
from guardian.report import sort_findings, to_json

def test_sorting_prioritizes_critical():
    low = Finding("x", "low", "b.py", 2, "***", "fix")
    critical = Finding("x", "critical", "a.py", 1, "***", "fix")
    assert sort_findings([low, critical])[0] == critical

def test_json_report_is_redacted():
    finding = Finding("x", "high", "a.py", 1, "abcd****ef", "fix")
    output = to_json([finding])
    assert "abcd****ef" in output
    assert '"count": 1' in output
