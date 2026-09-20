from guardian.models import Finding
from guardian.suppressions import apply_suppressions


def test_suppression_by_detector():
    finding = Finding("aws_access_key", "high", "x.env", 2, "AKIA****EF", "rotate")
    assert apply_suppressions([finding], {"aws_access_key"}) == []
