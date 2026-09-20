from guardian.baseline import apply_baseline, load_baseline, write_baseline
from guardian.models import Finding


def test_baseline_round_trip(tmp_path):
    finding = Finding("x", "high", "a.py", 3, "abcd****ef", "rotate")
    path = tmp_path / "baseline.json"
    write_baseline(str(path), [finding])
    assert apply_baseline([finding], load_baseline(str(path))) == []


def test_baseline_keeps_new_findings(tmp_path):
    known = Finding("x", "high", "a.py", 3, "abcd****ef", "rotate")
    new = Finding("x", "high", "b.py", 4, "zzzz****yy", "rotate")
    path = tmp_path / "baseline.json"
    write_baseline(str(path), [known])
    assert apply_baseline([known, new], load_baseline(str(path))) == [new]
