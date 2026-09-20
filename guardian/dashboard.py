"""Generate a dependency-free static HTML report."""

import html
from pathlib import Path


def write_dashboard(output: str, repository: str, findings, checks, score: int) -> None:
    rows = "".join(
        f"<tr><td>{html.escape(f.severity.upper())}</td><td>{html.escape(f.detector)}</td>"
        f"<td>{html.escape(f.path)}</td><td>{f.line}</td><td>{html.escape(f.redacted_match)}</td></tr>"
        for f in findings
    )
    check_rows = "".join(
        f"<tr><td>{html.escape(c['id'])}</td><td>{html.escape(c['status'])}</td><td>{html.escape(c['message'])}</td></tr>"
        for c in checks
    )
    document = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>GitHub Guardian Report</title>
<style>body{{font-family:system-ui;margin:40px;max-width:1200px}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:8px;text-align:left}}.score{{font-size:48px;font-weight:700}}</style>
</head><body><h1>GitHub Guardian</h1><p>{html.escape(repository)}</p>
<div class="score">{score}/100</div><h2>Security findings</h2>
<table><tr><th>Severity</th><th>Detector</th><th>File</th><th>Line</th><th>Redacted match</th></tr>{rows}</table>
<h2>Repository checks</h2><table><tr><th>Check</th><th>Status</th><th>Message</th></tr>{check_rows}</table>
</body></html>"""
    output_path = Path(output)\n    output_path.parent.mkdir(parents=True, exist_ok=True)\n    output_path.write_text(document, encoding="utf-8")
