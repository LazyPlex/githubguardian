"""Command-line interface for GitHub Guardian."""

import argparse
import json
import sys
from pathlib import Path

from .dashboard import write_dashboard
from .github import GitHubClient, GitHubError, parse_repository
from .health import analyze_repository_paths, security_score
from .history import scan_history, scan_pull_request
from .report import sort_findings
from .sarif import to_sarif
from .scanner import scan_repository
from .suppressions import apply_suppressions, load_suppressions

def main() -> int:
    parser = argparse.ArgumentParser(prog="githubguardian", description="Defensive security scanner for authorized/public GitHub repositories.")
    parser.add_argument("repository", help="owner/name or GitHub repository URL")
    parser.add_argument("--ref")
    parser.add_argument("--history", type=int, metavar="N")
    parser.add_argument("--pr", type=int, metavar="NUMBER")
    parser.add_argument("--max-files", type=int, default=500)
    parser.add_argument("--max-file-bytes", type=int, default=1000000)
    parser.add_argument("--ignore-file", default=".githubguardianignore")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--sarif", metavar="PATH")
    parser.add_argument("--dashboard", metavar="PATH")
    parser.add_argument("--score", action="store_true")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low"])
    parser.add_argument("--token", help="Optional GitHub token. Prefer GITHUB_TOKEN.")
    args = parser.parse_args()

    try:
        owner, repo = parse_repository(args.repository)
        client = GitHubClient(token=args.token)
        metadata, findings = scan_repository(client, owner, repo, ref=args.ref, max_files=args.max_files, max_file_bytes=args.max_file_bytes)
        if args.history:
            findings.extend(scan_history(client, owner, repo, args.ref, args.history))
        if args.pr:
            findings.extend(scan_pull_request(client, owner, repo, args.pr))
        findings = sort_findings(apply_suppressions(findings, load_suppressions(args.ignore_file)))
        paths = [e["path"] for e in client.tree(owner, repo, args.ref or metadata["default_branch"]) if e.get("type") == "blob"]
        checks = analyze_repository_paths(paths)
        score = security_score(findings, checks)
    except (ValueError, GitHubError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    branch = args.ref or metadata["default_branch"]
    if args.sarif:
        Path(args.sarif).write_text(to_sarif(findings), encoding="utf-8")
    if args.dashboard:
        write_dashboard(args.dashboard, metadata["full_name"], findings, checks, score)

    if args.json:
        print(json.dumps({"repository": metadata["full_name"], "branch": branch, "count": len(findings), "security_score": score, "checks": checks, "findings": [f.to_dict() for f in findings]}, indent=2))
    else:
        print("GitHub Guardian")
        print(f"Repository: {metadata['full_name']}")
        print(f"Branch: {branch}")
        print(f"Findings: {len(findings)}")
        print(f"Security score: {score}/100")
        for f in findings:
            print(f"[{f.severity.upper()}] {f.detector} | {f.path}:{f.line} | {f.redacted_match}")
            print(f"  Fix: {f.recommendation}")
        if not findings:
            print("No matching patterns detected.")

    if args.fail_on:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        threshold = order[args.fail_on]
        if any(order.get(f.severity, 99) <= threshold for f in findings):
            return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
