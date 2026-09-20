"""Command-line interface for GitHub Guardian."""

import argparse
import json
import sys
from pathlib import Path

from .dashboard import write_dashboard
from .dependencies import extract_dependencies, scan_dependencies
from .github import GitHubClient, GitHubError, parse_repository
from .health import analyze_repository_paths, security_score
from .history import scan_history, scan_pull_request
from .models import Finding
from .report import sort_findings
from .sarif import to_sarif
from .scanner import scan_repository
from .suppressions import apply_suppressions, load_suppressions
from .workflow import analyze_workflow


def main() -> int:
    parser = argparse.ArgumentParser(prog="githubguardian", description="Defensive security scanner for authorized/public GitHub repositories.")
    parser.add_argument("repository", help="owner/name or GitHub repository URL")
    parser.add_argument("--ref")
    parser.add_argument("--history", type=int, metavar="N", help="Scan up to N recent commits, paginating through the GitHub API.")\n    parser.add_argument("--history-all", action="store_true", help="Scan every reachable commit on the selected ref. This can be slow and GitHub API rate limits apply.")
    parser.add_argument("--pr", type=int, metavar="NUMBER")
    parser.add_argument("--max-files", type=int, default=500)
    parser.add_argument("--max-file-bytes", type=int, default=1000000)
    parser.add_argument("--ignore-file", default=".githubguardianignore")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--sarif", metavar="PATH")
    parser.add_argument("--dashboard", metavar="PATH")
    parser.add_argument("--score", action="store_true")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low"])
    parser.add_argument("--dependencies", action="store_true", help="Check supported manifests against the public OSV vulnerability database.")
    parser.add_argument("--no-workflow-audit", action="store_true", help="Skip static GitHub Actions security checks.")
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

        tree_entries = client.tree(owner, repo, args.ref or metadata["default_branch"])
        paths = [e["path"] for e in tree_entries if e.get("type") == "blob"]
        workflow_findings = []
        dependency_pairs = []
        for entry in tree_entries:
            path = entry.get("path", "")
            if not entry.get("type") == "blob":
                continue
            if path.lower().startswith(".github/workflows/") and path.lower().endswith((".yml", ".yaml")) and not args.no_workflow_audit:
                content = client.workflow_file(owner, repo, path, args.ref or metadata["default_branch"])
                if content:
                    workflow_findings.extend(analyze_workflow(path, content))
            if args.dependencies and path.lower().split("/")[-1] in {"requirements.txt", "package.json", "go.mod", "cargo.toml"}:
                content = client.workflow_file(owner, repo, path, args.ref or metadata["default_branch"])
                if content:
                    dependency_pairs.extend(extract_dependencies(path, content))

        if args.dependencies and dependency_pairs:
            for item in scan_dependencies(dependency_pairs):
                findings.append(Finding(
                    detector=f"OSV:{item['id']}",
                    severity=item["severity"],
                    path=item["package"],
                    line=0,
                    redacted_match=f"{item['package']} {item['version']}",
                    recommendation=item["summary"],
                ))

        findings = sort_findings(apply_suppressions(findings, load_suppressions(args.ignore_file)))
        checks = analyze_repository_paths(paths, workflow_findings)
        score = security_score(findings, checks)
    except (ValueError, GitHubError, OSError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    branch = args.ref or metadata["default_branch"]
    if args.sarif:
        Path(args.sarif).write_text(to_sarif(findings), encoding="utf-8")
    if args.dashboard:
        write_dashboard(args.dashboard, metadata["full_name"], findings, checks, score)

    if args.json:
        print(json.dumps({
            "repository": metadata["full_name"],
            "branch": branch,
            "count": len(findings),
            "security_score": score,
            "checks": checks,
            "workflow_findings": workflow_findings,
            "findings": [f.to_dict() for f in findings],
        }, indent=2))
    else:
        print("GitHub Guardian")
        print(f"Repository: {metadata['full_name']}")
        print(f"Branch: {branch}")
        print(f"Findings: {len(findings)}")
        print(f"Security score: {score}/100")
        for item in workflow_findings:
            print(f"[WORKFLOW {item['status'].upper()}] {item['path']} | {item['message']}")
        for f in findings:
            print(f"[{f.severity.upper()}] {f.detector} | {f.path}:{f.line} | {f.redacted_match}")
            print(f"  Fix: {f.recommendation}")
        if not findings:
            print("No matching secret or dependency vulnerability patterns detected.")

    if args.fail_on:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        threshold = order[args.fail_on]
        if any(order.get(f.severity, 99) <= threshold for f in findings):
            return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
