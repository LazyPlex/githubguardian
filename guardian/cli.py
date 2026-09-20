"""Command-line interface for GitHub Guardian."""

import argparse
import json
import sys

from .github import GitHubClient, GitHubError, parse_repository
from .scanner import scan_repository


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="githubguardian",
        description="Scan an authorized/public GitHub repository for exposed secrets.",
    )
    parser.add_argument("repository", help="owner/name or a GitHub repository URL")
    parser.add_argument("--ref")
    parser.add_argument("--max-files", type=int, default=500)
    parser.add_argument("--max-file-bytes", type=int, default=1_000_000)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--token", help="Optional GitHub token. Prefer GITHUB_TOKEN.")
    args = parser.parse_args()

    try:
        owner, repo = parse_repository(args.repository)
        metadata, findings = scan_repository(
            GitHubClient(token=args.token), owner, repo,
            ref=args.ref, max_files=args.max_files, max_file_bytes=args.max_file_bytes,
        )
    except (ValueError, GitHubError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    branch = args.ref or metadata["default_branch"]
    if args.json:
        print(json.dumps({
            "repository": metadata["full_name"],
            "branch": branch,
            "findings": [finding.to_dict() for finding in findings],
            "count": len(findings),
        }, indent=2))
        return 0

    print("GitHub Guardian")
    print(f"Repository: {metadata['full_name']}")
    print(f"Branch: {branch}")
    print(f"Findings: {len(findings)}")
    print()

    for finding in findings:
        print(f"[{finding.severity.upper()}] {finding.detector}")
        print(f"  File: {finding.path}")
        print(f"  Line: {finding.line}")
        print(f"  Match: {finding.redacted_match}")
        print(f"  Fix: {finding.recommendation}")
        print()

    if not findings:
        print("No matching patterns detected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
