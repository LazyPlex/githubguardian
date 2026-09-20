# GitHub Guardian

Open-source defensive security scanner for detecting accidentally exposed secrets and security risks in public GitHub repositories.

## Features

- Current branch secret scanning
- Historical commit diff scanning with deduplication
- Pull request diff scanning
- GitHub, AWS, Google, database, JWT and generic credential detectors
- Redacted findings
- SARIF 2.1.0 output
- Configurable suppressions via `.githubguardianignore`
- CI-friendly severity exit codes
- Repository security health checks and a 0 to 100 score
- GitHub Actions security posture checks
- Optional OSV dependency vulnerability checks
- Static HTML dashboard generation
- Optional GitHub Pages hosted dashboard workflow
- Hardened GitHub Actions PR scanning
- Weekly dependency update checks

## Quick start

Requires Python 3.10+.

    python -m venv .venv
    pip install -e ".[dev]"
    githubguardian owner/repository

Useful commands:

    githubguardian owner/repository --history 20
    githubguardian owner/repository --pr 123
    githubguardian owner/repository --dependencies
    githubguardian owner/repository --json
    githubguardian owner/repository --sarif guardian.sarif
    githubguardian owner/repository --dashboard report.html
    githubguardian owner/repository --history 1000
    githubguardian owner/repository --fail-on high

Set `GITHUB_TOKEN` for higher GitHub API limits. The scanner never validates or uses discovered credentials.

## What the audits cover

### Secrets

Deterministic detectors look for common GitHub, cloud, database, JWT and generic credential patterns. Matches are redacted before output.

### GitHub Actions

Workflow files are statically inspected for high-risk patterns including `pull_request_target`, broad write permissions, pull-request write access, direct curl or wget piping into shells, and mutable action references.

These are review signals, not proof of exploitability.

### Dependencies

The optional `--dependencies` flag sends supported manifest coordinates to the public OSV vulnerability database. This feature reports known vulnerability records and does not install, execute, or authenticate with anything.

Network access to OSV is required for this check.

## Safety

Use GitHub Guardian only on repositories you are authorized to assess. Never authenticate with a discovered credential. Findings are redacted before output. Tests use fake values only.

## Architecture

Repository or PR -> GitHub API -> file or diff retrieval -> deterministic detectors and static audits -> suppression -> severity sorting -> JSON, SARIF, CLI or HTML report.

## Historical coverage

The history mode scans patches from recent commits. It is useful for detecting secrets that appeared in recent changes, including deleted lines, but it is not a complete reconstruction of every historical tree state.

## Roadmap

The core v0.5 scanner is implemented. Future extensions can focus on deeper git tree reconstruction, richer dependency version-range handling, and remediation integrations. Code Scanning and GitHub Pages workflows are included.

## Development

    pytest -q

Never commit real credentials.

## License

MIT
