# GitHub Guardian

Open-source defensive security scanner for detecting accidentally exposed secrets and sensitive credentials in public GitHub repositories.

## Features

- Current branch scanning
- Historical commit diff scanning
- Pull request diff scanning
- GitHub, AWS, Google, database, JWT and generic credential detectors
- Redacted findings
- SARIF 2.1.0 output for GitHub code scanning
- Configurable suppressions via `.githubguardianignore`
- CI-friendly severity exit codes
- Repository security health checks and a 0 to 100 score
- Dependency-free static HTML dashboard generation
- GitHub Actions PR scanning
- Weekly dependency update checks

## Quick start

Requires Python 3.10+.

    python -m venv .venv
    pip install -e ".[dev]"
    githubguardian owner/repository

Useful commands:

    githubguardian owner/repository --history 20
    githubguardian owner/repository --pr 123
    githubguardian owner/repository --json
    githubguardian owner/repository --sarif guardian.sarif
    githubguardian owner/repository --dashboard report.html
    githubguardian owner/repository --fail-on high

Set `GITHUB_TOKEN` for higher GitHub API limits. The scanner does not validate or use discovered credentials.

## Safety

Use GitHub Guardian only on repositories you are authorized to assess. Never authenticate with a discovered credential. Findings are redacted before output.

## Architecture

Repository or PR -> GitHub API -> file/diff retrieval -> deterministic detectors -> suppression -> severity sorting -> JSON, SARIF, CLI or HTML report.

## Roadmap

Future work can focus on more provider-specific detectors, stronger historical coverage, dependency vulnerability feeds, workflow permission analysis, a hosted dashboard and richer remediation integrations.

## Development

    pytest -q

Never commit real credentials. Tests must use fake values only.

## License

MIT
