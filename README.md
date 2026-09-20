# GitHub Guardian

Open-source defensive security scanner for detecting accidentally exposed secrets and security risks in public GitHub repositories.

## Features

- Current branch secret scanning
- Historical commit diff scanning with deduplication
- Pull request diff scanning with paginated file retrieval
- GitHub, AWS, Google, database, JWT and generic credential detectors
- Redacted findings
- SARIF 2.1.0 output
- Configurable suppressions via `.githubguardianignore`
- Baseline support for accepting known findings while detecting new ones
- CI-friendly severity exit codes
- Repository security health checks and a 0 to 100 score
- GitHub Actions security posture checks
- Optional OSV dependency vulnerability checks
- Static HTML dashboard generation
- Optional GitHub Pages hosted dashboard workflow
- Hardened GitHub Actions PR scanning
- Retry and rate-limit aware GitHub API client
- Weekly audit workflow and Dependabot updates

## Quick start

Requires Python 3.10+.

    python -m venv .venv
    pip install -e ".[dev]"
    githubguardian owner/repository

Useful commands:

    githubguardian owner/repository --history 20
    githubguardian owner/repository --history-all
    githubguardian owner/repository --pr 123
    githubguardian owner/repository --dependencies
    githubguardian owner/repository --baseline guardian-baseline.json
    githubguardian owner/repository --write-baseline guardian-baseline.json
    githubguardian owner/repository --json
    githubguardian owner/repository --sarif guardian.sarif
    githubguardian owner/repository --dashboard report.html
    githubguardian owner/repository --fail-on high

Set `GITHUB_TOKEN` for higher GitHub API limits. The scanner never validates or uses discovered credentials.

## Baselines

Generate a reviewed baseline from the current scan:

    githubguardian owner/repository --write-baseline guardian-baseline.json

Then fail only on findings that are not already present in that baseline:

    githubguardian owner/repository --baseline guardian-baseline.json --fail-on high

Baselines are local JSON files. Review them before committing and never put real secrets in them.

## What the audits cover

### Secrets

Deterministic detectors look for common GitHub, cloud, database, JWT and generic credential patterns. Matches are redacted before output.

### GitHub Actions

Workflow files are statically inspected for high-risk patterns including `pull_request_target`, broad write permissions, pull-request write access, direct curl or wget piping into shells, and mutable action references.

These are review signals, not proof of exploitability.

### Dependencies

The optional `--dependencies` flag sends supported manifest coordinates to the public OSV vulnerability database. It reports known vulnerability records and does not install, execute, or authenticate with anything.

Network access to OSV is required for this check.

## Safety

Use GitHub Guardian only on repositories you are authorized to assess. Never authenticate with a discovered credential. Findings are redacted before output. Tests use fake values only.

## Architecture

Repository or PR -> GitHub API -> file or diff retrieval -> deterministic detectors and static audits -> suppression or baseline -> severity sorting -> JSON, SARIF, CLI or HTML report.

## Historical coverage

History mode scans commit patches, including deleted lines. Use `--history N` for a bounded scan or `--history-all` to paginate through every reachable commit on the selected ref. Exhaustive mode can be slow and is subject to GitHub API rate limits. Patch scanning is not a reconstruction of every historical tree state.

## Development

    pytest -q

Never commit real credentials.

## License

MIT

## SaaS mode

GitHub Guardian now includes an optional hosted service layer under `server/`.

Capabilities:

- GitHub OAuth sign-in
- Multiple repository monitoring per account
- SQLite persistence for repositories, scans and findings
- Finding lifecycle states: open, acknowledged and resolved
- Configurable Slack and email webhook alerts
- Scheduled rescans through GitHub Actions
- Browser dashboard
- Docker and Docker Compose deployment

Run locally:

    pip install -r requirements-saas.txt
    GITHUB_CLIENT_ID=... GITHUB_CLIENT_SECRET=... uvicorn server.app:app --host 0.0.0.0 --port 8000

Required deployment secrets:

    GITHUB_CLIENT_ID
    GITHUB_CLIENT_SECRET
    GITHUB_OAUTH_REDIRECT_URI
    GUARDIAN_SCHEDULE_TOKEN

For scheduled scanning, configure `GUARDIAN_URL` and `GUARDIAN_SCHEDULE_TOKEN` as GitHub Actions secrets. Do not commit OAuth credentials, schedule tokens, database files or real secrets.

The hosted layer is intentionally defensive. It only invokes the existing scanner against repositories the signed-in GitHub account can access and never attempts to authenticate with discovered credentials.
