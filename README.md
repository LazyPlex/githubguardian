# GitHub Guardian

Open-source defensive security scanner for detecting accidentally exposed secrets and sensitive credentials in public GitHub repositories.

## Current release

GitHub Guardian 0.2.0 is a functional command-line scanner for one repository ref.

## Detection coverage

The current engine checks for:

- GitHub access tokens
- AWS access keys
- Google API keys
- Private key headers
- Generic API key, secret key, and access token assignments
- Database connection strings
- JWT-like tokens

Findings contain only redacted matches. GitHub Guardian does not intentionally print complete credential values.

## Quick start

Requires Python 3.10 or newer.

Create an environment and install:

    python -m venv .venv
    pip install -e ".[dev]"

Scan a repository:

    githubguardian owner/repository

A GitHub URL also works:

    githubguardian https://github.com/owner/repository

For higher API limits, provide a GitHub token through the environment:

    export GITHUB_TOKEN="YOUR_TOKEN"

Windows PowerShell:

    $env:GITHUB_TOKEN="YOUR_TOKEN"

Machine-readable output:

    githubguardian owner/repository --json

Useful controls:

    githubguardian owner/repository --ref main
    githubguardian owner/repository --max-files 200
    githubguardian owner/repository --max-file-bytes 500000

## How it works

1. Resolve the repository and default branch.
2. Retrieve the Git tree for that ref.
3. Filter obvious binary, vendor, and generated paths.
4. Read eligible text blobs within configured size limits.
5. Run deterministic secret detectors.
6. Return redacted findings with file, line, severity, and remediation guidance.

## Safety

GitHub Guardian is for defensive security research and authorized security testing.

Only scan repositories you are permitted to assess. Never authenticate with, validate, or otherwise use a credential discovered by the scanner.

If you find a real credential, treat it as sensitive data and recommend revocation and rotation through the appropriate owner or provider process.

## Limitations in 0.2.0

- Scans one branch, tag, or commit at a time.
- Does not scan historical commits yet.
- Does not analyze dependencies yet.
- Does not analyze GitHub Actions workflow security yet.
- Does not provide a web dashboard yet.
- Large repository trees can be rejected when GitHub reports a truncated recursive tree.

## Roadmap

### 0.3
- More provider-specific detectors
- Better false-positive handling
- SARIF output
- Scan statistics and exit codes

### 0.4
- Historical commit scanning
- Pull request scanning
- GitHub Actions integration

### 0.5
- Repository security health checks
- Dependency and configuration checks
- Web dashboard

## Development

Run the test suite:

    pytest -q

Never commit real credentials. Tests should use obviously fake values only.

See SECURITY.md and CONTRIBUTING.md for project policies.

## License

MIT
