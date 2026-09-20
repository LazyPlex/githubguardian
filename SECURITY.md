# Security Policy

## Reporting a vulnerability in GitHub Guardian

If you discover a security vulnerability in GitHub Guardian itself, please report it privately to the repository maintainer rather than opening a public issue.

Do not include live credentials, access tokens, private keys, or other sensitive secrets in a public issue.

## Responsible use

GitHub Guardian is designed for defensive security research and authorized testing. Users are responsible for ensuring they have permission to scan repositories and for handling findings responsibly.

GitHub Guardian does not authorize access to, use of, or testing against credentials discovered by the scanner.

## Secret handling

The project should never intentionally store or publish detected secret values. Findings should be redacted before they are displayed, logged, persisted, or reported.
