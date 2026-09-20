# GitHub Guardian

GitHub Guardian is an open-source security scanner for detecting accidentally exposed secrets and sensitive credentials in public GitHub repositories.

## Status

Early development. The project is currently building its core scanning engine.

## Goals

- Detect common exposed credentials and secrets
- Scan public GitHub repositories safely
- Never expose detected secret values in reports
- Produce actionable, redacted security findings
- Provide a foundation for automated repository security checks

## Responsible use

GitHub Guardian is intended for defensive security research and authorized security testing. Only scan repositories you are permitted to assess, and never use discovered credentials.

## Development

The initial implementation is being developed in Python with automated tests and GitHub Actions.
