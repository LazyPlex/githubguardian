# Secure SaaS deployment configuration

The SaaS backend now signs browser sessions and encrypts GitHub OAuth tokens at rest. Configure these values before deploying or restarting the backend.

## Required secrets

Generate a Fernet encryption key:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Generate a separate session-signing secret:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Set both values in the backend environment:

- `GUARDIAN_ENCRYPTION_KEY`: the Fernet key generated above. Keep it stable and back it up securely. Losing it makes stored OAuth tokens unrecoverable.
- `GUARDIAN_SESSION_SECRET`: a random secret of at least 32 characters. Rotating it invalidates existing browser sessions.
- `COOKIE_SECURE=1`: required when serving the application over HTTPS.
- `GUARDIAN_SCHEDULE_TOKEN`: optional; only needed if the manual scheduler workflow is used.
- `GUARDIAN_EMAIL_WEBHOOK_HOSTS`: comma-separated exact HTTPS hostnames allowed for email webhook targets. Slack alerts are restricted to `hooks.slack.com`.

On startup, if an encryption key is configured, existing plaintext OAuth tokens in the SQLite users table are encrypted in place. Take a database backup first. Do not rotate or replace the encryption key without a planned token re-encryption migration.

## Automatic workflows paused

All workflows in `.github/workflows` are now `workflow_dispatch` only. Scheduled scans, push builds, PR scans, code scanning, and automatic releases will not run. Start an individual workflow manually from GitHub Actions when you are ready.

## Operational note

This repository change does not update deployment environment variables or GitHub repository secrets. Configure the backend environment before the next deployment. Existing users may need to sign in again after the new signed-cookie implementation is deployed.
