import ipaddress
import os
from urllib.parse import urlparse

import requests


def _validate_target(kind, target):
    parsed = urlparse(target or "")
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Alert webhook must be a valid HTTPS URL")
    host = parsed.hostname.lower().rstrip(".")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        raise ValueError("Private or non-public webhook addresses are not allowed")
    if kind == "slack" and host != "hooks.slack.com":
        raise ValueError("Slack webhook host must be hooks.slack.com")
    if kind == "email":
        allowed = {
            item.strip().lower()
            for item in os.getenv("GUARDIAN_EMAIL_WEBHOOK_HOSTS", "").split(",")
            if item.strip()
        }
        if host not in allowed:
            raise ValueError("Email webhook host is not allowlisted")
    return target


def _post(kind, url, payload):
    safe_url = _validate_target(kind, url)
    response = requests.post(safe_url, json=payload, timeout=10, allow_redirects=False)
    response.raise_for_status()
    return True


def notify_slack(message, target=None):
    if not target:
        return False
    return _post("slack", target, {"text": message})


def notify_email(subject, body, target=None):
    if not target:
        return False
    return _post("email", target, {"subject": subject, "body": body})
