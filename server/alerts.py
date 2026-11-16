import requests


def _post(url, payload):
    response = requests.post(url, json=payload, timeout=10, allow_redirects=False)
    response.raise_for_status()
    return True


def notify_slack(message, target=None):
    if not target:
        return False
    return _post(target, {"text": message})


def notify_email(subject, body, target=None):
    if not target:
        return False
    return _post(target, {"subject": subject, "body": body})
