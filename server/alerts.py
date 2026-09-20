import requests

def notify_slack(message,target=None):
    url=target
    if not url: return False
    requests.post(url,json={"text":message},timeout=10).raise_for_status()
    return True

def notify_email(subject,body,target=None):
    url=target
    if not url: return False
    requests.post(url,json={"subject":subject,"body":body},timeout=10).raise_for_status()
    return True
