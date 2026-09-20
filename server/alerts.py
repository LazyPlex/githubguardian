import os, requests
def notify_slack(message):
    url=os.getenv("SLACK_WEBHOOK_URL")
    if not url:return False
    requests.post(url,json={"text":message},timeout=10).raise_for_status(); return True
def notify_email(subject,body):
    url=os.getenv("ALERT_EMAIL_WEBHOOK")
    if not url:return False
    requests.post(url,json={"subject":subject,"body":body},timeout=10).raise_for_status(); return True
