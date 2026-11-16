from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import secrets
import time
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field

from .alerts import notify_email, notify_slack
from .db import Database
from .github_oauth import GitHubOAuth
from .scan_service import ScanService

ROOT = Path(__file__).resolve().parent
app = FastAPI(title="GitHub Guardian")
db = Database(os.getenv("GUARDIAN_DB", "guardian.db"))
oauth = GitHubOAuth()
scanner = ScanService(db)
SESSION_TTL = 12 * 60 * 60


def _session_secret() -> bytes:
    value = os.getenv("GUARDIAN_SESSION_SECRET")
    if not value or len(value) < 32:
        raise HTTPException(503, "GUARDIAN_SESSION_SECRET must be configured with at least 32 characters")
    return value.encode()


def _session_cookie(uid: int) -> str:
    payload = f"{uid}.{int(time.time()) + SESSION_TTL}.{secrets.token_urlsafe(16)}"
    signature = hmac.new(_session_secret(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{signature}"


def _session_user_id(value: str | None) -> int:
    if not value:
        raise HTTPException(401, "Sign in with GitHub first")
    try:
        uid_text, expiry_text, nonce, signature = value.split(".", 3)
        payload = f"{uid_text}.{expiry_text}.{nonce}"
        expected = hmac.new(_session_secret(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected) or int(expiry_text) < int(time.time()):
            raise ValueError
        return int(uid_text)
    except (ValueError, TypeError):
        raise HTTPException(401, "Invalid or expired session")


def _validate_alert_target(kind: str, target: str) -> str:
    parsed = urlparse(target.strip())
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise HTTPException(400, "Alert endpoints must be valid HTTPS URLs")
    host = parsed.hostname.lower().rstrip(".")
    try:
        ip = ipaddress.ip_address(host)
        if not ip.is_global:
            raise HTTPException(400, "Private or non-public alert endpoint addresses are not allowed")
    except ValueError:
        pass
    if kind == "slack" and host != "hooks.slack.com":
        raise HTTPException(400, "Slack alerts must use hooks.slack.com webhook URLs")
    if kind == "email":
        allowed = {x.strip().lower() for x in os.getenv("GUARDIAN_EMAIL_WEBHOOK_HOSTS", "").split(",") if x.strip()}
        if host not in allowed:
            raise HTTPException(400, "Email webhook host is not allowlisted by the server operator")
    return target.strip()


class RepoRequest(BaseModel):
    repository: str
    ref: str | None = None


@app.get("/", response_class=HTMLResponse)
def home():
    return (ROOT / "static" / "index.html").read_text(encoding="utf-8")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/auth/github")
def auth_github():
    if not oauth.configured:
        raise HTTPException(503, "GitHub OAuth is not configured")
    _session_secret()
    state = secrets.token_urlsafe(32)
    response = RedirectResponse(oauth.authorize_url(state))
    response.set_cookie("guardian_oauth_state", state, httponly=True, samesite="lax",
                        secure=os.getenv("COOKIE_SECURE", "0") == "1", max_age=600)
    return response


@app.get("/auth/github/callback")
def auth_callback(request: Request, code: str, state: str | None = None):
    expected = request.cookies.get("guardian_oauth_state")
    if not state or not expected or not secrets.compare_digest(state, expected):
        raise HTTPException(400, "Invalid OAuth state")
    token = oauth.exchange(code)
    user = oauth.user(token)
    uid = db.upsert_user(user, token)
    response = RedirectResponse("/dashboard")
    response.set_cookie("guardian_user", _session_cookie(uid), httponly=True, samesite="lax",
                        secure=os.getenv("COOKIE_SECURE", "0") == "1", max_age=SESSION_TTL)
    response.delete_cookie("guardian_oauth_state")
    return response


def current_user(request: Request):
    uid = _session_user_id(request.cookies.get("guardian_user"))
    user = db.get_user(uid)
    if not user:
        raise HTTPException(401, "Session expired")
    return user


@app.post("/api/repos")
def add_repo(payload: RepoRequest, request: Request):
    user = current_user(request)
    repo = scanner.validate_repository(user, payload.repository)
    rid = db.upsert_repo(user["id"], repo["full_name"], payload.ref or repo["default_branch"])
    scanner.queue_scan(rid)
    return {"repository": repo["full_name"], "status": "queued"}


class TeamRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)


class MemberRequest(BaseModel):
    login: str = Field(min_length=1, max_length=39)
    role: str = "member"


@app.post("/api/teams")
def create_team(payload: TeamRequest, request: Request):
    return {"team_id": db.create_team(current_user(request)["id"], payload.name.strip())}


@app.get("/api/teams")
def teams(request: Request):
    return {"teams": db.list_teams(current_user(request)["id"])}


@app.post("/api/teams/{team_id}/members")
def add_member(team_id: int, payload: MemberRequest, request: Request):
    uid = current_user(request)["id"]
    role = db.team_role(uid, team_id)
    if role not in {"owner", "admin"}:
        raise HTTPException(403, "Only team owners or admins can add members")
    if payload.role not in {"member", "admin"} or (role != "owner" and payload.role != "member"):
        raise HTTPException(400, "Only team owners can grant admin; owner cannot be granted through this endpoint")
    if not db.add_team_member(team_id, payload.login, payload.role):
        raise HTTPException(404, "GitHub user must sign in first")
    return {"status": "added"}


@app.get("/api/repos")
def repos(request: Request):
    return {"repositories": db.list_repositories(current_user(request)["id"])}


@app.get("/api/alerts")
def alerts(request: Request):
    return {"alerts": db.list_alerts(current_user(request)["id"])}


class FindingStatusRequest(BaseModel):
    status: str


@app.patch("/api/findings/{finding_id}")
def update_finding(finding_id: int, payload: FindingStatusRequest, request: Request):
    user = current_user(request)
    try:
        changed = db.update_finding_status(user["id"], finding_id, payload.status)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if not changed:
        raise HTTPException(404, "Finding not found")
    return {"status": payload.status}


class AlertRequest(BaseModel):
    kind: str
    target: str = Field(min_length=1, max_length=2048)


@app.post("/api/alerts")
def add_alert(payload: AlertRequest, request: Request):
    user = current_user(request)
    if payload.kind not in {"slack", "email"}:
        raise HTTPException(400, "Unsupported alert type")
    target = _validate_alert_target(payload.kind, payload.target)
    db.add_alert(user["id"], payload.kind, target)
    return {"status": "configured"}


@app.get("/api/findings")
def findings(request: Request):
    return {"findings": db.list_findings(current_user(request)["id"])}


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    current_user(request)
    return (ROOT / "static" / "dashboard.html").read_text(encoding="utf-8")


@app.post("/api/internal/scan-all")
def scan_all(request: Request):
    token = os.getenv("GUARDIAN_SCHEDULE_TOKEN")
    supplied = request.headers.get("X-Guardian-Schedule-Token", "")
    if not token or not secrets.compare_digest(supplied, token):
        raise HTTPException(403, "Forbidden")
    for repo in db.list_repos_all():
        scanner.queue_scan(repo["id"])
    return {"status": "queued"}


@app.post("/api/logout")
def logout():
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie("guardian_user")
    return response
