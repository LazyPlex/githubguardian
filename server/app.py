from __future__ import annotations
import os, secrets
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
from .alerts import notify_email, notify_slack
from .db import Database
from .github_oauth import GitHubOAuth
from .scan_service import ScanService

ROOT=Path(__file__).resolve().parent
app=FastAPI(title="GitHub Guardian")
db=Database(os.getenv("GUARDIAN_DB","guardian.db"))
oauth=GitHubOAuth()
scanner=ScanService(db)

class RepoRequest(BaseModel):
    repository:str
    ref:str|None=None

@app.get("/",response_class=HTMLResponse)
def home(): return (ROOT/"static"/"index.html").read_text(encoding="utf-8")

@app.get("/health")
def health(): return {"status":"ok"}

@app.get("/auth/github")
def auth_github():
    if not oauth.configured: raise HTTPException(503,"GitHub OAuth is not configured")
    state=secrets.token_urlsafe(24)
    response=RedirectResponse(oauth.authorize_url(state))
    response.set_cookie("guardian_oauth_state",state,httponly=True,samesite="lax",secure=os.getenv("COOKIE_SECURE","0")=="1")
    return response

@app.get("/auth/github/callback")
def auth_callback(request:Request,code:str,state:str|None=None):
    expected=request.cookies.get("guardian_oauth_state")
    if not state or not expected or not secrets.compare_digest(state,expected): raise HTTPException(400,"Invalid OAuth state")
    token=oauth.exchange(code); user=oauth.user(token); uid=db.upsert_user(user,token)
    response=RedirectResponse("/dashboard"); response.set_cookie("guardian_user",str(uid),httponly=True,samesite="lax",secure=os.getenv("COOKIE_SECURE","0")=="1"); response.delete_cookie("guardian_oauth_state"); return response

def current_user(request:Request):
    raw=request.cookies.get("guardian_user")
    if not raw: raise HTTPException(401,"Sign in with GitHub first")
    try: uid=int(raw)
    except ValueError: raise HTTPException(401,"Invalid session")
    user=db.get_user(uid)
    if not user: raise HTTPException(401,"Session expired")
    return user

@app.post("/api/repos")
def add_repo(payload:RepoRequest,request:Request):
    user=current_user(request); repo=scanner.validate_repository(user,payload.repository)
    rid=db.upsert_repo(user["id"],repo["full_name"],payload.ref or repo["default_branch"]); scanner.queue_scan(rid)
    return {"repository":repo["full_name"],"status":"queued"}

@app.get("/api/repos")
def repos(request:Request): return {"repositories":db.list_repositories(current_user(request)["id"])}

@app.get("/api/alerts")
def alerts(request:Request): return {"alerts":db.list_alerts(current_user(request)["id"])}

class AlertRequest(BaseModel):
    kind:str
    target:str

@app.post("/api/alerts")
def add_alert(payload:AlertRequest,request:Request):
    user=current_user(request)
    if payload.kind not in {"slack","email"}: raise HTTPException(400,"Unsupported alert type")
    db.add_alert(user["id"],payload.kind,payload.target)
    return {"status":"configured"}

@app.get("/api/findings")
def findings(request:Request): return {"findings":db.list_findings(current_user(request)["id"])}

@app.get("/dashboard",response_class=HTMLResponse)
def dashboard(request:Request):
    current_user(request); return (ROOT/"static"/"dashboard.html").read_text(encoding="utf-8")

@app.post("/api/internal/scan-all")\ndef scan_all(request:Request):\n    if not os.getenv("GUARDIAN_SCHEDULE_TOKEN") or request.headers.get("X-Guardian-Schedule-Token") != os.getenv("GUARDIAN_SCHEDULE_TOKEN"): raise HTTPException(403,"Forbidden")\n    for repo in db.list_repos_all(): scanner.queue_scan(repo["id"])\n    return {"status":"queued"}\n\n@app.post("/api/logout")
def logout():
    response=RedirectResponse("/",status_code=303); response.delete_cookie("guardian_user"); return response
