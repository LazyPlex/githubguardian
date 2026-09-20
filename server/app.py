from __future__ import annotations
import os, secrets
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
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
    return RedirectResponse(oauth.authorize_url(state))

@app.get("/auth/github/callback")
def auth_callback(code:str):
    token=oauth.exchange(code); user=oauth.user(token); uid=db.upsert_user(user,token)
    response=RedirectResponse("/dashboard"); response.set_cookie("guardian_user",str(uid),httponly=True,samesite="lax",secure=os.getenv("COOKIE_SECURE","0")=="1"); return response

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

@app.get("/api/findings")
def findings(request:Request): return {"findings":db.list_findings(current_user(request)["id"])}

@app.get("/dashboard",response_class=HTMLResponse)
def dashboard(request:Request):
    current_user(request); return (ROOT/"static"/"dashboard.html").read_text(encoding="utf-8")

@app.post("/api/logout")
def logout():
    response=RedirectResponse("/",status_code=303); response.delete_cookie("guardian_user"); return response
