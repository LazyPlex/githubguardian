from __future__ import annotations
import os, requests

class GitHubOAuth:
    def __init__(self):
        self.client_id=os.getenv("GITHUB_CLIENT_ID"); self.client_secret=os.getenv("GITHUB_CLIENT_SECRET")
        self.redirect_uri=os.getenv("GITHUB_OAUTH_REDIRECT_URI","http://localhost:8000/auth/github/callback")
    @property
    def configured(self): return bool(self.client_id and self.client_secret)
    def authorize_url(self,state):
        from urllib.parse import urlencode
        return "https://github.com/login/oauth/authorize?"+urlencode({"client_id":self.client_id,"redirect_uri":self.redirect_uri,"scope":"repo read:user","state":state})
    def exchange(self,code):
        r=requests.post("https://github.com/login/oauth/access_token",data={"client_id":self.client_id,"client_secret":self.client_secret,"code":code},headers={"Accept":"application/json"},timeout=15); r.raise_for_status()
        data=r.json()
        if "access_token" not in data: raise RuntimeError("GitHub OAuth failed")
        return data["access_token"]
    def user(self,t):
        r=requests.get("https://api.github.com/user",headers={"Authorization":f"Bearer {t}","Accept":"application/vnd.github+json"},timeout=15); r.raise_for_status(); return r.json()
