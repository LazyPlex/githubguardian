from __future__ import annotations
import hashlib, threading
from guardian.github import GitHubClient, parse_repository
from guardian.scanner import scan_repository

class ScanService:
    def __init__(self,db): self.db=db
    def validate_repository(self,user,name):
        owner,repo=parse_repository(name); return GitHubClient(token=user["access_token"]).repository(owner,repo)
    def queue_scan(self,rid): threading.Thread(target=self.run_scan,args=(rid,),daemon=True).start()
    def run_scan(self,rid):
        with self.db.connect() as c: row=c.execute("SELECT r.*,u.access_token FROM repositories r JOIN users u ON u.id=r.user_id WHERE r.id=?",(rid,)).fetchone()
        if not row:return
        sid=self.db.start_scan(rid)
        try:
            owner,repo=row["full_name"].split("/",1); _,findings=scan_repository(GitHubClient(token=row["access_token"]),owner,repo,row["ref"]); seen=set()
            for f in findings:
                fp=hashlib.sha256(f"{f.detector}|{f.path}|{f.line}|{f.redacted_match}".encode()).hexdigest(); seen.add(fp); self.db.upsert_finding(rid,fp,f)
            self.db.close_missing(rid,seen); self.db.finish_scan(sid,"completed",len(findings))
        except Exception: self.db.finish_scan(sid,"failed",0)
