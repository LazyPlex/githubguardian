from __future__ import annotations
import sqlite3
from datetime import datetime, timezone

def now(): return datetime.now(timezone.utc).isoformat()

class Database:
    def __init__(self,path): self.path=path; self.init()
    def connect(self):
        c=sqlite3.connect(self.path); c.row_factory=sqlite3.Row; return c
    def init(self):
        with self.connect() as c:
            c.executescript("""CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,github_id INTEGER UNIQUE NOT NULL,login TEXT NOT NULL,access_token TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS repositories(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,full_name TEXT NOT NULL,ref TEXT NOT NULL,UNIQUE(user_id,full_name));
CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY AUTOINCREMENT,repository_id INTEGER NOT NULL,fingerprint TEXT NOT NULL,detector TEXT NOT NULL,severity TEXT NOT NULL,path TEXT NOT NULL,line INTEGER NOT NULL,redacted_match TEXT NOT NULL,recommendation TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'open',first_seen TEXT NOT NULL,last_seen TEXT NOT NULL,UNIQUE(repository_id,fingerprint));
CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY AUTOINCREMENT,repository_id INTEGER NOT NULL,status TEXT NOT NULL,finding_count INTEGER NOT NULL DEFAULT 0,started_at TEXT NOT NULL,finished_at TEXT);
CREATE TABLE IF NOT EXISTS alert_configs(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,kind TEXT NOT NULL,target TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1);""")
    def upsert_user(self,u,t):
        with self.connect() as c:
            c.execute("INSERT INTO users(github_id,login,access_token,created_at) VALUES(?,?,?,?) ON CONFLICT(github_id) DO UPDATE SET login=excluded.login,access_token=excluded.access_token",(u["id"],u["login"],t,now()))
            return c.execute("SELECT id FROM users WHERE github_id=?",(u["id"],)).fetchone()["id"]
    def get_user(self,i):
        with self.connect() as c:
            x=c.execute("SELECT * FROM users WHERE id=?",(i,)).fetchone(); return dict(x) if x else None
    def upsert_repo(self,uid,name,ref):
        with self.connect() as c:
            c.execute("INSERT INTO repositories(user_id,full_name,ref) VALUES(?,?,?) ON CONFLICT(user_id,full_name) DO UPDATE SET ref=excluded.ref",(uid,name,ref))
            return c.execute("SELECT id FROM repositories WHERE user_id=? AND full_name=?",(uid,name)).fetchone()["id"]
    def start_scan(self,rid):
        with self.connect() as c: return c.execute("INSERT INTO scans(repository_id,status,started_at) VALUES(?,?,?)",(rid,"running",now())).lastrowid
    def finish_scan(self,sid,status,count):
        with self.connect() as c: c.execute("UPDATE scans SET status=?,finding_count=?,finished_at=? WHERE id=?",(status,count,now(),sid))
    def upsert_finding(self,rid,fp,f):
        with self.connect() as c:
            c.execute("""INSERT INTO findings(repository_id,fingerprint,detector,severity,path,line,redacted_match,recommendation,status,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(repository_id,fingerprint) DO UPDATE SET severity=excluded.severity,path=excluded.path,line=excluded.line,redacted_match=excluded.redacted_match,recommendation=excluded.recommendation,last_seen=excluded.last_seen,status='open'""",(rid,fp,f.detector,f.severity,f.path,f.line,f.redacted_match,f.recommendation,"open",now(),now()))
    def close_missing(self,rid,seen):
        with self.connect() as c:
            for x in c.execute("SELECT fingerprint FROM findings WHERE repository_id=? AND status='open'",(rid,)).fetchall():
                if x["fingerprint"] not in seen: c.execute("UPDATE findings SET status='resolved',last_seen=? WHERE repository_id=? AND fingerprint=?",(now(),rid,x["fingerprint"]))
    def list_findings(self,uid):
        with self.connect() as c:
            rows=c.execute("SELECT f.*,r.full_name FROM findings f JOIN repositories r ON r.id=f.repository_id WHERE r.user_id=? ORDER BY last_seen DESC",(uid,)).fetchall(); return [dict(x) for x in rows]
