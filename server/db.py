from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone

from cryptography.fernet import Fernet, InvalidToken


def now():
    return datetime.now(timezone.utc).isoformat()


class Database:
    def __init__(self, path):
        self.path = path
        key = os.getenv("GUARDIAN_ENCRYPTION_KEY")
        self.fernet = Fernet(key.encode()) if key else None
        self.init()

    def _encrypt(self, value):
        if not self.fernet:
            raise RuntimeError("GUARDIAN_ENCRYPTION_KEY is required to store OAuth tokens")
        return self.fernet.encrypt(value.encode()).decode()

    def _decrypt(self, value):
        if not self.fernet:
            raise RuntimeError("GUARDIAN_ENCRYPTION_KEY is required to read OAuth tokens")
        try:
            return self.fernet.decrypt(value.encode()).decode()
        except InvalidToken as exc:
            raise RuntimeError("Stored GitHub token cannot be decrypted; check GUARDIAN_ENCRYPTION_KEY") from exc

    def connect(self):
        c = sqlite3.connect(self.path)
        c.row_factory = sqlite3.Row
        return c

    def init(self):
        with self.connect() as c:
            c.executescript("""CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,github_id INTEGER UNIQUE NOT NULL,login TEXT NOT NULL,access_token TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS teams(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,owner_id INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS team_members(team_id INTEGER NOT NULL,user_id INTEGER NOT NULL,role TEXT NOT NULL DEFAULT 'member',UNIQUE(team_id,user_id)); CREATE TABLE IF NOT EXISTS repositories(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,full_name TEXT NOT NULL,ref TEXT NOT NULL,team_id INTEGER,UNIQUE(user_id,full_name));
CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY AUTOINCREMENT,repository_id INTEGER NOT NULL,fingerprint TEXT NOT NULL,detector TEXT NOT NULL,severity TEXT NOT NULL,path TEXT NOT NULL,line INTEGER NOT NULL,redacted_match TEXT NOT NULL,recommendation TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'open',first_seen TEXT NOT NULL,last_seen TEXT NOT NULL,UNIQUE(repository_id,fingerprint));
CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY AUTOINCREMENT,repository_id INTEGER NOT NULL,status TEXT NOT NULL,finding_count INTEGER NOT NULL DEFAULT 0,started_at TEXT NOT NULL,finished_at TEXT);
CREATE TABLE IF NOT EXISTS alert_configs(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,kind TEXT NOT NULL,target TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1);""")
            # Encrypt pre-existing plaintext OAuth tokens during the first keyed startup.
            if self.fernet:
                rows = c.execute("SELECT id,access_token FROM users").fetchall()
                for row in rows:
                    token = row["access_token"]
                    if token.startswith("gAAAA"):
                        # An encrypted value that fails to decrypt means the key is wrong.
                        self.fernet.decrypt(token.encode())
                    else:
                        c.execute("UPDATE users SET access_token=? WHERE id=?", (self._encrypt(token), row["id"]))

    def upsert_user(self, u, token):
        encrypted = self._encrypt(token)
        with self.connect() as c:
            c.execute("INSERT INTO users(github_id,login,access_token,created_at) VALUES(?,?,?,?) ON CONFLICT(github_id) DO UPDATE SET login=excluded.login,access_token=excluded.access_token", (u["id"], u["login"], encrypted, now()))
            return c.execute("SELECT id FROM users WHERE github_id=?", (u["id"],)).fetchone()["id"]

    def get_user(self, uid):
        with self.connect() as c:
            row = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
            if not row:
                return None
            user = dict(row)
            user["access_token"] = self._decrypt(user["access_token"])
            return user

    def create_team(self, uid, name):
        with self.connect() as c:
            cur = c.execute("INSERT INTO teams(name,owner_id) VALUES(?,?)", (name, uid))
            tid = cur.lastrowid
            c.execute("INSERT INTO team_members(team_id,user_id,role) VALUES(?,?,?)", (tid, uid, "owner"))
            return tid

    def list_teams(self, uid):
        with self.connect() as c:
            return [dict(x) for x in c.execute("SELECT t.* FROM teams t JOIN team_members m ON m.team_id=t.id WHERE m.user_id=?", (uid,)).fetchall()]

    def add_team_member(self, team_id, login, role="member"):
        with self.connect() as c:
            user = c.execute("SELECT id FROM users WHERE login=?", (login,)).fetchone()
            if not user:
                return False
            c.execute("INSERT INTO team_members(team_id,user_id,role) VALUES(?,?,?) ON CONFLICT(team_id,user_id) DO UPDATE SET role=excluded.role", (team_id, user["id"], role))
            return True

    def team_role(self, uid, team_id):
        with self.connect() as c:
            row = c.execute("SELECT role FROM team_members WHERE team_id=? AND user_id=?", (team_id, uid)).fetchone()
            return row["role"] if row else None

    def team_access(self, uid, team_id):
        return self.team_role(uid, team_id) is not None

    def upsert_repo(self, uid, name, ref, team_id=None):
        with self.connect() as c:
            c.execute("INSERT INTO repositories(user_id,full_name,ref,team_id) VALUES(?,?,?,?) ON CONFLICT(user_id,full_name) DO UPDATE SET ref=excluded.ref", (uid, name, ref, team_id))
            return c.execute("SELECT id FROM repositories WHERE user_id=? AND full_name=?", (uid, name)).fetchone()["id"]

    def start_scan(self, rid):
        with self.connect() as c:
            return c.execute("INSERT INTO scans(repository_id,status,started_at) VALUES(?,?,?)", (rid, "running", now())).lastrowid

    def finish_scan(self, sid, status, count):
        with self.connect() as c:
            c.execute("UPDATE scans SET status=?,finding_count=?,finished_at=? WHERE id=?", (status, count, now(), sid))

    def upsert_finding(self, rid, fp, finding):
        with self.connect() as c:
            before = c.execute("SELECT 1 FROM findings WHERE repository_id=? AND fingerprint=?", (rid, fp)).fetchone() is not None
            c.execute("""INSERT INTO findings(repository_id,fingerprint,detector,severity,path,line,redacted_match,recommendation,status,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(repository_id,fingerprint) DO UPDATE SET severity=excluded.severity,path=excluded.path,line=excluded.line,redacted_match=excluded.redacted_match,recommendation=excluded.recommendation,last_seen=excluded.last_seen,status='open'""", (rid, fp, finding.detector, finding.severity, finding.path, finding.line, finding.redacted_match, finding.recommendation, "open", now(), now()))
            return not before

    def close_missing(self, rid, seen):
        with self.connect() as c:
            rows = c.execute("SELECT fingerprint FROM findings WHERE repository_id=? AND status='open'", (rid,)).fetchall()
            for row in rows:
                if row["fingerprint"] not in seen:
                    c.execute("UPDATE findings SET status='resolved',last_seen=? WHERE repository_id=? AND fingerprint=?", (now(), rid, row["fingerprint"]))

    def list_repositories(self, uid):
        with self.connect() as c:
            return [dict(x) for x in c.execute("SELECT * FROM repositories WHERE user_id=? ORDER BY full_name", (uid,)).fetchall()]

    def add_alert(self, uid, kind, target):
        with self.connect() as c:
            c.execute("INSERT INTO alert_configs(user_id,kind,target) VALUES(?,?,?)", (uid, kind, target))

    def list_alerts(self, uid):
        with self.connect() as c:
            return [dict(x) for x in c.execute("SELECT * FROM alert_configs WHERE user_id=? AND enabled=1", (uid,)).fetchall()]

    def get_repo_for_scan(self, repository_id):
        with self.connect() as c:
            row = c.execute(
                "SELECT r.*,u.access_token FROM repositories r JOIN users u ON u.id=r.user_id WHERE r.id=?",
                (repository_id,),
            ).fetchone()
        if not row:
            return None
        result = dict(row)
        result["access_token"] = self._decrypt(result["access_token"])
        return result

    def list_repos_all(self):
        with self.connect() as c:
            rows = [dict(x) for x in c.execute("SELECT r.*,u.access_token FROM repositories r JOIN users u ON u.id=r.user_id").fetchall()]
        for row in rows:
            row["access_token"] = self._decrypt(row["access_token"])
        return rows

    def update_finding_status(self, uid, finding_id, status):
        if status not in {"open", "acknowledged", "resolved"}:
            raise ValueError("Invalid finding status")
        with self.connect() as c:
            c.execute("UPDATE findings SET status=?,last_seen=? WHERE id=? AND repository_id IN (SELECT id FROM repositories WHERE user_id=?)", (status, now(), finding_id, uid))
            return c.total_changes > 0

    def list_findings(self, uid):
        with self.connect() as c:
            rows = c.execute("SELECT f.*,r.full_name FROM findings f JOIN repositories r ON r.id=f.repository_id WHERE r.user_id=? ORDER BY last_seen DESC", (uid,)).fetchall()
            return [dict(x) for x in rows]
