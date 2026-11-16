from __future__ import annotations

import hashlib
import logging
import threading

from guardian.github import GitHubClient, parse_repository
from guardian.scanner import scan_repository
from .alerts import notify_email, notify_slack

logger = logging.getLogger(__name__)


class ScanService:
    def __init__(self, db):
        self.db = db

    def validate_repository(self, user, name):
        owner, repo = parse_repository(name)
        return GitHubClient(token=user["access_token"]).repository(owner, repo)

    def queue_scan(self, rid):
        thread = threading.Thread(target=self.run_scan, args=(rid,), daemon=True)
        thread.start()

    def run_scan(self, rid):
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT r.*,u.access_token FROM repositories r JOIN users u ON u.id=r.user_id WHERE r.id=?",
                (rid,),
            ).fetchone()
        if not row:
            logger.warning("Scan requested for missing repository id=%s", rid)
            return

        sid = self.db.start_scan(rid)
        try:
            owner, repo = row["full_name"].split("/", 1)
            _, findings = scan_repository(
                GitHubClient(token=row["access_token"]), owner, repo, row["ref"]
            )
            seen = set()
            for finding in findings:
                fingerprint = hashlib.sha256(
                    f"{finding.detector}|{finding.path}|{finding.line}|{finding.redacted_match}".encode()
                ).hexdigest()
                seen.add(fingerprint)
                created = self.db.upsert_finding(rid, fingerprint, finding)
                if not created:
                    continue

                with self.db.connect() as conn:
                    user_id = conn.execute(
                        "SELECT user_id FROM repositories WHERE id=?", (rid,)
                    ).fetchone()["user_id"]

                message = (
                    f"GitHub Guardian: new {finding.severity} finding in "
                    f"{row['full_name']} at {finding.path}:{finding.line} ({finding.detector})"
                )
                for alert in self.db.list_alerts(user_id):
                    try:
                        if alert["kind"] == "slack":
                            notify_slack(message, alert["target"])
                        elif alert["kind"] == "email":
                            notify_email("GitHub Guardian security finding", message, alert["target"])
                    except Exception:
                        logger.exception("Alert delivery failed for alert id=%s", alert.get("id"))

            self.db.close_missing(rid, seen)
            self.db.finish_scan(sid, "completed", len(findings))
        except Exception:
            logger.exception("Repository scan failed for repository id=%s", rid)
            self.db.finish_scan(sid, "failed", 0)
