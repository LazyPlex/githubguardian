import sqlite3

from cryptography.fernet import Fernet

from server.db import Database


def test_oauth_tokens_are_encrypted_at_rest(tmp_path, monkeypatch):
    key = Fernet.generate_key().decode()
    monkeypatch.setenv("GUARDIAN_ENCRYPTION_KEY", key)
    path = tmp_path / "guardian.sqlite"
    db = Database(str(path))
    user_id = db.upsert_user({"id": 123, "login": "sample-user"}, "gho_sensitive_token_value")
    with sqlite3.connect(path) as conn:
        stored = conn.execute("SELECT access_token FROM users WHERE id=?", (user_id,)).fetchone()[0]
    assert stored != "gho_sensitive_token_value"
    assert db.get_user(user_id)["access_token"] == "gho_sensitive_token_value"


def test_team_role_is_scoped_to_team(tmp_path, monkeypatch):
    monkeypatch.setenv("GUARDIAN_ENCRYPTION_KEY", Fernet.generate_key().decode())
    db = Database(str(tmp_path / "teams.sqlite"))
    owner_id = db.upsert_user({"id": 1, "login": "owner"}, "token-owner")
    other_id = db.upsert_user({"id": 2, "login": "other"}, "token-other")
    team_id = db.create_team(owner_id, "Security")
    assert db.team_role(owner_id, team_id) == "owner"
    assert db.team_role(other_id, team_id) is None


def test_background_scan_repository_returns_decrypted_token(tmp_path, monkeypatch):
    monkeypatch.setenv("GUARDIAN_ENCRYPTION_KEY", Fernet.generate_key().decode())
    db = Database(str(tmp_path / "scan.sqlite"))
    user_id = db.upsert_user({"id": 77, "login": "scanner"}, "gho_scan_token")
    repo_id = db.upsert_repo(user_id, "owner/repo", "main")
    record = db.get_repo_for_scan(repo_id)
    assert record["access_token"] == "gho_scan_token"
    assert record["full_name"] == "owner/repo"
