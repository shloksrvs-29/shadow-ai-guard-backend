import sqlite3
import tempfile
from pathlib import Path

from app.audit.audit_log import AuditLog
from app.models.schemas import Decision


def _tmp_log() -> AuditLog:
    tmp_dir = tempfile.mkdtemp()
    return AuditLog(db_path=str(Path(tmp_dir) / "audit.db"))


def test_records_and_queries_entries():
    log = _tmp_log()
    log.record(org_id="acme", user_id="u1", platform="chatgpt", event_type="submit",
               decision=Decision.BLOCK, categories=["api_key"], highest_severity="high",
               raw_text="secret stuff")
    entries = log.query(org_id="acme")
    assert len(entries) == 1
    assert entries[0].decision == Decision.BLOCK


def test_chain_is_valid_after_multiple_writes():
    log = _tmp_log()
    for i in range(5):
        log.record(org_id="acme", user_id=f"u{i}", platform="claude", event_type="submit",
                   decision=Decision.ALLOW, categories=[], highest_severity=None,
                   raw_text=f"message {i}")
    valid, bad_row = log.verify_integrity()
    assert valid is True
    assert bad_row is None


def test_tampering_is_detected():
    log = _tmp_log()
    log.record(org_id="acme", user_id="u1", platform="claude", event_type="submit",
               decision=Decision.BLOCK, categories=["email"], highest_severity="medium",
               raw_text="sensitive")
    log.record(org_id="acme", user_id="u2", platform="claude", event_type="submit",
               decision=Decision.ALLOW, categories=[], highest_severity=None,
               raw_text="safe text")

    # Simulate an out-of-band edit directly on the DB file (bypassing the API).
    conn = sqlite3.connect(log._db_path)
    conn.execute("UPDATE audit_entries SET decision = 'allow' WHERE id = 1")
    conn.commit()
    conn.close()

    valid, bad_row = log.verify_integrity()
    assert valid is False
    assert bad_row == 1
