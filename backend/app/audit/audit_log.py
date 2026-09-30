"""
Tamper-evident audit log.

Every entry stores a SHA-256 hash of (its own content + the previous entry's
hash) -- the same chaining idea used in blockchains/git. If any historical
row is edited or deleted out of band, recomputing the chain from row 1
will reveal a mismatch, which `verify_integrity()` reports. This satisfies
objective 2.4 (auditability / tamper-evidence) without needing an external
ledger service for the prototype.

Storage: SQLite for simplicity in a mini-project deployment. Swap the
`_connect()` implementation for Postgres/MySQL in production -- the rest of
the module is DB-agnostic SQL.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator, Optional

from app.config import get_settings
from app.models.schemas import AuditEntry, Decision

_GENESIS_HASH = "0" * 64


def _redact_preview(text: str, max_len: int = 120) -> str:
    """Store only a short preview in the audit log, never the full raw text,
    to avoid the audit store itself becoming a sensitive-data honeypot."""
    flat = " ".join(text.split())
    return flat[:max_len] + ("..." if len(flat) > max_len else "")


class AuditLog:
    def __init__(self, db_path: str | None = None) -> None:
        self._db_path = db_path or get_settings().audit_db_path
        os.makedirs(os.path.dirname(self._db_path) or ".", exist_ok=True)
        self._init_db()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    org_id TEXT,
                    user_id TEXT,
                    platform TEXT,
                    event_type TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    categories TEXT NOT NULL,
                    highest_severity TEXT,
                    text_preview TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL
                )
                """
            )

    def _last_hash(self, conn: sqlite3.Connection) -> str:
        row = conn.execute(
            "SELECT entry_hash FROM audit_entries ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return row["entry_hash"] if row else _GENESIS_HASH

    @staticmethod
    def _compute_hash(prev_hash: str, payload: dict) -> str:
        canonical = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()

    def record(
        self,
        *,
        org_id: Optional[str],
        user_id: Optional[str],
        platform: Optional[str],
        event_type: str,
        decision: Decision,
        categories: list[str],
        highest_severity: Optional[str],
        raw_text: str,
    ) -> AuditEntry:
        timestamp = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            prev_hash = self._last_hash(conn)
            payload = {
                "timestamp": timestamp,
                "org_id": org_id,
                "user_id": user_id,
                "platform": platform,
                "event_type": event_type,
                "decision": decision.value,
                "categories": categories,
                "highest_severity": highest_severity,
                "text_preview": _redact_preview(raw_text),
            }
            entry_hash = self._compute_hash(prev_hash, payload)

            cur = conn.execute(
                """
                INSERT INTO audit_entries
                (timestamp, org_id, user_id, platform, event_type, decision,
                 categories, highest_severity, text_preview, prev_hash, entry_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp, org_id, user_id, platform, event_type, decision.value,
                    json.dumps(categories), highest_severity, payload["text_preview"],
                    prev_hash, entry_hash,
                ),
            )
            return AuditEntry(
                id=cur.lastrowid,
                timestamp=datetime.fromisoformat(timestamp),
                org_id=org_id, user_id=user_id, platform=platform,
                event_type=event_type, decision=decision,
                categories=categories, highest_severity=highest_severity,
                text_preview=payload["text_preview"],
                entry_hash=entry_hash, prev_hash=prev_hash,
            )

    def query(
        self,
        *,
        org_id: Optional[str] = None,
        user_id: Optional[str] = None,
        decision: Optional[Decision] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEntry]:
        clauses, params = [], []
        if org_id:
            clauses.append("org_id = ?"); params.append(org_id)
        if user_id:
            clauses.append("user_id = ?"); params.append(user_id)
        if decision:
            clauses.append("decision = ?"); params.append(decision.value)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM audit_entries {where} ORDER BY id DESC LIMIT ? OFFSET ?",
                (*params, limit, offset),
            ).fetchall()

        return [
            AuditEntry(
                id=r["id"], timestamp=datetime.fromisoformat(r["timestamp"]),
                org_id=r["org_id"], user_id=r["user_id"], platform=r["platform"],
                event_type=r["event_type"], decision=Decision(r["decision"]),
                categories=json.loads(r["categories"]), highest_severity=r["highest_severity"],
                text_preview=r["text_preview"], entry_hash=r["entry_hash"], prev_hash=r["prev_hash"],
            )
            for r in rows
        ]

    def verify_integrity(self) -> tuple[bool, Optional[int]]:
        """Recomputes the hash chain from scratch. Returns (is_valid, first_bad_row_id)."""
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM audit_entries ORDER BY id ASC").fetchall()

        expected_prev = _GENESIS_HASH
        for r in rows:
            payload = {
                "timestamp": r["timestamp"], "org_id": r["org_id"], "user_id": r["user_id"],
                "platform": r["platform"], "event_type": r["event_type"], "decision": r["decision"],
                "categories": json.loads(r["categories"]), "highest_severity": r["highest_severity"],
                "text_preview": r["text_preview"],
            }
            if r["prev_hash"] != expected_prev:
                return False, r["id"]
            recomputed = self._compute_hash(expected_prev, payload)
            if recomputed != r["entry_hash"]:
                return False, r["id"]
            expected_prev = r["entry_hash"]
        return True, None


_audit_log_instance: AuditLog | None = None


def get_audit_log() -> AuditLog:
    global _audit_log_instance
    if _audit_log_instance is None:
        _audit_log_instance = AuditLog()
    return _audit_log_instance
