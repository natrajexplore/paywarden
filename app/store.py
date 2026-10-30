"""Persistence. PII (payee email/name) is encrypted at rest; lookups use a keyed blind index.
Free text (notes, AI summaries) is redacted before it is stored. SQLite runs with secure_delete and
an owner-only DB file (PCI DSS 3.2/7.2, GLBA 314.4(c)(3), GDPR Art. 32)."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path

from .config import settings
from .security import crypto, redact
from .security.audit import AuditLog


UPDATABLE = {"status", "approvals", "paypal_ref"}


class Store:
    def __init__(self, path: str):
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        self.conn.execute("PRAGMA secure_delete=ON")   # overwrite deleted content
        if path != ":memory:":
            self.conn.execute("PRAGMA journal_mode=WAL")
            if os.name == "posix":
                os.chmod(path, 0o600)
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS proposals (
                id TEXT PRIMARY KEY, ts REAL, agent_id TEXT, action TEXT,
                payee_bidx TEXT, payee_enc TEXT, payee_masked TEXT, name_enc TEXT,
                amount TEXT, currency TEXT, purpose TEXT, country TEXT, note TEXT,
                source_sha256 TEXT, verdict TEXT, risk INTEGER, decision TEXT,
                status TEXT, approvals TEXT, binding TEXT, paypal_ref TEXT, ai_summary TEXT)"""
        )
        self.conn.execute("CREATE TABLE IF NOT EXISTS webhook_seen (transmission_id TEXT PRIMARY KEY, ts REAL)")
        self.conn.commit()
        self.audit = AuditLog(self.conn, settings.audit_key)

    def payee_key(self, email: str) -> str:
        return crypto.blind_index(email, settings.bidx_key)

    def history(self, agent_id: str, exclude: str | None = None) -> list[dict]:
        rows = self.conn.execute(
            "SELECT ts, payee_bidx, amount, currency, status FROM proposals WHERE agent_id=? AND id<>?",
            (agent_id, exclude or ""),
        ).fetchall()
        return [{"ts": r[0], "payee": r[1], "amount": r[2], "currency": r[3], "status": r[4]} for r in rows]

    def create(self, p, decision: dict, binding_fn, ai_summary: str, paypal_ref: str | None = None) -> dict:
        pid = uuid.uuid4().hex[:16]
        aad = pid
        status = {"ALLOW": "APPROVED", "DENY": "DENIED"}.get(decision["verdict"], "PENDING")
        binding = binding_fn(pid, p.amount, p.currency, p.payee_email)
        lvl = settings.redaction_level
        with self.lock:
            self.conn.execute(
                "INSERT INTO proposals VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (pid, time.time(), p.agent_id, p.action,
                 self.payee_key(p.payee_email),
                 crypto.encrypt(p.payee_email, settings.enc_key, aad),
                 crypto.mask_email(p.payee_email),
                 crypto.encrypt(p.payee_name, settings.enc_key, aad),
                 p.amount, p.currency, p.purpose, p.country, redact.redact_text(p.note[:500], lvl),
                 hashlib.sha256(p.source_text.encode()).hexdigest(),
                 decision["verdict"], decision["risk_score"], json.dumps(decision),
                 status, "[]", binding, paypal_ref, redact.redact_text(ai_summary[:1000], lvl)),
            )
            self.conn.commit()
        return self.get(pid)

    def get(self, pid: str, reveal: bool = False) -> dict | None:
        r = self.conn.execute("SELECT * FROM proposals WHERE id=?", (pid,)).fetchone()
        if not r:
            return None
        cols = [d[0] for d in self.conn.execute("SELECT * FROM proposals LIMIT 0").description]
        row = dict(zip(cols, r))
        row["decision"] = json.loads(row["decision"])
        row["approvals"] = json.loads(row["approvals"])
        if reveal:
            row["payee_email"] = crypto.decrypt(row["payee_enc"], settings.enc_key, pid)
            row["payee_name"] = crypto.decrypt(row["name_enc"], settings.enc_key, pid)
        for k in ("payee_enc", "name_enc", "payee_bidx"):
            row.pop(k, None)
        return row

    def list(self, limit: int = 200) -> list[dict]:
        ids = [r[0] for r in self.conn.execute(
            "SELECT id FROM proposals ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()]
        return [self.get(i) for i in ids]

    def update(self, pid: str, **fields) -> None:
        if not fields or not set(fields) <= UPDATABLE:
            raise ValueError(f"not updatable: {sorted(set(fields) - UPDATABLE)}")
        if "approvals" in fields:
            fields["approvals"] = json.dumps(fields["approvals"])
        sets = ", ".join(f"{k}=?" for k in fields)
        with self.lock:
            # column names come only from the UPDATABLE allow-list above
            self.conn.execute(f"UPDATE proposals SET {sets} WHERE id=?", (*fields.values(), pid))  # nosec B608
            self.conn.commit()

    def webhook_replayed(self, transmission_id: str) -> bool:
        """Records a webhook transmission id; True if it was already seen (replay)."""
        with self.lock:
            cur = self.conn.execute("INSERT OR IGNORE INTO webhook_seen VALUES (?, ?)",
                                    (transmission_id, time.time()))
            self.conn.commit()
        return cur.rowcount == 0


store = Store(settings.db_path)
