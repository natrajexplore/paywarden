"""Tamper-evident, append-only audit log.

Each record carries the SHA-256 hash of the previous record and an HMAC-SHA256 signature over
its own canonical JSON. Editing, deleting or re-ordering any past record breaks verification.

Controls mapped: PCI DSS v4.0.1 Req 10 (log & monitor all access, protect audit trails 10.3),
SOX ITGC change/approval evidence, NYDFS 500.06 (audit trail), FFIEC IT Handbook (audit logging),
EU DORA ICT risk management (Arts. 9–10), ISO/IEC 27001:2022 A.8.15.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
import time
from typing import Any

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, conn: sqlite3.Connection, key: bytes):
        self.conn = conn
        self.key = key
        self._lock = threading.Lock()
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS audit (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                hash TEXT NOT NULL,
                sig TEXT NOT NULL)"""
        )
        self.conn.commit()

    @staticmethod
    def _canon(ts: float, actor: str, action: str, details: dict, prev_hash: str) -> bytes:
        return json.dumps(
            {"ts": round(ts, 6), "actor": actor, "action": action, "details": details, "prev": prev_hash},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

    def append(self, actor: str, action: str, details: dict[str, Any]) -> dict:
        with self._lock:
            row = self.conn.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            prev = row[0] if row else GENESIS
            ts = time.time()
            body = self._canon(ts, actor, action, details, prev)
            h = hashlib.sha256(body).hexdigest()
            sig = hmac.new(self.key, body, hashlib.sha256).hexdigest()
            cur = self.conn.execute(
                "INSERT INTO audit (ts, actor, action, details, prev_hash, hash, sig) VALUES (?,?,?,?,?,?,?)",
                (round(ts, 6), actor, action, json.dumps(details, sort_keys=True), prev, h, sig),
            )
            self.conn.commit()
            return {"seq": cur.lastrowid, "hash": h}

    def entries(self, limit: int = 200) -> list[dict]:
        rows = self.conn.execute(
            "SELECT seq, ts, actor, action, details, prev_hash, hash FROM audit ORDER BY seq DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            {"seq": r[0], "ts": r[1], "actor": r[2], "action": r[3], "details": json.loads(r[4]),
             "prev_hash": r[5], "hash": r[6]}
            for r in rows
        ]

    def verify(self) -> dict:
        prev = GENESIS
        count = 0
        for seq, ts, actor, action, details, prev_hash, h, sig in self.conn.execute(
            "SELECT seq, ts, actor, action, details, prev_hash, hash, sig FROM audit ORDER BY seq ASC"
        ):
            body = self._canon(ts, actor, action, json.loads(details), prev_hash)
            if prev_hash != prev:
                return {"valid": False, "broken_at": seq, "reason": "chain link mismatch", "checked": count}
            if hashlib.sha256(body).hexdigest() != h:
                return {"valid": False, "broken_at": seq, "reason": "record content altered", "checked": count}
            if not hmac.compare_digest(hmac.new(self.key, body, hashlib.sha256).hexdigest(), sig):
                return {"valid": False, "broken_at": seq, "reason": "signature invalid", "checked": count}
            prev = h
            count += 1
        return {"valid": True, "checked": count, "head": prev}
