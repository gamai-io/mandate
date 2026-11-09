from __future__ import annotations

import os
import sqlite3
import threading
import time

STATES = ("intent", "executing", "executed", "receipted", "failed", "abandoned")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS effect_journal(
  idem_key TEXT PRIMARY KEY,
  intent_hash TEXT NOT NULL,
  kind TEXT NOT NULL,
  payload TEXT NOT NULL,
  grant_core TEXT NOT NULL,
  not_after REAL,
  state TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  owner TEXT,
  lease_until REAL,
  result_json TEXT,
  external_ref TEXT,
  receipt_entry TEXT,
  result_entry TEXT,
  created_ts REAL NOT NULL,
  executed_ts REAL,
  receipted_ts REAL,
  last_error TEXT
);
CREATE INDEX IF NOT EXISTS ix_journal_state ON effect_journal(state, lease_until);
"""


class Journal:
    def __init__(self, path: str, lease_s: float = 60):
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        self.path = path
        self.lease_s = float(lease_s)
        self._lock = threading.Lock()
        self._con = sqlite3.connect(path, timeout=30, check_same_thread=False)
        self._con.row_factory = sqlite3.Row
        self._con.execute("PRAGMA journal_mode=WAL")
        self._con.executescript(_SCHEMA)
        self._con.commit()

    def _row(self, nonce):
        return self._con.execute(
            "SELECT * FROM effect_journal WHERE idem_key=?",
            (str(nonce),)).fetchone()

    def get(self, nonce) -> dict | None:
        with self._lock:
            row = self._row(nonce)
            return dict(row) if row else None

    def begin(self, nonce, intent_hash, kind, payload, grant_core,
              not_after) -> dict:
        with self._lock:
            row = self._row(nonce)
            if row is None:
                self._con.execute(
                    "INSERT INTO effect_journal(idem_key,intent_hash,kind,payload,"
                    "grant_core,not_after,state,created_ts) VALUES(?,?,?,?,?,?,?,?)",
                    (str(nonce), intent_hash, kind, payload, grant_core,
                     float(not_after or 0), "intent", time.time()))
                self._con.commit()
                return {"status": "new"}
            row = dict(row)
            if row["intent_hash"] != intent_hash:
                return {"status": "payload_mismatch", "row": row}
            if row["state"] in ("executed", "receipted"):
                return {"status": "done", "row": row}
            if row["state"] in ("failed", "abandoned"):
                return {"status": "terminal", "row": row}
            if row["state"] == "executing" and \
                    float(row["lease_until"] or 0) > time.time():
                return {"status": "busy", "row": row}
            return {"status": "retry", "row": row}

    def claim(self, nonce, owner: str) -> bool:
        with self._lock:
            now = time.time()
            cur = self._con.execute(
                "UPDATE effect_journal SET state='executing', owner=?,"
                " lease_until=?, attempts=attempts+1 WHERE idem_key=?"
                " AND (state='intent' OR (state='executing' AND lease_until<=?))",
                (str(owner), now + self.lease_s, str(nonce), now))
            self._con.commit()
            return cur.rowcount == 1

    def mark_executed(self, nonce, result_json, external_ref=None) -> bool:
        with self._lock:
            cur = self._con.execute(
                "UPDATE effect_journal SET state='executed', result_json=?,"
                " external_ref=?, executed_ts=? WHERE idem_key=? AND state='executing'",
                (result_json, external_ref, time.time(), str(nonce)))
            self._con.commit()
            return cur.rowcount == 1

    def mark_receipted(self, nonce, receipt_entry, result_entry) -> bool:
        with self._lock:
            cur = self._con.execute(
                "UPDATE effect_journal SET state='receipted', receipt_entry=?,"
                " result_entry=?, receipted_ts=? WHERE idem_key=?"
                " AND state IN ('executed','executing')",
                (receipt_entry, result_entry, time.time(), str(nonce)))
            self._con.commit()
            return cur.rowcount == 1

    def mark_failed(self, nonce, error) -> None:
        with self._lock:
            self._con.execute(
                "UPDATE effect_journal SET state='failed', last_error=?"
                " WHERE idem_key=? AND state IN ('intent','executing')",
                (str(error)[:300], str(nonce)))
            self._con.commit()

    def mark_abandoned(self, nonce, note) -> None:
        with self._lock:
            self._con.execute(
                "UPDATE effect_journal SET state='abandoned', last_error=?"
                " WHERE idem_key=? AND state IN ('intent','executing')",
                (str(note)[:300], str(nonce)))
            self._con.commit()

    def recoverable(self) -> list[dict]:
        now = time.time()
        with self._lock:
            rows = self._con.execute(
                "SELECT * FROM effect_journal WHERE"
                " (state='executing' AND lease_until<=?)"
                " OR (state='executed' AND receipt_entry IS NULL)"
                " OR (state='intent' AND not_after>0 AND not_after<=?)",
                (now, now)).fetchall()
            return [dict(row) for row in rows]

    def counts(self) -> dict:
        with self._lock:
            rows = self._con.execute(
                "SELECT state, COUNT(*) AS n FROM effect_journal GROUP BY state"
            ).fetchall()
            return {row["state"]: row["n"] for row in rows}
