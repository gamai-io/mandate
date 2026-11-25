"""SQL write as an effect the broker owns.

The database credential never reaches the agent: the broker holds the connection
and applies one statement that the grant authorised. Only INSERT and UPDATE are
accepted (no DDL, no DELETE), parameters are bound, and the row count goes into
the result so the receipt says what changed.
"""
from __future__ import annotations

import os
import re
import sqlite3

from .. import core

ALLOWED = ("insert", "update")
_BLOCKED = re.compile(r";\s*\S")           # one statement, no stacking


class SqlWriteError(core.MandateError):
    pass


class SqlWriter:
    def __init__(self, cfg: dict | None = None):
        self.cfg = cfg or {}
        self.db = str(self.cfg.get("db") or "effects.sqlite")
        self.audit_table = str(self.cfg.get("audit_table") or "applied_effects")

    def _connect(self) -> sqlite3.Connection:
        directory = os.path.dirname(os.path.abspath(self.db))
        if directory:
            os.makedirs(directory, exist_ok=True)
        con = sqlite3.connect(self.db, timeout=30)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("CREATE TABLE IF NOT EXISTS %s("
                    " idem_key TEXT PRIMARY KEY, sql TEXT, rows_changed INT, ts REAL)"
                    % self.audit_table)
        return con

    def lookup(self, idem_key: str) -> dict | None:
        con = self._connect()
        try:
            row = con.execute("SELECT * FROM %s WHERE idem_key=?"
                              % self.audit_table, (str(idem_key),)).fetchone()
            return {"idem_key": row[0], "rows_changed": row[2]} if row else None
        finally:
            con.close()

    def execute(self, intent: dict, idem_key: str) -> dict:
        params = (intent.get("effect") or {}).get("params") or {}
        statement = str(params.get("sql") or "").strip()
        if not statement:
            raise SqlWriteError("sql.write needs params.sql")
        keyword = statement.split(None, 1)[0].lower()
        if keyword not in ALLOWED:
            raise SqlWriteError("only INSERT and UPDATE are allowed, got %r" % keyword)
        if _BLOCKED.search(statement):
            raise SqlWriteError("one statement per effect")
        bound = params.get("args") or {}
        if not isinstance(bound, dict):
            raise SqlWriteError("params.args must be an object")
        existing = self.lookup(idem_key)
        if existing:
            return {"ok": True, "idem_key": idem_key, "recovered": True,
                    "rows_changed": existing["rows_changed"]}
        con = self._connect()
        try:
            con.execute("BEGIN IMMEDIATE")
            cursor = con.execute(statement, bound)
            changed = cursor.rowcount if cursor.rowcount and cursor.rowcount > 0 else 0
            con.execute("INSERT INTO %s(idem_key, sql, rows_changed, ts)"
                        " VALUES(?,?,?,strftime('%%s','now'))" % self.audit_table,
                        (str(idem_key), statement[:500], changed))
            con.commit()
        except Exception as exc:
            con.rollback()
            raise SqlWriteError("sql write failed: %s" % str(exc)[:160]) from exc
        finally:
            con.close()
        return {"ok": True, "idem_key": idem_key, "rows_changed": changed}
