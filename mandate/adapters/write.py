from __future__ import annotations

import glob
import json
import os
import re
import sqlite3
import time

from .. import core


class WriteAdapter:
    """Idempotent effect writer.

    mode=file (default) writes one file per nonce. mode=sqlite runs a trusted
    configured statement together with an idempotency insert in one SQLite
    transaction, so a committed effect and its idempotency key are atomic.
    """

    def __init__(self, cfg: dict | None = None):
        self.cfg = cfg or {}
        self.mode = str(self.cfg.get("mode") or "file")
        self.effects_dir = str(self.cfg.get("effects_dir") or "effects")

    @staticmethod
    def _safe(nonce) -> str:
        return re.sub(r"[^A-Za-z0-9._-]", "_", str(nonce))[:120]

    def execute(self, intent: dict, idem_key: str | None = None) -> dict:
        key = str(idem_key or intent.get("nonce") or "")
        if self.mode == "sqlite":
            return self._sqlite(intent, key)
        return self._file(intent, key)

    def has_effect(self, nonce) -> bool:
        if self.mode == "sqlite":
            return self._sql_has(nonce)
        return bool(glob.glob(os.path.join(
            self.effects_dir, "*-%s.json" % self._safe(nonce))))

    def result_for(self, nonce):
        if self.mode == "sqlite":
            return self._sql_result(nonce)
        files = glob.glob(os.path.join(
            self.effects_dir, "*-%s.json" % self._safe(nonce)))
        if not files:
            return None
        try:
            with open(files[0], encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None

    def _file(self, intent: dict, idem_key: str) -> dict:
        os.makedirs(self.effects_dir, exist_ok=True)
        kind = str(intent["effect"]["kind"]).replace(".", "_")
        path = os.path.join(self.effects_dir,
                            "%s-%s.json" % (kind, self._safe(idem_key)))
        record = {"effect": intent["effect"], "nonce": idem_key,
                  "intent_nonce": intent.get("nonce"),
                  "actor": intent.get("actor"),
                  "requested_by": intent.get("requested_by"),
                  "ts": int(time.time())}
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(core.jcs(record) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        return {"ok": True, "mode": "file", "path": path, "idem_key": idem_key}

    def _connect(self) -> sqlite3.Connection:
        path = os.path.abspath(str(self.cfg.get("db") or ""))
        con = sqlite3.connect(path, timeout=30)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")
        con.execute(
            "CREATE TABLE IF NOT EXISTS mandate_effects("
            " idem_key TEXT PRIMARY KEY, kind TEXT, payload_hash TEXT,"
            " result TEXT, ts REAL)")
        return con

    def _bind(self, intent: dict, idem_key: str) -> dict:
        effect = intent["effect"]
        amount = effect.get("amount") or {}
        binds = {"nonce": str(idem_key),
                 "target": effect.get("target"),
                 "amount": amount.get("value"),
                 "currency": amount.get("currency")}
        for key, value in (effect.get("params") or {}).items():
            binds[str(key)] = value
        return binds

    def _sqlite(self, intent: dict, idem_key: str) -> dict:
        nonce = str(idem_key)
        kind = str(intent["effect"]["kind"])
        payload_hash = core.sha256(core.jcs(intent))
        con = self._connect()
        try:
            con.execute("BEGIN IMMEDIATE")
            cur = con.execute(
                "INSERT OR IGNORE INTO mandate_effects(idem_key,kind,payload_hash,"
                "result,ts) VALUES(?,?,?,?,?)",
                (nonce, kind, payload_hash, None, time.time()))
            if cur.rowcount == 0:
                row = con.execute(
                    "SELECT result FROM mandate_effects WHERE idem_key=?",
                    (nonce,)).fetchone()
                con.rollback()
                if row and row["result"]:
                    return json.loads(row["result"])
                return {"ok": True, "recovered": True, "idem_key": nonce}
            statement = str(self.cfg.get("statement") or "").strip()
            if statement:
                con.execute(statement, self._bind(intent, nonce))
            result = {"ok": True, "mode": "sqlite", "idem_key": nonce}
            con.execute("UPDATE mandate_effects SET result=? WHERE idem_key=?",
                        (core.jcs(result), nonce))
            con.commit()
            return result
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

    def _sql_has(self, nonce) -> bool:
        con = self._connect()
        try:
            return con.execute(
                "SELECT 1 FROM mandate_effects WHERE idem_key=?",
                (str(nonce),)).fetchone() is not None
        finally:
            con.close()

    def _sql_result(self, nonce):
        con = self._connect()
        try:
            row = con.execute(
                "SELECT result FROM mandate_effects WHERE idem_key=?",
                (str(nonce),)).fetchone()
            return json.loads(row["result"]) if row and row["result"] else None
        finally:
            con.close()
