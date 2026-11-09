from __future__ import annotations

import json
import os
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request

from .. import core


class PaymentError(core.MandateError):
    pass


class SandboxProvider:
    """Local sandbox provider with a strict idempotency key."""

    def __init__(self, db: str):
        self.db = db

    def _connect(self) -> sqlite3.Connection:
        os.makedirs(os.path.dirname(os.path.abspath(self.db)) or ".", exist_ok=True)
        con = sqlite3.connect(self.db, timeout=30)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")
        con.execute(
            "CREATE TABLE IF NOT EXISTS charges("
            " idem_key TEXT PRIMARY KEY, target TEXT, amount REAL, currency TEXT,"
            " reference TEXT, charge_id TEXT, status TEXT, ts REAL)")
        return con

    def lookup(self, idem_key):
        con = self._connect()
        try:
            row = con.execute("SELECT * FROM charges WHERE idem_key=?",
                              (str(idem_key),)).fetchone()
            return dict(row) if row else None
        finally:
            con.close()

    def charge(self, idem_key, target, amount, currency, reference):
        con = self._connect()
        try:
            con.execute("BEGIN IMMEDIATE")
            con.execute(
                "INSERT OR IGNORE INTO charges(idem_key,target,amount,currency,"
                "reference,charge_id,status,ts) VALUES(?,?,?,?,?,?,?,?)",
                (str(idem_key), str(target), float(amount), str(currency),
                 str(reference), "ch_" + core.sha256(str(idem_key))[:24],
                 "captured", time.time()))
            con.commit()
            row = con.execute("SELECT * FROM charges WHERE idem_key=?",
                              (str(idem_key),)).fetchone()
            return dict(row)
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()


class HttpProvider:
    """Generic HTTP payment provider. It must be idempotent on idem_key and
    expose a lookup by idempotency key."""

    def __init__(self, cfg: dict):
        self.url = str(cfg.get("url") or "")
        self.token = os.environ.get(str(cfg.get("token_env") or ""), "")

    def _headers(self) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        return headers

    def lookup(self, idem_key):
        request = urllib.request.Request(
            self.url.rstrip("/") + "/" + urllib.parse.quote(str(idem_key)),
            headers=self._headers(), method="GET")
        try:
            with urllib.request.urlopen(request, timeout=20) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise PaymentError("payment lookup http %s" % exc.code) from exc

    def charge(self, idem_key, target, amount, currency, reference):
        payload = json.dumps({
            "idempotency_key": str(idem_key), "target": str(target),
            "amount": float(amount), "currency": str(currency),
            "reference": str(reference),
        }).encode("utf-8")
        request = urllib.request.Request(
            self.url.rstrip("/"), data=payload, headers=self._headers(),
            method="POST")
        try:
            with urllib.request.urlopen(request, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise PaymentError("payment charge http %s" % exc.code) from exc


class PaymentAdapter:
    def __init__(self, cfg: dict | None = None):
        self.cfg = cfg or {}
        self.mode = str(self.cfg.get("provider") or "sandbox")
        if self.mode == "http":
            self.provider = HttpProvider(self.cfg)
        else:
            self.provider = SandboxProvider(
                str(self.cfg.get("db") or "payments.sqlite"))

    def _charge_result(self, idem_key, charge, recovered=False):
        status = str((charge or {}).get("status") or "unknown")
        return {"ok": status == "captured", "provider": self.mode,
                "idem_key": str(idem_key), "charge": charge,
                "recovered": recovered}

    def execute(self, intent: dict, idem_key: str) -> dict:
        effect = intent["effect"]
        amount = effect.get("amount") or {}
        target = str(effect.get("target") or "")
        value = float(amount.get("value") or 0)
        currency = str(amount.get("currency") or "BAM")
        reference = str((effect.get("params") or {}).get("ref") or "")
        existing = self.provider.lookup(idem_key)
        if existing:
            return self._charge_result(idem_key, existing, recovered=True)
        try:
            charge = self.provider.charge(idem_key, target, value, currency,
                                          reference)
        except Exception as exc:
            found = None
            try:
                found = self.provider.lookup(idem_key)
            except Exception:
                found = None
            if not found:
                raise PaymentError("payment provider error: %s"
                                   % str(exc)[:160]) from exc
            return self._charge_result(idem_key, found, recovered=True)
        return self._charge_result(idem_key, charge)

    def has_effect(self, idem_key) -> bool:
        return self.provider.lookup(idem_key) is not None

    def result_for(self, idem_key):
        row = self.provider.lookup(idem_key)
        return self._charge_result(idem_key, row, recovered=True) if row else None
