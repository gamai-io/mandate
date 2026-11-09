from __future__ import annotations

import math
import os
import re
import sqlite3


class ErpChecker:
    """Read-only precondition and derivation checks against master data.

    driver=sqlite (default): opens the database with mode=ro.
    driver=mssql: optional, requires ``pyodbc`` (``pip install gama-mandate[mssql]``);
    only SELECT/WITH queries are accepted.
    """

    def __init__(self, cfg: dict):
        cfg = cfg or {}
        self.db = str(cfg.get("db") or "")
        self.driver = str(cfg.get("driver") or "sqlite").lower()
        self.dsn = str(cfg.get("dsn") or "")
        self.user_env = str(cfg.get("user_env") or "")
        self.password_env = str(cfg.get("password_env") or "")
        self.checks = cfg.get("checks") or {}
        self.derive_checks = cfg.get("derive") or {}

    @staticmethod
    def _validate(query: str) -> str:
        text = str(query or "").strip()
        upper = text.upper()
        if not upper.startswith(("SELECT", "WITH")):
            raise ValueError("only SELECT/WITH queries are allowed")
        return text

    def _connect(self):
        if self.driver == "mssql":
            try:
                import pyodbc
            except ImportError as exc:
                raise RuntimeError(
                    "pyodbc not installed; pip install gama-mandate[mssql]") from exc
            user = os.environ.get(self.user_env, "") if self.user_env else ""
            password = os.environ.get(self.password_env, "") if self.password_env else ""
            return pyodbc.connect(self.dsn, user=user, password=password,
                                  timeout=10, autocommit=False)
        con = sqlite3.connect("file:%s?mode=ro" % os.path.abspath(self.db),
                              uri=True)
        con.row_factory = sqlite3.Row
        return con

    def _execute(self, con, query: str, binds: dict):
        if self.driver == "mssql":
            names = re.findall(r":([A-Za-z_][A-Za-z0-9_]*)", query)
            positional = re.sub(r":[A-Za-z_][A-Za-z0-9_]*", "?", query)
            return con.execute(positional, [binds.get(n) for n in names])
        return con.execute(query, binds)

    @staticmethod
    def _get(row, field: str):
        try:
            return row[field]
        except (TypeError, IndexError, KeyError):
            return getattr(row, field, None)

    def _fetch(self, spec: dict, binds: dict):
        try:
            query = self._validate(spec.get("query"))
        except ValueError:
            return None, "invalid_query"
        try:
            con = self._connect()
        except Exception:
            return None, "erp_unavailable"
        try:
            try:
                row = self._execute(con, query, binds).fetchone()
            except Exception:
                return None, "erp_query_failed"
            return row, None
        finally:
            try:
                if self.driver == "mssql":
                    con.rollback()
                con.close()
            except Exception:
                pass

    def check(self, intent: dict) -> dict:
        kind = str((intent.get("effect") or {}).get("kind") or "")
        spec = self.checks.get(kind)
        if not isinstance(spec, dict):
            return {"ok": True, "skipped": True}
        effect = intent.get("effect") or {}
        amount = effect.get("amount")
        params = effect.get("params") or {}
        if amount is not None and not isinstance(amount, dict):
            return {"ok": False, "reason": "invalid_amount"}
        if not isinstance(params, dict):
            return {"ok": False, "reason": "invalid_params"}
        amount = amount or {}
        try:
            value = (float(amount.get("value"))
                     if amount.get("value") is not None else 0.0)
        except (TypeError, ValueError):
            return {"ok": False, "reason": "invalid_amount"}
        if not math.isfinite(value):
            return {"ok": False, "reason": "invalid_amount"}
        binds = {"target": effect.get("target"), "amount": value}
        for key in (spec.get("bind_params") or []):
            binds[str(key)] = params.get(key)
        row, error = self._fetch(spec, binds)
        if error:
            return {"ok": False, "reason": error}
        if row is None:
            return {"ok": False, "reason": "counterparty_not_found",
                    "target": effect.get("target")}
        field = spec.get("amount_field")
        if field and amount.get("value") is not None:
            try:
                expected = float(self._get(row, field))
                got = float(amount["value"])
            except (TypeError, ValueError):
                return {"ok": False, "reason": "erp_amount_unreadable"}
            if not math.isfinite(expected) or not math.isfinite(got):
                return {"ok": False, "reason": "invalid_amount"}
            tolerance = float(spec.get("tolerance_pct") or 0.0) / 100.0
            if expected == 0:
                if got != 0:
                    return {"ok": False, "reason": "amount_mismatch",
                            "expected": expected, "got": got}
            elif abs(got - expected) / abs(expected) > tolerance:
                return {"ok": False, "reason": "amount_mismatch",
                        "expected": expected, "got": got}
        return {"ok": True}

    def derive_expected(self, intent: dict) -> dict:
        kind = str((intent.get("effect") or {}).get("kind") or "")
        spec = self.derive_checks.get(kind)
        if not isinstance(spec, dict):
            return {"ok": True, "skipped": True}
        effect = intent.get("effect") or {}
        params = effect.get("params") or {}
        amount = effect.get("amount")
        if amount is not None and not isinstance(amount, dict):
            return {"ok": False, "reason": "invalid_amount"}
        amount = amount or {}
        try:
            got = (float(amount.get("value"))
                   if amount.get("value") is not None else None)
        except (TypeError, ValueError):
            return {"ok": False, "reason": "invalid_amount"}
        if got is not None and not math.isfinite(got):
            return {"ok": False, "reason": "invalid_amount"}
        binds = {"target": effect.get("target"),
                 "amount": got if got is not None else 0.0}
        for key in (spec.get("bind_params") or []):
            binds[str(key)] = params.get(key)
        row, error = self._fetch(spec, binds)
        if error:
            return {"ok": False, "reason": error}
        if row is None:
            return {"ok": False, "reason": "counterparty_not_found",
                    "target": effect.get("target")}
        fields = spec.get("fields") or {}
        expected_counterparty = self._get(row, fields.get("counterparty", "")) \
            if fields.get("counterparty") else None
        expected_amount = self._get(row, fields.get("amount", "")) \
            if fields.get("amount") else None
        expected_currency = self._get(row, fields.get("currency", "")) \
            if fields.get("currency") else None
        if expected_counterparty is not None and \
                str(effect.get("target")) != str(expected_counterparty):
            return {"ok": False, "reason": "derivation_mismatch",
                    "field": "counterparty", "expected": expected_counterparty}
        if expected_amount is not None and got is not None:
            try:
                expected = float(expected_amount)
            except (TypeError, ValueError):
                return {"ok": False, "reason": "erp_amount_unreadable"}
            tolerance = float(spec.get("tolerance_pct") or 0.0) / 100.0
            if not math.isfinite(expected) or \
                    (expected == 0 and got != 0) or \
                    (expected != 0 and abs(got - expected) / abs(expected) > tolerance):
                return {"ok": False, "reason": "derivation_mismatch",
                        "field": "amount", "expected": expected, "got": got}
        if expected_currency is not None and \
                str(amount.get("currency") or "BAM") != str(expected_currency):
            return {"ok": False, "reason": "derivation_mismatch",
                    "field": "currency", "expected": expected_currency}
        return {"ok": True, "expected": {
            "counterparty": expected_counterparty,
            "amount": expected_amount,
            "currency": expected_currency,
        }}
