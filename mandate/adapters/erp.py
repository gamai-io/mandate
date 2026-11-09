from __future__ import annotations

import math
import os
import sqlite3


class ErpChecker:
    """Read-only precondition check against master data (SQLite).

    Uses a named-parameter query. Binds :target, :amount and every effect
    param. Fails closed: no row or an amount outside tolerance blocks the
    effect before any grant is consumed.
    """

    def __init__(self, cfg: dict):
        self.db = str((cfg or {}).get("db") or "")
        self.checks = (cfg or {}).get("checks") or {}
        self.derive_checks = (cfg or {}).get("derive") or {}

    def _connect(self) -> sqlite3.Connection:
        path = os.path.abspath(self.db)
        return sqlite3.connect("file:%s?mode=ro" % path, uri=True)

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
        try:
            con = self._connect()
        except sqlite3.Error as exc:
            return {"ok": False, "reason": "erp_unavailable", "message": str(exc)[:160]}
        con.row_factory = sqlite3.Row
        try:
            row = con.execute(str(spec.get("query") or ""), binds).fetchone()
        except sqlite3.Error as exc:
            return {"ok": False, "reason": "erp_query_failed",
                    "message": str(exc)[:160]}
        finally:
            con.close()
        if row is None:
            return {"ok": False, "reason": "counterparty_not_found",
                    "target": effect.get("target")}
        field = spec.get("amount_field")
        if field and amount.get("value") is not None:
            try:
                expected = float(row[field])
                got = float(amount["value"])
            except (KeyError, TypeError, ValueError):
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
        try:
            con = self._connect()
        except sqlite3.Error as exc:
            return {"ok": False, "reason": "erp_unavailable",
                    "message": str(exc)[:160]}
        con.row_factory = sqlite3.Row
        try:
            row = con.execute(str(spec.get("query") or ""), binds).fetchone()
        except sqlite3.Error as exc:
            return {"ok": False, "reason": "erp_query_failed",
                    "message": str(exc)[:160]}
        finally:
            con.close()
        if row is None:
            return {"ok": False, "reason": "counterparty_not_found",
                    "target": effect.get("target")}
        fields = spec.get("fields") or {}

        def field(name):
            column = fields.get(name)
            return row[column] if column else None

        expected_counterparty = field("counterparty")
        expected_amount = field("amount")
        expected_currency = field("currency")
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
