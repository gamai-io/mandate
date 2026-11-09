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
