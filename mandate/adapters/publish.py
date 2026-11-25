"""Package publish as an effect the broker owns.

The registry token lives in the broker's environment, never in the agent's. The
broker sends one artefact, with an idempotency key, and asks the registry whether
that key already landed before sending again — the Mythos incident was an agent
publishing on its own authority, which this path removes.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .. import core
from ..net import require_http


class PublishError(core.MandateError):
    pass


class Publisher:
    def __init__(self, cfg: dict | None = None):
        self.cfg = cfg or {}
        self.url = require_http(str(self.cfg.get("url") or ""), "registry url")
        self.token = os.environ.get(str(self.cfg.get("token_env") or ""), "")

    def _headers(self, idem_key: str) -> dict:
        headers = {"Content-Type": "application/json",
                   "Idempotency-Key": str(idem_key)}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        return headers

    def lookup(self, idem_key: str) -> dict | None:
        request = urllib.request.Request(
            self.url.rstrip("/") + "/" + str(idem_key), headers=self._headers(idem_key),
            method="GET")
        try:
            with urllib.request.urlopen(request, timeout=20) as resp:
                return json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise PublishError("registry lookup http %s" % exc.code) from exc

    def execute(self, intent: dict, idem_key: str) -> dict:
        effect = intent.get("effect") or {}
        params = effect.get("params") or {}
        artefact = str(params.get("artefact") or "")
        if not artefact:
            raise PublishError("package.publish needs params.artefact")
        existing = self.lookup(idem_key)
        if existing:
            return {"ok": True, "idem_key": idem_key, "recovered": True,
                    "registry": existing}
        body = json.dumps({"artefact": artefact,
                           "target": str(effect.get("target") or ""),
                           "idempotency_key": str(idem_key)}).encode()
        request = urllib.request.Request(self.url.rstrip("/"), data=body,
                                         headers=self._headers(idem_key), method="POST")
        try:
            with urllib.request.urlopen(request, timeout=30) as resp:
                return {"ok": 200 <= resp.status < 300, "idem_key": idem_key,
                        "registry": json.loads(resp.read() or b"{}")}
        except urllib.error.HTTPError as exc:
            found = None
            try:
                found = self.lookup(idem_key)
            except PublishError:
                found = None
            if found:
                return {"ok": True, "idem_key": idem_key, "recovered": True,
                        "registry": found}
            raise PublishError("registry rejected the publish: http %s" % exc.code) from exc
