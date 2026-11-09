from __future__ import annotations

import os
import smtplib
import time
from email.message import EmailMessage


class SmtpSender:
    """Effect handler for message.send.

    ``mode=dry_run`` (default) writes an .eml file to the outbox; ``mode=live``
    sends through SMTP. The SMTP password is read from the environment named in
    ``password_env`` and is never logged or returned.
    """

    def __init__(self, cfg: dict):
        self.cfg = cfg or {}

    def _message(self, intent: dict) -> EmailMessage:
        effect = intent.get("effect") or {}
        params = effect.get("params") or {}
        msg = EmailMessage()
        msg["From"] = str(self.cfg.get("from") or "noreply@localhost")
        msg["To"] = str(effect.get("target") or "")
        msg["Subject"] = str(params.get("subject") or "GAMA mandate")
        msg.set_content(str(params.get("body") or "Authorized message."))
        return msg

    def send(self, intent: dict) -> dict:
        msg = self._message(intent)
        if str(self.cfg.get("mode") or "dry_run") != "live":
            outbox = str(self.cfg.get("outbox") or "outbox")
            os.makedirs(outbox, exist_ok=True)
            path = os.path.join(outbox, "msg-%d-%s.eml" % (
                int(time.time() * 1000), str(intent.get("nonce") or "x")[:12]))
            with open(path, "wb") as fh:
                fh.write(bytes(msg))
            return {"ok": True, "dry_run": True, "path": path,
                    "to": str(msg["To"])}
        host = str(self.cfg.get("host") or "")
        if not host:
            return {"ok": False, "error": "smtp host not configured"}
        port = int(self.cfg.get("port") or 587)
        with smtplib.SMTP(host, port, timeout=20) as client:
            client.ehlo()
            if self.cfg.get("starttls", True):
                client.starttls()
                client.ehlo()
            user = str(self.cfg.get("user") or "")
            if user:
                password = os.environ.get(
                    str(self.cfg.get("password_env") or "MANDATE_SMTP_PASSWORD"), "")
                client.login(user, password)
            client.send_message(msg)
        return {"ok": True, "dry_run": False, "to": str(msg["To"])}
