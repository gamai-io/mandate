from __future__ import annotations

import json
import urllib.error
import urllib.request


class NotifierError(Exception):
    pass


class TelegramNotifier:
    """Advisory notification only. It never carries an approval token or link;
    the decision still happens on the approver host's terminal."""

    def __init__(self, token: str, chat_id: str, timeout: int = 10):
        self.token = str(token or "")
        self.chat_id = str(chat_id or "")
        self.timeout = int(timeout)

    def send(self, text: str) -> bool:
        if not self.token or not self.chat_id:
            return False
        payload = json.dumps({
            "chat_id": self.chat_id,
            "text": str(text)[:3500],
            "disable_web_page_preview": True,
        }).encode("utf-8")
        request = urllib.request.Request(
            "https://api.telegram.org/bot%s/sendMessage" % self.token,
            data=payload, headers={"Content-Type": "application/json"},
            method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as resp:
                return 200 <= resp.status < 300
        except (OSError, urllib.error.URLError) as exc:
            raise NotifierError("telegram send failed: %s"
                                % str(exc)[:120]) from exc
