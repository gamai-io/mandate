"""One place that refuses a URL we would not fetch.

Every outbound call in this package takes a URL from configuration. `urlopen`
accepts more schemes than we intend (`file:`, `ftp:`, custom ones), so a typo or a
tampered config could turn a payment call into a local file read. The check is
deliberately narrow: http and https, with a host, nothing else.
"""
from __future__ import annotations

import urllib.parse

from .core import MandateError

ALLOWED = ("http", "https")


def require_http(url: str, what: str = "url") -> str:
    parts = urllib.parse.urlsplit(str(url or ""))
    if parts.scheme not in ALLOWED:
        raise MandateError("%s must be http or https, got %r" % (what, parts.scheme or ""))
    if not parts.hostname:
        raise MandateError("%s has no host" % what)
    return str(url)
