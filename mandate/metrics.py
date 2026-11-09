from __future__ import annotations

import threading
import time


class Registry:
    """Tiny in-process Prometheus text exporter (stdlib only)."""

    def __init__(self, prefix: str = "mandate"):
        self.prefix = str(prefix)
        self._lock = threading.Lock()
        self._counters: dict = {}
        self._gauges: dict = {}
        self._start = time.time()

    @staticmethod
    def _key(name: str, labels: dict | None):
        return (str(name),
                tuple(sorted((str(k), str(v)) for k, v in (labels or {}).items())))

    def inc(self, name: str, amount: float = 1, **labels) -> None:
        with self._lock:
            key = self._key(name, labels)
            self._counters[key] = self._counters.get(key, 0) + amount

    def set(self, name: str, value, **labels) -> None:
        with self._lock:
            self._gauges[self._key(name, labels)] = value

    @staticmethod
    def _labels(labels) -> str:
        if not labels:
            return ""
        return "{" + ",".join('%s="%s"' % (k, v) for k, v in labels) + "}"

    def render(self) -> str:
        with self._lock:
            counters = dict(self._counters)
            gauges = dict(self._gauges)
        lines = []
        seen = set()
        for (name, labels), value in sorted(counters.items()):
            metric = "%s_%s_total" % (self.prefix, name)
            if metric not in seen:
                lines.append("# TYPE %s counter" % metric)
                seen.add(metric)
            lines.append("%s%s %s" % (metric, self._labels(labels), value))
        seen = set()
        for (name, labels), value in sorted(gauges.items()):
            metric = "%s_%s" % (self.prefix, name)
            if metric not in seen:
                lines.append("# TYPE %s gauge" % metric)
                seen.add(metric)
            lines.append("%s%s %s" % (metric, self._labels(labels), value))
        lines.append("# TYPE %s_uptime_seconds gauge" % self.prefix)
        lines.append("%s_uptime_seconds %d" % (self.prefix,
                                               int(time.time() - self._start)))
        return "\n".join(lines) + "\n"
