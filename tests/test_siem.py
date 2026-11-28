"""SIEM_V1: what a SOC actually tests — schema, retry, and replay without duplicates.

A CEF string in the docs proves nothing. These tests run a real HTTP server and check the envelope
a Splunk HEC expects, that a 503 is retried instead of dropped, that a 4xx is not retried (it will
never succeed and retrying hides a configuration mistake), and that a second run does not resend
what the checkpoint already delivered unless `--resend` says so.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from mandate import core, siem

ROOT = pathlib.Path(__file__).resolve().parents[1]


class Collector(BaseHTTPRequestHandler):
    posts: list[dict] = []
    statuses: list[int] = []

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        Collector.posts.append({"auth": self.headers.get("Authorization", ""),
                                "body": json.loads(body.decode("utf-8")),
                                "raw": body.decode("utf-8")})
        status = Collector.statuses.pop(0) if Collector.statuses else 200
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"text":"ok"}')

    def log_message(self, *args):  # silence
        return


class ServerCase(unittest.TestCase):
    def setUp(self):
        Collector.posts = []
        Collector.statuses = []
        self.server = HTTPServer(("127.0.0.1", 0), Collector)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = "http://127.0.0.1:%d/services/collector" % self.server.server_port
        self.td = tempfile.TemporaryDirectory()
        self.dir = self.td.name
        self.ledger = os.path.join(self.dir, "ledger.jsonl")
        core.append_receipt(self.ledger, {"v": 1, "type": "receipt", "agent": "agent@x",
                                          "approver": "agent@x", "ts": 1,
                                          "render": {"fields": {"kind": "payment.send",
                                                                "target": "X"}},
                                          "commitment": "sha256:" + "0" * 64})

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.td.cleanup()


class Schema(unittest.TestCase):
    def finding(self):
        return {"rule": "self_approval", "severity": "high", "agent": "agent@x",
                "evidence": {"approver": "agent@x"},
                "dora": {"class": "major", "basis": "proposal only"}}

    def test_ecs_has_the_fields_a_saved_search_uses(self):
        event = siem.to_ecs(self.finding())
        self.assertEqual(event["event"]["kind"], "alert")
        self.assertEqual(event["event"]["action"], "self_approval")
        self.assertEqual(event["event"]["severity"], 73)
        self.assertEqual(event["rule"]["name"], "self_approval")
        self.assertEqual(event["user"]["name"], "agent@x")
        self.assertEqual(event["mandate"]["dora_class"], "major")

    def test_ocsf_is_a_detection_finding(self):
        event = siem.to_ocsf(self.finding())
        self.assertEqual(event["class_uid"], 2004)
        self.assertEqual(event["category_name"], "Findings")
        self.assertEqual(event["finding_info"]["uid"], siem.event_id(self.finding()))

    def test_the_event_id_is_stable_across_formats(self):
        finding = self.finding()
        self.assertEqual(siem.event_id(finding), siem.event_id(json.loads(json.dumps(finding))))
        self.assertIn(siem.event_id(finding), siem.render(finding, "ecs"))

    def test_all_formats_render_one_line(self):
        for fmt in ("ecs", "ocsf", "cef", "leef", "jsonl"):
            line = siem.render(self.finding(), fmt)
            self.assertTrue(line)
            self.assertNotIn("\n", line)


class Delivery(ServerCase):
    def test_the_envelope_is_a_hec_event(self):
        token = "tok-123"
        result = siem.deliver(self.ledger, "", "ecs", self.url, token)
        self.assertGreaterEqual(result["to_send"], 1, result)
        self.assertEqual(result["failed"], [], result)
        post = Collector.posts[0]
        self.assertEqual(post["auth"], "Splunk tok-123")
        self.assertEqual(post["body"]["sourcetype"], "mandate:alert")
        self.assertIn("index", post["body"])
        self.assertIsInstance(post["body"]["event"], list)
        self.assertEqual(len(post["body"]["event"][0]["event"]["id"]), 64)

    def test_a_503_is_retried(self):
        Collector.statuses = [503, 503]
        result = siem.send(['{"a":1}'], self.url, "", retries=3, backoff=0.01)
        self.assertEqual(result["sent"], 1, result)
        self.assertEqual(len(Collector.posts), 3)

    def test_a_400_is_not_retried(self):
        Collector.statuses = [400]
        result = siem.send(['{"a":1}'], self.url, "", retries=3, backoff=0.01)
        self.assertEqual(result["sent"], 0)
        self.assertEqual(len(Collector.posts), 1)
        self.assertEqual(result["failed"][0]["status"], 400)

    def test_the_checkpoint_prevents_duplicates(self):
        checkpoint = os.path.join(self.dir, "sent.ids")
        first = siem.deliver(self.ledger, "", "ecs", self.url, "", checkpoint=checkpoint)
        self.assertGreaterEqual(first["sent"], 1)
        second = siem.deliver(self.ledger, "", "ecs", self.url, "", checkpoint=checkpoint)
        self.assertEqual(second["sent"], 0)
        self.assertGreaterEqual(second["already_sent"], 1)

    def test_resend_backfills(self):
        checkpoint = os.path.join(self.dir, "sent.ids")
        siem.deliver(self.ledger, "", "ecs", self.url, "", checkpoint=checkpoint)
        again = siem.deliver(self.ledger, "", "ecs", self.url, "", checkpoint=checkpoint,
                             resend=True)
        self.assertGreaterEqual(again["sent"], 1)


class Cli(ServerCase):
    def test_cli_delivers_and_exits_zero(self):
        done = subprocess.run([sys.executable, "-m", "mandate", "siem", "--ledger", self.ledger,
                               "--format", "ocsf", "--url", self.url,
                               "--token-env", "MANDATE_NO_SUCH_TOKEN"],
                              cwd=str(ROOT), capture_output=True, text=True,
                              env={**os.environ, "MANDATE_NO_SUCH_TOKEN": "t"})
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        payload = json.loads(done.stdout)
        self.assertGreaterEqual(payload["sent"], 1)
        self.assertEqual(Collector.posts[0]["body"]["event"][0]["class_uid"], 2004)

    def test_cli_file_output_works_offline(self):
        out = os.path.join(self.dir, "events.ecs")
        done = subprocess.run([sys.executable, "-m", "mandate", "siem", "--ledger", self.ledger,
                               "--format", "ecs", "--out", out], cwd=str(ROOT),
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        lines = [line for line in pathlib.Path(out).read_text(encoding="utf-8").splitlines() if line]
        self.assertTrue(lines)
        self.assertIn("ecs.version", lines[0])


if __name__ == "__main__":
    unittest.main()
