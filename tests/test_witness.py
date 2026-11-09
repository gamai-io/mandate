import json
import os
import pathlib
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from mandate import core
from mandate import log as mlog
from mandate import witness as mwit


class WitnessTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = self.td.name
        self.ledger = os.path.join(self.dir, "ledger.jsonl")
        for i in range(3):
            core.append_receipt(self.ledger, {"v": 1, "type": "receipt", "i": i})
        self.key = os.path.join(self.dir, "log_key")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", self.key],
                       check=True, capture_output=True)
        self.signers = os.path.join(self.dir, "log_signers")
        pathlib.Path(self.signers).write_text(
            'log1 namespaces="mandate-log" %s\n' % pathlib.Path(
                self.key + ".pub").read_text(encoding="utf-8").strip(),
            encoding="utf-8")
        self.state = os.path.join(self.dir, "witness.json")
        self.leaves = mlog.leaves_from_ledger(self.ledger)
        self.log_id = mlog.log_id_from_key(self.key)

    def tearDown(self):
        self.td.cleanup()

    def _sth(self, size, root=None, log_id=None):
        payload = mlog.sth_payload(
            "log1", log_id or self.log_id, size,
            root or mlog.root_hex(self.leaves[:size]))
        return mlog.sign_sth(payload, self.key)

    def _proof(self, first, second):
        return mlog.consistency_proof(self.leaves, first, second)

    def test_first_pin_and_unchanged(self):
        out = mwit.accept(self._sth(2), None, self.signers, self.state)
        self.assertTrue(out["first"])
        self.assertEqual(mwit.load_state(self.state)["tree_size"], 2)
        again = mwit.accept(self._sth(2), None, self.signers, self.state)
        self.assertTrue(again["unchanged"])

    def test_growth_requires_valid_proof(self):
        mwit.accept(self._sth(2), None, self.signers, self.state)
        with self.assertRaises(mwit.WitnessError):
            mwit.accept(self._sth(3), None, self.signers, self.state)
        bad = self._proof(2, 3)
        bad["path"] = ["00" * 32] + bad["path"][1:]
        with self.assertRaises(mwit.WitnessError):
            mwit.accept(self._sth(3), bad, self.signers, self.state)
        out = mwit.accept(self._sth(3), self._proof(2, 3), self.signers,
                          self.state)
        self.assertTrue(out["advanced"])
        self.assertEqual(mwit.load_state(self.state)["tree_size"], 3)

    def test_rollback_rejected(self):
        mwit.accept(self._sth(3), None, self.signers, self.state)
        with self.assertRaises(mwit.WitnessError):
            mwit.accept(self._sth(2), None, self.signers, self.state)

    def test_split_view_rejected(self):
        mwit.accept(self._sth(2), None, self.signers, self.state)
        with self.assertRaises(mwit.WitnessError):
            mwit.accept(self._sth(2, root="00" * 32), None, self.signers,
                        self.state)

    def test_log_identity_mismatch_rejected(self):
        mwit.accept(self._sth(2), None, self.signers, self.state)
        with self.assertRaises(mwit.WitnessError):
            mwit.accept(self._sth(3, log_id="SHA256:other"), None,
                        self.signers, self.state)

    def test_invalid_signature_rejected(self):
        other = os.path.join(self.dir, "other")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", other],
                       check=True, capture_output=True)
        payload = mlog.sth_payload("log1", self.log_id, 2,
                                   mlog.root_hex(self.leaves[:2]))
        bad = mlog.sign_sth(payload, other)
        with self.assertRaises(mwit.WitnessError):
            mwit.accept(bad, None, self.signers, self.state)

    def test_dry_run_does_not_write(self):
        out = mwit.accept(self._sth(2), None, self.signers, self.state,
                          dry_run=True)
        self.assertTrue(out["first"])
        self.assertIsNone(mwit.load_state(self.state))

    def test_http_witness(self):
        token = "witness-token"
        server = mwit.make_server("127.0.0.1", 0, self.state, self.signers,
                                  token)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]
        base = "http://127.0.0.1:%d" % port

        def post(sth, proof=None, bearer=token):
            data = json.dumps({"sth": sth, "proof": proof}).encode()
            request = urllib.request.Request(
                base + "/sth", data=data,
                headers={"Content-Type": "application/json",
                         "Authorization": "Bearer " + bearer}, method="POST")
            try:
                with urllib.request.urlopen(request, timeout=5) as resp:
                    return resp.status, json.loads(resp.read().decode())
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read().decode())

        status, body = post(self._sth(1))
        self.assertEqual(status, 200, body)
        self.assertTrue(body["first"])
        status, body = post(self._sth(3), self._proof(1, 3))
        self.assertEqual(status, 200, body)
        self.assertTrue(body["advanced"])
        status, body = post(self._sth(2))
        self.assertEqual(status, 409, body)
        status, body = post(self._sth(3), bearer="wrong")
        self.assertEqual(status, 401, body)

        request = urllib.request.Request(base + "/state", headers={
            "Authorization": "Bearer " + token})
        with urllib.request.urlopen(request, timeout=5) as resp:
            state = json.loads(resp.read().decode())["state"]
        self.assertEqual(state["tree_size"], 3)


if __name__ == "__main__":
    unittest.main()
