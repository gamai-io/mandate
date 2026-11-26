"""Differential and fuzz tests: the two verifiers must agree; parsers must not crash.

RT5 found the offline verifier accepting a key restricted to another namespace
while the package refused it. A differential test catches that class immediately.
"""
from __future__ import annotations

import json
import os
import pathlib
import random
import subprocess
import sys
import tempfile
import unittest

from mandate import core

ROOT = pathlib.Path(__file__).resolve().parents[1]
OFFLINE = ROOT / "spec" / "verify_offline.py"


def keypair(directory, name):
    path = os.path.join(directory, name)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", path],
                   check=True)
    return path


def signers_line(name, key, namespace="mandate"):
    return '%s namespaces="%s" %s\n' % (
        name, namespace, pathlib.Path(key + ".pub").read_text(
            encoding="utf-8").strip())


def intent(amount=10.0, target="Supplier", nonce="n-1"):
    return {"v": 1, "actor": {"agent": "agent@example", "session": "s1"},
            "effect": {"kind": "payment.send", "target": target,
                       "amount": {"value": amount, "currency": "BAM"}},
            "requested_by": "ops", "nonce": nonce,
            "provenance": [{"type": "data_ref", "source": "erp:vendor:1"}]}


class Differential(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.td.name)
        self.key = keypair(self.dir, "approver")
        self.signers = self.dir / "signers"
        self.signers.write_text(signers_line("approver", self.key),
                                encoding="utf-8")

    def tearDown(self):
        self.td.cleanup()

    def _offline(self, grant_path, intent_path, receipt_path, signers=None,
                 revoked=None):
        args = [sys.executable, str(OFFLINE), "--grant", str(grant_path),
                "--intent", str(intent_path), "--signers",
                str(signers or self.signers), "--receipt", str(receipt_path)]
        if revoked:
            args += ["--revoked", str(revoked)]
        done = subprocess.run(args, capture_output=True, text=True)
        return json.loads(done.stdout)

    def _case(self, *, tamper=False, namespace="mandate", revoked=False,
              signer_key=None):
        data = intent()
        proposal = core.propose(data)
        grant_core = core.build_grant_core(
            proposal["commitment"], "approver", ttl_s=600,
            render_hash=proposal["render_hash"], agent="agent@example",
            policy_fingerprint=core.policy_digest(core.load_policy()))
        grant = core.make_grant(grant_core, signer_key or self.key)
        receipt = core.redeem(data, grant, str(self.signers),
                              str(self.dir / "ledger.jsonl"),
                              policy=core.load_policy(), sign_key=self.key)
        if tamper:
            data = json.loads(json.dumps(data))
            data["effect"]["amount"]["value"] = 999.0
            receipt = json.loads(json.dumps(receipt))
            receipt["body"]["decision"] = "executed-but-forged"
        signers = self.dir / ("signers-" + namespace)
        signers.write_text(signers_line("approver", self.key, namespace),
                           encoding="utf-8")
        revoked_path = None
        if revoked:
            from mandate import sign
            blob = pathlib.Path(self.key + ".pub").read_text(
                encoding="utf-8").split()[1]
            revoked_path = self.dir / "revoked"
            revoked_path.write_text(sign.fingerprint(blob) + "\n",
                                    encoding="utf-8")
        files = {}
        for name, value in (("grant", grant), ("intent", data),
                            ("receipt", receipt)):
            files[name] = self.dir / (name + ".json")
            files[name].write_text(json.dumps(value), encoding="utf-8")
        offline = self._offline(files["grant"], files["intent"],
                                files["receipt"], signers, revoked_path)
        try:
            core.verify_authorization(data, grant, str(signers),
                                      policy=core.load_policy(),
                                      revoked_path=str(revoked_path or ""))
            granted = True
        except (core.MandateError, OSError, ValueError):
            granted = False
        package = granted and bool(core.verify_receipt(
            receipt, data, grant, str(self.signers),
            revoked_path=str(revoked_path or "")))
        return offline["ok"], package

    def test_the_two_verifiers_agree_on_valid_and_tampered_cases(self):
        cases = {"valid": {}, "tampered": {"tamper": True},
                 "wrong_namespace": {"namespace": "other"},
                 "revoked": {"revoked": True}}
        for name, kwargs in cases.items():
            with self.subTest(case=name):
                offline, package = self._case(**kwargs)
                self.assertEqual(offline, package,
                                 "%s: offline=%s package=%s" % (name, offline, package))


class KeyRotation(unittest.TestCase):
    def test_a_rotated_key_closes_the_old_grants_and_opens_new_ones(self):
        with tempfile.TemporaryDirectory() as td:
            directory = pathlib.Path(td)
            old = keypair(directory, "old")
            new = keypair(directory, "new")
            signers = directory / "signers"
            data = intent()
            proposal = core.propose(data)

            def grant_for(key):
                gc = core.build_grant_core(
                    proposal["commitment"], "approver", ttl_s=600,
                    render_hash=proposal["render_hash"], agent="agent@example",
                    policy_fingerprint=core.policy_digest(core.load_policy()))
                return core.make_grant(gc, key)

            signers.write_text(signers_line("approver", old), encoding="utf-8")
            old_grant = grant_for(old)
            self.assertTrue(core.verify_grant(old_grant, str(signers)))

            signers.write_text(signers_line("approver", new), encoding="utf-8")
            self.assertFalse(core.verify_grant(old_grant, str(signers)))
            new_grant = grant_for(new)
            self.assertTrue(core.verify_grant(new_grant, str(signers)))
            entry = core.redeem(data, new_grant, str(signers),
                                str(directory / "l.jsonl"), policy=core.load_policy())
            self.assertEqual(entry["body"]["decision"], "executed")


class ParsersDoNotCrash(unittest.TestCase):
    def test_random_intent_objects_do_not_crash(self):
        rng = random.Random(99)
        values = [None, 0, -1, 1.5, "", "x", [], {}, True, {"a": [None]}]
        for _ in range(300):
            obj = {key: rng.choice(values) for key in
                   ("v", "actor", "effect", "requested_by", "nonce",
                    "provenance")}
            try:
                core.normalize_intent(obj)
            except core.MandateError:
                pass
            except (KeyError, TypeError, ValueError):
                pass

    def test_random_policy_objects_do_not_crash_lint(self):
        from mandate import policy_tools
        rng = random.Random(7)
        for _ in range(300):
            policy = {key: rng.choice([None, {}, [], "x", 1, True, {"a": 1}])
                      for key in ("version", "default", "effects", "limits")}
            result = policy_tools.lint(policy)
            self.assertIn("ok", result)


if __name__ == "__main__":
    unittest.main()
