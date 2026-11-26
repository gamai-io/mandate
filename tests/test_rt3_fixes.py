"""Regressions from the third adversarial review (RT3) of mandate.

Three of these are about claims rather than crypto: the approver daemon did not
bind the policy, an `--observe` receipt verified exactly like an executed one,
and the claims gate could not see the CLAIMS.md rows it generated.
"""
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from mandate import approver as mapprover
from mandate import core

ROOT = pathlib.Path(__file__).resolve().parents[1]


def intent_factory():
    return {"v": 1, "actor": {"agent": "agent@example", "session": "s1"},
            "effect": {"kind": "payment.send", "target": "Example Supplier",
                       "amount": {"value": 10.0, "currency": "BAM"}},
            "requested_by": "ops", "nonce": "n-1",
            "provenance": [{"type": "data_ref", "source": "erp:vendor:1"}]}


class ApproverBindsThePolicy(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = self.td.name
        self.key = os.path.join(self.dir, "id_ed25519")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f",
                        self.key], check=True)
        self.signers = os.path.join(self.dir, "signers")
        pathlib.Path(self.signers).write_text(
            'approver namespaces="mandate" %s\n' % pathlib.Path(
                self.key + ".pub").read_text(encoding="utf-8").strip(),
            encoding="utf-8")
        self.ledger = os.path.join(self.dir, "ledger.jsonl")
        self.policy = os.path.join(self.dir, "policy.json")
        pathlib.Path(self.policy).write_text(json.dumps(core.load_policy()),
                                             encoding="utf-8")

    def tearDown(self):
        self.td.cleanup()

    def test_the_grant_carries_a_policy_digest(self):
        approver = mapprover.Approver(self.key, "approver",
                                      audience_default="local-broker",
                                      confirm=lambda *a: True,
                                      policy_path=self.policy)
        grant = approver.request(intent_factory())["grant"]
        self.assertTrue(grant["grant"]["policy_digest"],
                        "approver daemon minted a grant with no policy binding")

    def test_a_changed_policy_invalidates_the_grant(self):
        approver = mapprover.Approver(self.key, "approver",
                                      audience_default="local-broker",
                                      confirm=lambda *a: True,
                                      policy_path=self.policy)
        grant = approver.request(intent_factory())["grant"]
        changed = json.loads(pathlib.Path(self.policy).read_text(encoding="utf-8"))
        changed["limits"] = {"max_amount": 1, "currency": "BAM",
                             "window_seconds": 3600}
        with self.assertRaises(core.PolicyDenied):
            core.verify_authorization(intent_factory(), grant, self.signers,
                                      policy=changed, audience="local-broker")


class ObserveIsNotExecuted(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = self.td.name
        self.key = os.path.join(self.dir, "id_ed25519")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f",
                        self.key], check=True)
        self.signers = os.path.join(self.dir, "signers")
        pathlib.Path(self.signers).write_text(
            'approver namespaces="mandate" %s\n' % pathlib.Path(
                self.key + ".pub").read_text(encoding="utf-8").strip(),
            encoding="utf-8")
        proposal = core.propose(intent_factory())
        gc = core.build_grant_core(proposal["commitment"], "approver",
                                   ttl_s=600, render_hash=proposal["render_hash"],
                                   agent="agent@example", audience="local-broker",
                                   policy_fingerprint=core.policy_digest(
                                       core.load_policy()))
        self.grant = core.make_grant(gc, self.key)
        self.intent = intent_factory()

    def tearDown(self):
        self.td.cleanup()

    def test_the_cli_says_observed_and_not_executed(self):
        receipt = core.redeem(self.intent, self.grant, self.signers,
                              os.path.join(self.dir, "l.jsonl"),
                              policy=core.load_policy(), audience="local-broker",
                              observe=True)
        self.assertEqual(receipt["body"]["decision"], "observe")
        rpath = os.path.join(self.dir, "r.json")
        gpath = os.path.join(self.dir, "g.json")
        ipath = os.path.join(self.dir, "i.json")
        pathlib.Path(rpath).write_text(json.dumps(receipt), encoding="utf-8")
        pathlib.Path(gpath).write_text(json.dumps(self.grant), encoding="utf-8")
        pathlib.Path(ipath).write_text(json.dumps(self.intent), encoding="utf-8")
        env = dict(os.environ)
        done = subprocess.run([sys.executable, str(ROOT / "bin" / "mandate"),
                               "verify", "--receipt", rpath, "--intent", ipath,
                               "--grant", gpath, "--signers", self.signers],
                              capture_output=True, text=True, env=env)
        payload = json.loads(done.stdout)
        self.assertTrue(payload["valid"])
        self.assertFalse(payload["executed"])
        self.assertTrue(payload["observed"])
        self.assertEqual(payload["decision"], "observe")


class ClaimsGateSeesItsOwnRows(unittest.TestCase):
    def _module(self, root):
        spec = importlib.util.spec_from_file_location(
            "mandate_claims_rt3", ROOT / "tools" / "claims.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.ROOT = str(root)
        module.STRICT[0] = True
        module.count_tests = lambda: 10
        module.count_summary = lambda: {"exit": 0, "passed": 7, "failed": 0,
                                        "skipped": 3}
        return module

    def _tree(self, collected=10, failed=0, readme_pass=8):
        td = tempfile.TemporaryDirectory()
        root = pathlib.Path(td.name)
        (root / "pyproject.toml").write_text('version = "1.2.3"\n',
                                             encoding="utf-8")
        (root / "CLAIMS.md").write_text(
            "| version | 1.2.3 |\n| tests collected | %d |\n"
            "| tests failed | %d |\n" % (collected, failed), encoding="utf-8")
        (root / "README.md").write_text("%d pass\n" % readme_pass,
                                        encoding="utf-8")
        return td, root

    def test_a_stale_collected_row_fails(self):
        td, root = self._tree(collected=999)
        try:
            problems = self._module(root).check_claims_file("1.2.3", 10)
        finally:
            td.cleanup()
        self.assertTrue(any("collected" in p for p in problems), problems)

    def test_a_failed_row_fails(self):
        td, root = self._tree(failed=3)
        try:
            problems = self._module(root).check_claims_file("1.2.3", 10)
        finally:
            td.cleanup()
        self.assertTrue(any("failed" in p for p in problems), problems)

    def test_the_full_gate_requires_every_test_to_be_accounted_for(self):
        td, root = self._tree()
        try:
            module = self._module(root)
            module.count_summary = lambda: {"exit": 0, "passed": 5, "failed": 0,
                                            "skipped": 1}
            os.environ["CLAIMS_FULL"] = "1"
            problems = module.check_versions()
        finally:
            os.environ.pop("CLAIMS_FULL", None)
            td.cleanup()
        self.assertTrue(any("accounted" in p for p in problems), problems)


if __name__ == "__main__":
    unittest.main()
