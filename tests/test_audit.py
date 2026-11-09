import os
import pathlib
import subprocess
import tempfile
import unittest

from mandate import audit, core, export
from mandate import log as mlog
from mandate import witness as mwit


class AuditBundleTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = self.td.name
        self.approver = os.path.join(self.dir, "approver")
        self.logkey = os.path.join(self.dir, "logkey")
        for path in (self.approver, self.logkey):
            subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", path],
                           check=True, capture_output=True)
        self.signers = os.path.join(self.dir, "signers")
        pathlib.Path(self.signers).write_text(
            'approver namespaces="mandate,mandate-export" %s\n'
            'log1 namespaces="mandate-log" %s\n' % (
                pathlib.Path(self.approver + ".pub").read_text(
                    encoding="utf-8").strip(),
                pathlib.Path(self.logkey + ".pub").read_text(
                    encoding="utf-8").strip()),
            encoding="utf-8")
        self.ledger = os.path.join(self.dir, "ledger.jsonl")
        self.intent = intent_factory()
        proposal = core.propose(self.intent)
        grant_core = core.build_grant_core(
            proposal["commitment"], "approver", ttl_s=900,
            render_hash=proposal["render_hash"], agent="agent@example")
        self.grant = core.make_grant(grant_core, self.approver)
        self.receipt = core.redeem(self.intent, self.grant, self.signers,
                                   self.ledger, policy=core.load_policy())
        leaves = mlog.leaves_from_ledger(self.ledger)
        self.proof = mlog.inclusion_proof(leaves, 0)
        payload = mlog.sth_payload(
            "log1", mlog.log_id_from_key(self.logkey), len(leaves),
            mlog.root_hex(leaves))
        self.sth = mlog.sign_sth(payload, self.logkey)
        self.state_path = os.path.join(self.dir, "witness.json")
        mwit.accept(self.sth, None, self.signers, self.state_path)
        self.state = mwit.load_state(self.state_path)

    def tearDown(self):
        self.td.cleanup()

    def _bundle(self, **over):
        kwargs = dict(key_path=self.approver, signer="approver",
                      sth=self.sth, witness_state=self.state)
        kwargs.update(over)
        return export.build_bundle(self.receipt, self.intent, self.grant,
                                   self.proof, **kwargs)

    def test_valid_bundle(self):
        result = audit.verify_bundle(self._bundle(), self.signers,
                                     self.signers)
        self.assertTrue(result["valid"], result)
        self.assertTrue(result["envelope"]["valid"])
        self.assertTrue(result["sth"])
        self.assertTrue(result["inclusion"])
        self.assertTrue(result["witness"])

    def test_wrong_witness_state_fails(self):
        bad_state = dict(self.state)
        bad_state["tree_size"] = int(bad_state["tree_size"]) + 1
        result = audit.verify_bundle(self._bundle(witness_state=bad_state),
                                     self.signers, self.signers)
        self.assertFalse(result["witness"])
        self.assertFalse(result["valid"])

    def test_missing_sth_fails(self):
        bundle = self._bundle(sth=None)
        result = audit.verify_bundle(bundle, self.signers, self.signers)
        self.assertFalse(result["sth"])
        self.assertFalse(result["valid"])

    def test_tampered_inclusion_fails(self):
        bundle = self._bundle()
        bundle["inclusion_proof"]["leaf_hash"] = "00" * 32
        result = audit.verify_bundle(bundle, self.signers, self.signers)
        self.assertFalse(result["inclusion"])
        self.assertFalse(result["valid"])


def intent_factory():
    return {
        "v": 1,
        "actor": {"agent": "agent@example"},
        "effect": {"kind": "payment.send", "target": "Example Supplier",
                   "amount": {"value": 10.0, "currency": "BAM"},
                   "params": {}},
        "requested_by": "approver",
        "nonce": "audit-1",
        "provenance": [{"type": "data_ref", "source": "erp:vendor:1",
                        "covers": ["target", "amount"]}],
    }


if __name__ == "__main__":
    unittest.main()
