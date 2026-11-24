"""SVID: short-lived agent identity and delegation chains that can only narrow."""
from __future__ import annotations

import os
import subprocess
import tempfile
import time
import unittest

from mandate import svid


def make_key(directory: str, name: str) -> str:
    path = os.path.join(directory, name)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-f", path, "-C", name, "-N", ""],
                   check=True)
    return path


class Svid(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dir = cls.tmp.name
        cls.agent_key = make_key(cls.dir, "agent_key")
        cls.sub_key = make_key(cls.dir, "sub_key")
        cls.signers = os.path.join(cls.dir, "allowed_signers")
        with open(cls.signers, "w", encoding="utf-8") as fh:
            for name, key in (("bank-agent", cls.agent_key), ("sub-agent", cls.sub_key)):
                pub = open(key + ".pub").read().strip()
                fh.write(f'{name} namespaces="mandate" {pub}\n')

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def token(self, **kw) -> dict:
        kw.setdefault("sub", "bank-agent")
        kw.setdefault("issuer", "bank-agent")
        kw.setdefault("audience", "local-broker")
        kw.setdefault("scopes", ["payment.send"])
        kw.setdefault("ttl", 300)
        return svid.issue(key_path=self.agent_key, **kw)

    def test_issue_and_verify(self) -> None:
        res = svid.verify(self.token(), self.signers, audience="local-broker")
        self.assertTrue(res["valid"], res)
        self.assertEqual(res["payload"]["sub"], "bank-agent")

    def test_expired(self) -> None:
        tok = self.token(ttl=10)
        res = svid.verify(tok, self.signers, now=time.time() + 11)
        self.assertFalse(res["valid"])
        self.assertEqual(res["code"], "expired")

    def test_tampered_payload(self) -> None:
        tok = self.token()
        tok["payload"]["scopes"] = ["payment.send", "wire.transfer"]
        res = svid.verify(tok, self.signers)
        self.assertFalse(res["valid"])
        self.assertEqual(res["code"], "bad_signature")

    def test_wrong_audience(self) -> None:
        res = svid.verify(self.token(), self.signers, audience="other-broker")
        self.assertEqual(res["code"], "wrong_audience")

    def test_ttl_is_capped(self) -> None:
        with self.assertRaises(ValueError):
            self.token(ttl=99999)

    def test_covers(self) -> None:
        tok = self.token()
        self.assertTrue(svid.covers(tok, "payment.send")["ok"])
        self.assertEqual(svid.covers(tok, "order.create")["code"], "scope_not_granted")
        self.assertEqual(svid.covers(tok, "payment.send", subject="other")["code"],
                         "subject_mismatch")

    def test_chain_narrows_and_passes(self) -> None:
        parent = self.token()
        child = svid.issue("sub-agent", self.sub_key, "sub-agent", "local-broker",
                           ["payment.send"], 30, parent=parent["payload"])
        res = svid.verify_chain(child, [parent], self.signers, audience="local-broker")
        self.assertTrue(res["valid"], res)
        self.assertEqual(res["depth"], 1)

    def test_chain_rejects_widened_scopes(self) -> None:
        parent = self.token()
        child = svid.issue("sub-agent", self.sub_key, "sub-agent", "local-broker",
                           ["payment.send", "order.create"], 30, parent=parent["payload"])
        res = svid.verify_chain(child, [parent], self.signers)
        self.assertFalse(res["valid"])
        self.assertEqual(res["code"], "scope_widened")

    def test_chain_rejects_extended_expiry(self) -> None:
        parent = self.token(ttl=60)
        child = svid.issue("sub-agent", self.sub_key, "sub-agent", "local-broker",
                           ["payment.send"], 600, parent=parent["payload"])
        res = svid.verify_chain(child, [parent], self.signers)
        self.assertEqual(res["code"], "expiry_extended")

    def test_chain_requires_the_parent(self) -> None:
        parent = self.token()
        child = svid.issue("sub-agent", self.sub_key, "sub-agent", "local-broker",
                           ["payment.send"], 30, parent=parent["payload"])
        res = svid.verify_chain(child, [], self.signers)
        self.assertFalse(res["valid"])
        self.assertEqual(res["code"], "parent_missing")

    def test_self_delegation_rejected(self) -> None:
        parent = self.token()
        same = svid.issue("bank-agent", self.agent_key, "bank-agent", "local-broker",
                          ["payment.send"], 30, parent=parent["payload"])
        res = svid.verify_chain(same, [parent], self.signers)
        self.assertFalse(res["valid"])
        self.assertEqual(res["code"], "self_delegation")


if __name__ == "__main__":
    unittest.main()
