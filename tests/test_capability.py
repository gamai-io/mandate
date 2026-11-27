"""CAPABILITY_V1: delegated authority can only narrow.

A grant authorises one effect; a capability token says whether the agent was allowed to
ask at all. The property that matters is attenuation: no child may allow more than its
parent, and the chain must be verifiable link by link.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest

from mandate import capability

ROOT = pathlib.Path(__file__).resolve().parents[1]


class Base(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        d = self.dir = self.td.name
        self.keys = {}
        for name in ("ops", "lead", "agent"):
            path = os.path.join(d, name)
            subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", path],
                           check=True, capture_output=True)
            self.keys[name] = path
        self.signers = os.path.join(d, "signers")
        pathlib.Path(self.signers).write_text("".join(
            '%s namespaces="mandate-capability" %s\n'
            % (n, pathlib.Path(self.keys[n] + ".pub").read_text(encoding="utf-8").strip())
            for n in self.keys), encoding="utf-8")

    def tearDown(self):
        self.td.cleanup()

    def root(self, **over):
        scope = {"kinds": ["payment.send"], "max_amount": 5000, "currency": "BAM",
                 "targets": ["Example Supplier", "Other Ltd"]}
        scope.update(over.pop("scopes", {}))
        return capability.mint(scope, self.keys["ops"], "ops", "ops", ttl_s=3600,
                               max_uses=5, **over)


class MintAndVerify(Base):
    def test_roundtrip(self):
        token = self.root()
        out = capability.verify(token, self.signers)
        self.assertTrue(out["ok"])
        self.assertEqual(out["subject"], "ops")

    def test_tampered_scope_breaks_the_signature(self):
        token = self.root()
        token["scopes"]["max_amount"] = 99999
        with self.assertRaises(capability.CapabilityError) as ctx:
            capability.verify(token, self.signers)
        self.assertEqual(ctx.exception.code, "E_SIG")

    def test_expired_token_is_refused(self):
        token = self.root()
        with self.assertRaises(capability.CapabilityError) as ctx:
            capability.verify(token, self.signers, now=time.time() + 7200)
        self.assertEqual(ctx.exception.code, "E_EXPIRED")

    def test_unknown_signer_is_refused(self):
        other = os.path.join(self.dir, "outsider")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", other],
                       check=True, capture_output=True)
        token = capability.mint({"kinds": ["payment.send"]}, other, "outsider", "x")
        with self.assertRaises(capability.CapabilityError) as ctx:
            capability.verify(token, self.signers)
        self.assertEqual(ctx.exception.code, "E_SIG")


class Attenuation(Base):
    def test_child_can_narrow(self):
        parent = self.root()
        child = capability.attenuate(parent, {"kinds": ["payment.send"], "max_amount": 100,
                                              "currency": "BAM",
                                              "targets": ["Example Supplier"]},
                                     self.keys["ops"], "lead",
                                     signers_path=self.signers)
        self.assertTrue(capability.verify(child, self.signers)["ok"])
        self.assertEqual(child["scopes"]["max_amount"], 100)

    def test_child_cannot_raise_the_amount(self):
        parent = self.root()
        with self.assertRaises(capability.CapabilityError) as ctx:
            capability.attenuate(parent, {"kinds": ["payment.send"], "max_amount": 9000,
                                         "currency": "BAM",
                                         "targets": ["Example Supplier"]},
                                 self.keys["ops"], "lead", signers_path=self.signers)
        self.assertEqual(ctx.exception.code, "E_WIDEN")

    def test_child_cannot_add_a_kind(self):
        parent = self.root()
        with self.assertRaises(capability.CapabilityError) as ctx:
            capability.attenuate(parent, {"kinds": ["payment.send", "wire.transfer"],
                                         "max_amount": 100, "currency": "BAM",
                                         "targets": ["Example Supplier"]},
                                 self.keys["ops"], "lead", signers_path=self.signers)
        self.assertEqual(ctx.exception.code, "E_WIDEN")

    def test_child_cannot_drop_the_target_list(self):
        parent = self.root()
        with self.assertRaises(capability.CapabilityError) as ctx:
            capability.attenuate(parent, {"kinds": ["payment.send"], "max_amount": 100,
                                          "currency": "BAM"},
                                 self.keys["ops"], "lead", signers_path=self.signers)
        self.assertEqual(ctx.exception.code, "E_WIDEN")

    def test_child_cannot_live_longer(self):
        parent = self.root()
        with self.assertRaises(capability.CapabilityError) as ctx:
            capability.attenuate(parent, {"kinds": ["payment.send"], "max_amount": 100,
                                          "currency": "BAM",
                                          "targets": ["Example Supplier"]},
                                 self.keys["ops"], "lead", ttl_s=999999,
                                 signers_path=self.signers)
        self.assertEqual(ctx.exception.code, "E_WIDEN")

    def test_child_cannot_raise_max_uses(self):
        parent = self.root()
        with self.assertRaises(capability.CapabilityError) as ctx:
            capability.attenuate(parent, {"kinds": ["payment.send"], "max_amount": 100,
                                          "currency": "BAM",
                                          "targets": ["Example Supplier"]},
                                 self.keys["ops"], "lead", max_uses=50,
                                 signers_path=self.signers)
        self.assertEqual(ctx.exception.code, "E_WIDEN")


class Chains(Base):
    def _chain(self):
        root = self.root()
        child = capability.attenuate(root, {"kinds": ["payment.send"], "max_amount": 2000,
                                            "currency": "BAM",
                                            "targets": ["Example Supplier"]},
                                     self.keys["ops"], "lead", signers_path=self.signers)
        leaf = capability.attenuate(child, {"kinds": ["payment.send"], "max_amount": 500,
                                            "currency": "BAM",
                                            "targets": ["Example Supplier"]},
                                    self.keys["lead"], "agent@example",
                                    signers_path=self.signers)
        return root, child, leaf

    def test_chain_verifies(self):
        root, child, leaf = self._chain()
        out = capability.verify_chain([root, child, leaf], self.signers)
        self.assertTrue(out["ok"])
        self.assertEqual(out["length"], 3)
        self.assertEqual(out["subject"], "agent@example")

    def test_broken_link_is_caught(self):
        root, child, leaf = self._chain()
        other = self.root()
        with self.assertRaises(capability.CapabilityError) as ctx:
            capability.verify_chain([other, child, leaf], self.signers)
        self.assertEqual(ctx.exception.code, "E_CHAIN")

    def test_root_with_a_parent_is_caught(self):
        root, child, leaf = self._chain()
        with self.assertRaises(capability.CapabilityError) as ctx:
            capability.verify_chain([child, leaf], self.signers)
        self.assertEqual(ctx.exception.code, "E_CHAIN")


class Allows(Base):
    def setUp(self):
        super().setUp()
        self.token = capability.mint({"kinds": ["payment.send"], "max_amount": 1000,
                                      "currency": "BAM", "targets": ["Example Supplier"]},
                                     self.keys["ops"], "ops", "agent@example")

    def _intent(self, kind="payment.send", target="Example Supplier", value=100,
                currency="BAM"):
        return {"effect": {"kind": kind, "target": target,
                           "amount": {"value": value, "currency": currency}}}

    def test_allowed(self):
        self.assertTrue(capability.allows(self.token, self._intent())["ok"])

    def test_kind_target_amount_currency(self):
        self.assertFalse(capability.allows(self.token, self._intent(kind="read.lookup"))["ok"])
        self.assertFalse(capability.allows(self.token, self._intent(target="Evil Ltd"))["ok"])
        self.assertFalse(capability.allows(self.token, self._intent(value=5000))["ok"])
        self.assertFalse(capability.allows(self.token, self._intent(currency="EUR"))["ok"])


class Cli(Base):
    def _run(self, *args):
        return subprocess.run([sys.executable, "-m", "mandate", "--signers", self.signers,
                               "cap", *args], cwd=str(ROOT), capture_output=True, text=True)

    def test_mint_attenuate_verify(self):
        root = os.path.join(self.dir, "root.json")
        child = os.path.join(self.dir, "child.json")
        done = self._run("mint", "--kinds", "payment.send", "--max-amount", "5000",
                         "--currency", "BAM", "--targets", "Example Supplier",
                         "--issuer", "ops", "--subject", "ops",
                         "--key", self.keys["ops"], "-o", root)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        done = self._run("attenuate", "--parent", root, "--kinds", "payment.send",
                         "--max-amount", "500", "--currency", "BAM",
                         "--targets", "Example Supplier", "--subject", "lead",
                         "--key", self.keys["ops"], "-o", child)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        done = self._run("verify", "--chain", "%s,%s" % (root, child))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertTrue(json.loads(done.stdout)["ok"])

    def test_widening_exits_non_zero(self):
        root = os.path.join(self.dir, "root.json")
        self._run("mint", "--kinds", "payment.send", "--max-amount", "500",
                  "--issuer", "ops", "--subject", "ops", "--key", self.keys["ops"],
                  "-o", root)
        done = self._run("attenuate", "--parent", root, "--kinds", "payment.send",
                         "--max-amount", "9000", "--subject", "lead",
                         "--key", self.keys["ops"])
        self.assertEqual(done.returncode, 1)
        self.assertEqual(json.loads(done.stdout)["error"], "E_WIDEN")


if __name__ == "__main__":
    unittest.main()
