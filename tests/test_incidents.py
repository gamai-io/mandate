"""Replay the recorded incidents against this stack, including the ones it misses.

Each test names a public incident and asserts only what the code can actually do.
Where the answer is "not covered", the test says so with a skip and a reason, so
the inventory cannot quietly grow optimistic over time.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import time
import unittest

from mandate import core

POLICY = {
    "version": 1, "default": "deny",
    "effects": {
        "payment.send": {"risk": "high", "new_payee": "deny",
                         "new_payee_grace_h": 24},
        "mcp.call": {"risk": "high"},
    },
}


def keypair(td: str, name: str) -> str:
    path = os.path.join(td, name)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-f", path, "-C", name,
                    "-N", ""], check=True)
    return path


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.key = keypair(self.dir, "approver")
        self.signers = os.path.join(self.dir, "allowed_signers")
        open(self.signers, "w").write(
            'approver namespaces="mandate" %s\n' % open(self.key + ".pub").read().strip())
        self.ledger = os.path.join(self.dir, "ledger.jsonl")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def intent(self, **effect) -> dict:
        base = {"kind": "payment.send", "target": "Supplier A",
                "amount": {"value": 1170.0, "currency": "BAM"}}
        base.update(effect)
        return core.normalize_intent({
            "v": 1, "actor": {"agent": "bank-agent", "session": "s"},
            "effect": base, "requested_by": "ops",
            "nonce": "n-%d" % int(time.time() * 1e6),
            "provenance": [{"type": "data_ref", "source": "erp:x"}]})

    def grant(self, item: dict) -> dict:
        gc = core.build_grant_core(core.intent_commitment(item), "approver",
                                   ttl_s=600, render_hash=core.render_hash(item),
                                   agent="bank-agent")
        return core.make_grant(gc, self.key)

    def pay(self, item: dict) -> dict:
        return core.redeem(item, self.grant(item), self.signers, self.ledger,
                           policy=POLICY)


class Incidents(Base):
    def test_zscaler_injected_payee_is_refused(self) -> None:
        """A site talks the agent into paying a wallet it has never paid before."""
        item = self.intent(target="attacker-wallet-0xdead")
        with self.assertRaises(core.PolicyDenied):
            self.pay(item)

    def test_lakera_poisoned_payee_inside_the_cooling_period_is_refused(self) -> None:
        """Memory poisoning plants the payee days early; the grace window still holds."""
        first = self.intent(target="poisoned-supplier")
        # the instruction was planted earlier, so one small payment already exists
        core.redeem(first, self.grant(first), self.signers, self.ledger,
                    policy={"version": 1, "default": "deny",
                            "effects": {"payment.send": {"risk": "high"}}})
        second = self.intent(target="poisoned-supplier",
                             amount={"value": 90000.0, "currency": "BAM"})
        with self.assertRaises(core.PolicyDenied):
            self.pay(second)

    def test_opus_47_wrong_target_is_refused(self) -> None:
        """A grant for one company cannot pay a similarly-named one."""
        granted = self.intent(target="Real Company d.o.o.")
        swapped = self.intent(target="Real Company d.o.o. (impostor)")
        with self.assertRaises(core.CommitmentMismatch):
            core.redeem(swapped, self.grant(granted), self.signers, self.ledger,
                        policy=POLICY)

    def test_deadbugz_tool_metadata_is_bound_by_the_commitment(self) -> None:
        """Approving a tool approves its schema hash, so a later swap fails."""
        approved = self.intent(kind="mcp.call", target="invoices",
                               params={"tool": "erp.read", "schema_sha256": "a" * 64})
        swapped = self.intent(kind="mcp.call", target="invoices",
                              params={"tool": "erp.read", "schema_sha256": "b" * 64})
        with self.assertRaises(core.CommitmentMismatch):
            core.redeem(swapped, self.grant(approved), self.signers, self.ledger,
                        policy=POLICY)

    def test_an_effect_kind_outside_the_policy_is_denied(self) -> None:
        """Default deny is what stops the publish/DB class if it goes through us."""
        item = self.intent(kind="package.publish", target="pypi:requests-secure-v2")
        with self.assertRaises(core.PolicyDenied):
            self.pay(item)

    def test_a_replayed_grant_is_refused(self) -> None:
        plain = {"version": 1, "default": "deny",
                 "effects": {"payment.send": {"risk": "high"}}}
        item = self.intent(target="Known Supplier")
        grant = self.grant(item)
        core.redeem(item, grant, self.signers, self.ledger, policy=plain)
        with self.assertRaises(core.GrantReplayed):
            core.redeem(item, grant, self.signers, self.ledger, policy=plain)

    @unittest.skip("not covered: sandbox escape and host-level code execution "
                   "(Hugging Face 41 dataset workers, OpenAI Artifactory) happen "
                   "outside any authorisation path; that is a hypervisor and "
                   "network control, not this package")
    def test_huggingface_sandbox_escape(self) -> None:
        pass

    @unittest.skip("not covered: supply-chain worms (Shai-Hulud/Miasma) and "
                   "assistant config tampering are endpoint and registry "
                   "integrity; nothing here reads the developer's machine")
    def test_shai_hulud_config_worm(self) -> None:
        pass

    @unittest.skip("not covered: memory poisoning inside the assistant "
                   "(CoSnitch CVE-2026-24301, Lakera) is only limited here by the "
                   "new_payee gate, not by inspecting memory")
    def test_cosnitch_memory_poisoning(self) -> None:
        pass


if __name__ == "__main__":
    unittest.main()
