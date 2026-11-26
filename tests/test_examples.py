"""The examples are product surface; run the offline ones for real.

They broke before (a grant bound to an audience that `redeem` could not name), so
the README test only covers the quickstart. These are the rest of the offline
scripts; 06 needs a TSA over the network and is deliberately excluded.

Set `RUN_EXAMPLES=1` (CI does this in one job) to run them.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXAMPLES = ["01-invoice-approval.sh", "02-audit-bundle.sh", "05-bank-scenario.sh",
            "09-identity.sh", "12-detect.sh", "13-audit-pack.sh"]
ENABLED = os.environ.get("RUN_EXAMPLES") == "1"


@unittest.skipUnless(ENABLED, "set RUN_EXAMPLES=1 to run the offline examples")
class Examples(unittest.TestCase):
    def test_each_offline_example_exits_zero(self) -> None:
        for name in EXAMPLES:
            with self.subTest(example=name):
                with tempfile.TemporaryDirectory() as td:
                    work = pathlib.Path(td)
                    shutil.copytree(ROOT / "examples", work / "examples")
                    env = dict(os.environ)
                    done = subprocess.run(["bash", "examples/" + name],
                                          cwd=str(work), env=env,
                                          capture_output=True, text=True,
                                          timeout=180)
                    self.assertEqual(done.returncode, 0,
                                     "%s failed:\n%s\n%s"
                                     % (name, done.stdout[-2000:],
                                        done.stderr[-2000:]))


if __name__ == "__main__":
    unittest.main()
