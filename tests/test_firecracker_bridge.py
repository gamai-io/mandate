import os
import tempfile
import unittest

from mandate import firecracker_bridge as fb


class BridgeHelpersTests(unittest.TestCase):
    def test_strip_separator(self):
        self.assertEqual(fb.strip_separator(["--", "python3", "s.py"]),
                         ["python3", "s.py"])
        self.assertEqual(fb.strip_separator(["python3", "s.py"]),
                         ["python3", "s.py"])

    def test_host_file_args(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "srv.py")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("print('x')\n")
            self.assertEqual(fb.host_file_args([path, "--flag", "text"]), [path])

    def test_mvm_dir_env(self):
        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "gama_mvm.py"), "w", encoding="utf-8") as fh:
                fh.write("")
            old = os.environ.get("GAMA_MVM_DIR")
            os.environ["GAMA_MVM_DIR"] = td
            try:
                self.assertEqual(fb.mvm_dir(), td)
            finally:
                if old is None:
                    os.environ.pop("GAMA_MVM_DIR", None)
                else:
                    os.environ["GAMA_MVM_DIR"] = old


if __name__ == "__main__":
    unittest.main()
