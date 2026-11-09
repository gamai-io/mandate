"""Firecracker stdio bridge for an MCP server inside a microVM.

The lab provides ``gama_mvm.py`` (Firecracker + KVM pool, Python inside the
guest). This bridge boots a microVM, copies host files referenced by absolute
path into ``/tmp`` in the guest, starts the command there and bridges JSON-RPC
lines between stdin/stdout and the guest serial console.

Usage:
  python3 -m mandate.firecracker_bridge -- python3 /tmp/fake_mcp.py
Set ``GAMA_MVM_DIR`` if ``gama_mvm.py`` is not in a default lab path.
"""
from __future__ import annotations

import base64
import json
import os
import shlex
import sys
import threading
import time

DEFAULT_MVM_DIRS = ("/root/gama-vmlab-lab", "/root/gama_mvm",
                    "/opt/gama-vmlab-lab")


def mvm_dir() -> str:
    candidates = [os.environ.get("GAMA_MVM_DIR", "")] + list(DEFAULT_MVM_DIRS)
    for path in candidates:
        if path and os.path.exists(os.path.join(path, "gama_mvm.py")):
            return path
    raise RuntimeError("gama_mvm.py not found; set GAMA_MVM_DIR")


def strip_separator(argv: list[str]) -> list[str]:
    argv = list(argv)
    if "--" in argv:
        return argv[argv.index("--") + 1:]
    return argv


def host_file_args(command: list[str]) -> list[str]:
    return [arg for arg in command
            if str(arg).startswith("/") and os.path.isfile(arg)]


class FirecrackerBridge:
    def __init__(self, command: list[str], cpus: int = 1, mem: int = 256):
        sys.path.insert(0, mvm_dir())
        import gama_mvm  # type: ignore
        self.command = list(command)
        self.vm = gama_mvm.MicroVM(cpus=cpus, mem=mem)
        self.vm.start()
        self._copy_files()
        try:
            self.vm.exec("stty -echo", timeout=10)
        except Exception:
            pass

    def _copy_files(self) -> None:
        for index, arg in enumerate(self.command):
            if str(arg).startswith("/") and os.path.isfile(arg):
                with open(arg, "rb") as fh:
                    data = base64.b64encode(fh.read()).decode()
                target = "/tmp/" + os.path.basename(arg)
                result = self.vm.exec(
                    "echo %s | base64 -d > %s" % (data, target), timeout=30)
                if result.get("rc") != 0:
                    raise RuntimeError("cannot copy %s into the microVM" % arg)
                self.command[index] = target
        if self.command and self.command[0].endswith("python3") \
                and "-u" not in self.command:
            self.command.insert(1, "-u")

    def run(self) -> int:
        line = " ".join(shlex.quote(part) for part in self.command)
        self.vm.p.stdin.write((line + "\n").encode())
        self.vm.p.stdin.flush()
        stop = threading.Event()

        def pump() -> None:
            for text in sys.stdin:
                try:
                    self.vm.p.stdin.write(text.encode())
                    self.vm.p.stdin.flush()
                except Exception:
                    break
            stop.set()

        threading.Thread(target=pump, daemon=True).start()
        position = 0
        buffer = b""
        deadline = None
        try:
            while True:
                if stop.is_set():
                    if deadline is None:
                        deadline = time.time() + 2.0
                    elif time.time() > deadline:
                        break
                data = self.vm._read()
                if len(data) > position:
                    buffer += data[position:]
                    position = len(data)
                    while b"\n" in buffer:
                        raw, buffer = buffer.split(b"\n", 1)
                        text = raw.decode("utf-8", "replace").strip()
                        start = text.find("{")
                        if start < 0:
                            continue
                        try:
                            _, end = json.JSONDecoder().raw_decode(text[start:])
                        except ValueError:
                            continue
                        sys.stdout.write(text[start:start + end] + "\n")
                        sys.stdout.flush()
                time.sleep(0.01)
        finally:
            try:
                self.vm.stop()
            except Exception:
                pass
        return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    command = strip_separator(argv)
    if not command:
        print("usage: python3 -m mandate.firecracker_bridge -- <cmd...>",
              file=sys.stderr)
        return 2
    bridge = FirecrackerBridge(command)
    return bridge.run()


if __name__ == "__main__":
    raise SystemExit(main())
