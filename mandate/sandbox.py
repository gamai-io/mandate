"""Sandbox runner for untrusted MCP servers.

local      - no isolation (development)
docker     - hardened Docker (runc): read-only root, no network, caps dropped
gvisor     - same but --runtime runsc
firecracker- wrap the command with an external launcher (e.g. a VMLab runner)
"""
from __future__ import annotations

import shlex

from . import core


class SandboxError(core.MandateError):
    pass


class LocalRunner:
    def wrap(self, cmd: str) -> list[str]:
        return shlex.split(str(cmd))


class DockerRunner:
    def __init__(self, image: str = "python:3.12-slim",
                 mounts: list[str] | None = None, workdir: str = "",
                 net: bool = False, runtime: str = "runc",
                 memory: str = "256m", pids: int = 128, cpus: str = "1"):
        self.image = str(image or "python:3.12-slim")
        self.mounts = list(mounts or [])
        self.workdir = str(workdir or "")
        self.net = bool(net)
        self.runtime = str(runtime or "runc")
        self.memory = str(memory or "256m")
        self.pids = int(pids or 128)
        self.cpus = str(cpus or "1")

    def wrap(self, cmd: str) -> list[str]:
        argv = [
            "docker", "run", "--rm", "-i",
            "--read-only",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", str(self.pids),
            "--memory", self.memory,
            "--cpus", self.cpus,
            "--tmpfs", "/tmp:rw,size=16m",
            "--env", "PYTHONDONTWRITEBYTECODE=1",
            "--env", "PYTHONUNBUFFERED=1",
        ]
        if not self.net:
            argv += ["--network", "none"]
        if self.runtime and self.runtime != "runc":
            argv += ["--runtime", self.runtime]
        for mount in self.mounts:
            argv += ["-v", str(mount)]
        if self.workdir:
            argv += ["-w", self.workdir]
        argv.append(self.image)
        argv += shlex.split(str(cmd))
        return argv


class TemplateRunner:
    def __init__(self, template: str):
        self.prefix = shlex.split(str(template or ""))
        if not self.prefix:
            raise SandboxError("sandbox command template is empty")

    def wrap(self, cmd: str) -> list[str]:
        return self.prefix + shlex.split(str(cmd))


def build_runner(mode: str = "local", image: str = "python:3.12-slim",
                 mounts: list[str] | None = None, workdir: str = "",
                 net: bool = False, template: str = "") -> object:
    mode = str(mode or "local").lower()
    if mode == "local":
        return LocalRunner()
    if mode == "docker":
        return DockerRunner(image=image, mounts=mounts, workdir=workdir,
                            net=net, runtime="runc")
    if mode == "gvisor":
        return DockerRunner(image=image, mounts=mounts, workdir=workdir,
                            net=net, runtime="runsc")
    if mode == "firecracker":
        if not template:
            raise SandboxError("firecracker requires --sandbox-cmd-template")
        return TemplateRunner(template)
    raise SandboxError("unknown sandbox mode: %s" % mode)
