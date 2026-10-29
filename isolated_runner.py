#!/usr/bin/env python3
"""Agent-neutral, offline scratch container runner. No host mounts or image pulls.

This is containment for commands launched here, not whole-Mac monitoring.
The user must select a trusted, already-present Linux image and command.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import uuid

CONTEXT = "orbstack"
LABEL = "com.swarmguard.isolated"


def docker(*args: str, timeout: int = 15) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    # Explicit context must not be redirected to another daemon by inherited env.
    for key in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
        env.pop(key, None)
    return subprocess.run(["docker", "--context", CONTEXT, *args], env=env,
                          capture_output=True, text=True, timeout=timeout, check=True)


def local_image(reference: str) -> str:
    if not reference or reference.startswith("-"):
        raise ValueError("Invalid image reference")
    data = json.loads(docker("image", "inspect", reference).stdout)[0]
    # An image VOLUME silently creates writable mounts even with no -v flag.
    if data.get("Config", {}).get("Volumes"):
        raise ValueError("Image declares volumes. Choose a trusted image without VOLUME directives.")
    image_id = data.get("Id", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise ValueError("Could not pin a local image ID")
    return image_id


def create_args(image_id: str, name: str, command: list[str]) -> list[str]:
    if not command or not command[0].startswith("/"):
        raise ValueError("Command must start with an absolute executable path inside the image")
    return ["create", "--name", name, "--label", f"{LABEL}=1", "--pull=never",
            "--network=none", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges=true", "--user=65534:65534",
            "--pids-limit=64", "--memory=256m", "--memory-swap=256m", "--cpus=1",
            "--ipc=private", "--pid=private", "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777",
            "--workdir=/tmp", "--env=HOME=/tmp", "--env=TMPDIR=/tmp",
            "--entrypoint", command[0], image_id, *command[1:]]


def verify_container(data: dict, name: str, image_id: str) -> None:
    host = data.get("HostConfig", {})
    config = data.get("Config", {})
    checks = {
        "name": data.get("Name") == "/" + name,
        "image": data.get("Image") == image_id,
        "ownership label": config.get("Labels", {}).get(LABEL) == "1",
        "network disabled": host.get("NetworkMode") == "none",
        "read-only root": host.get("ReadonlyRootfs") is True,
        "non-root user": config.get("User") == "65534:65534",
        "not privileged": host.get("Privileged") is False,
        "no bind mounts": not host.get("Binds"),
        "no volume inheritance": not host.get("VolumesFrom"),
        "no devices": not host.get("Devices") and not host.get("DeviceRequests"),
        "no port publishing": not host.get("PortBindings") and not host.get("PublishAllPorts"),
        "private PID namespace": host.get("PidMode") in ("private", ""),
        "private IPC": host.get("IpcMode") == "private",
        "capabilities dropped": "ALL" in (host.get("CapDrop") or []),
        "no capabilities added": not host.get("CapAdd"),
        "no privilege escalation": any(x in ("no-new-privileges", "no-new-privileges=true") for x in host.get("SecurityOpt", [])),
        "bounded processes": host.get("PidsLimit") == 64,
        "bounded memory": host.get("Memory") == 256 * 1024 * 1024,
        "bounded swap": host.get("MemorySwap") == 256 * 1024 * 1024,
        "bounded CPU": host.get("NanoCpus") == 1_000_000_000,
        "no host/volume mounts": all(m.get("Type") == "tmpfs" for m in data.get("Mounts", [])),
        "scratch only": set(host.get("Tmpfs", {})) == {"/tmp"},
        "scratch restrictions": {"noexec", "nosuid", "nodev", "size=32m"}.issubset(
            set(host.get("Tmpfs", {}).get("/tmp", "").split(","))
        ),
    }
    failed = [key for key, ok in checks.items() if not ok]
    if failed:
        raise ValueError("Container configuration rejected: " + ", ".join(failed))


def run(image: str, command: list[str], seconds: int = 60) -> int:
    image_id = local_image(image)
    name = "swarmguard-" + uuid.uuid4().hex
    created = False
    try:
        docker(*create_args(image_id, name, command))
        created = True
        data = json.loads(docker("inspect", name).stdout)[0]
        verify_container(data, name, image_id)
        print("SwarmGuard: verified offline scratch boundary. No host mounts. Not whole-Mac protection.", flush=True)
        try:
            result = docker("start", "--attach", name, timeout=seconds)
            print(result.stdout, end="")
            print(result.stderr, end="", file=sys.stderr)
        except subprocess.TimeoutExpired:
            print("SwarmGuard: time limit reached; stopping only this scratch container.", file=sys.stderr)
            return 124
        state = json.loads(docker("inspect", name).stdout)[0]["State"]
        return int(state["ExitCode"])
    finally:
        if created:
            # Unique generated name, never prune or remove other environments.
            try:
                docker("rm", "--force", name)
            except Exception as exc:
                print(f"Cleanup needs attention for {name}: {type(exc).__name__}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="Trusted existing local image (never downloaded)")
    parser.add_argument("--seconds", type=int, default=60, choices=range(1, 301), metavar="1..300")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    ns = parser.parse_args()
    command = ns.command[1:] if ns.command[:1] == ["--"] else ns.command
    return run(ns.image, command, ns.seconds)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, FileNotFoundError, subprocess.SubprocessError, KeyError, json.JSONDecodeError) as exc:
        # Never fall back to running the command directly on the Mac.
        print(f"SwarmGuard refused to launch: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)
