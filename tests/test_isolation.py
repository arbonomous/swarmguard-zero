"""Configuration regressions, not a claim of live OrbStack containment."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from types import SimpleNamespace
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import isolated_runner as runner

IMAGE = "sha256:" + "a" * 64


def configuration():
    return {"Name": "/test", "Image": IMAGE, "Config": {"User": "65534:65534", "Labels": {runner.LABEL: "1"}},
            "Mounts": [], "HostConfig": {"NetworkMode": "none", "ReadonlyRootfs": True, "Privileged": False,
            "IpcMode": "private", "PidMode": "private", "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges=true"],
            "PidsLimit": 64, "Memory": 268435456, "MemorySwap": 268435456, "NanoCpus": 1000000000,
            "Tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=32m,mode=1777"}}}


class IsolationTests(unittest.TestCase):
    def test_fixed_boundary(self):
        args = runner.create_args(IMAGE, "test", ["/bin/sh", "-c", "echo ok"])
        for flag in ("--network=none", "--read-only", "--cap-drop=ALL", "--pull=never", "--user=65534:65534"):
            self.assertIn(flag, args)
        self.assertNotIn("--pid=private", args)
        self.assertNotIn("--privileged", args)
        self.assertNotIn("--volume", args)
        self.assertEqual(args[-4:], ["/bin/sh", IMAGE, "-c", "echo ok"])

    def test_verified_configuration(self):
        runner.verify_container(configuration(), "test", IMAGE)

    def test_bad_host_settings_rejected(self):
        for key, value in [("NetworkMode", "host"), ("Privileged", True), ("ReadonlyRootfs", False),
                           ("Binds", ["/:/host"]), ("CapAdd", ["SYS_ADMIN"]), ("PidMode", "host"),
                           ("Devices", [{"PathOnHost": "/dev/disk0"}]), ("Memory", 0), ("SecurityOpt", []),
                           ("Tmpfs", {"/tmp": "rw,exec"})]:
            with self.subTest(key=key):
                data = configuration();data["HostConfig"][key] = value
                with self.assertRaises(ValueError): runner.verify_container(data, "test", IMAGE)

    def test_mount_and_user_rejected(self):
        data = configuration();data["Mounts"] = [{"Type": "bind", "Source": "/Users"}]
        with self.assertRaises(ValueError): runner.verify_container(data, "test", IMAGE)
        data = configuration();data["Config"]["User"] = "root"
        with self.assertRaises(ValueError): runner.verify_container(data, "test", IMAGE)

    def test_image_volumes_rejected(self):
        with patch.object(runner, "docker", return_value=SimpleNamespace(stdout=json.dumps([{"Id": IMAGE,"Config":{"Volumes":{"/data":{}}}}]))):
            with self.assertRaises(ValueError): runner.local_image("local")

    def test_unverified_never_started_and_cleanup_is_scoped(self):
        calls = []
        def fake(*args, **kwargs):
            calls.append(args)
            if args[0] == "inspect": return SimpleNamespace(stdout=json.dumps([{}]))
            return SimpleNamespace(stdout="")
        with patch.object(runner, "local_image", return_value=IMAGE), patch.object(runner, "docker", side_effect=fake):
            with self.assertRaises(ValueError): runner.run("local", ["/bin/sh"])
        self.assertFalse(any(c[0] == "start" for c in calls))
        self.assertEqual(calls[-1][:2], ("rm", "--force"))
        self.assertTrue(calls[-1][2].startswith("swarmguard-"))

    def test_relative_command_rejected(self):
        with self.assertRaises(ValueError): runner.create_args(IMAGE, "test", ["echo", "hi"])


if __name__ == "__main__": unittest.main()
