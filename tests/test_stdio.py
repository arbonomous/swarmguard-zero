"""Offline regressions. Wire client deliberately does not import proxy framing."""
import asyncio
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import shutil
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from mcp_proxy import _encode_message, _read_message
from menubar import _protecting_line


class StdioTests(unittest.TestCase):
    def test_wire_encoding(self):
        obj = {"jsonrpc": "2.0", "id": 1, "params": {"text": "café\nnext"}}
        wire = _encode_message(obj)
        self.assertEqual(wire.count(b"\n"), 1)
        self.assertTrue(wire.endswith(b"\n"))
        self.assertEqual(json.loads(wire), obj)
        self.assertNotIn(b"Content-Length", wire)

    def test_multiple_messages_and_eof(self):
        async def check():
            r = asyncio.StreamReader()
            r.feed_data(b'{"id":1}\n{"id":2}\n')
            r.feed_eof()
            self.assertEqual(await _read_message(r), {"id": 1})
            self.assertEqual(await _read_message(r), {"id": 2})
            self.assertIsNone(await _read_message(r))
        asyncio.run(check())

    def test_invalid_object_rejected(self):
        async def check():
            r = asyncio.StreamReader()
            r.feed_data(b'[]\n')
            with self.assertRaises(ValueError):
                await _read_message(r)
        asyncio.run(check())

    def test_heartbeat_refreshes_while_idle(self):
        from unittest.mock import patch
        from mcp_proxy import McpProxy
        proxy = McpProxy(["unused"])
        calls = []
        async def next_tick(_delay):
            calls.append("sleep")
            if len(calls) > 1:
                raise asyncio.CancelledError()
        async def check():
            with patch("mcp_proxy.asyncio.sleep", side_effect=next_tick), patch.object(proxy, "_heartbeat") as beat:
                with self.assertRaises(asyncio.CancelledError):
                    await proxy._keep_heartbeat()
                beat.assert_called_once()
        asyncio.run(check())

    def test_status_does_not_claim_protection(self):
        self.assertNotIn("Protecting", _protecting_line(True))
        self.assertIn("scoped", _protecting_line(True))
        self.assertIn("OFF", _protecting_line(False))

    def test_proof_leaves_gate_stopped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "safe_range").mkdir()
            for name in ("mcp_proxy.py", "policy.py", "threat_bus.py", "threat_model.py",
                         "safe_range/run_mcp_gate_demo.py", "safe_range/fake_mcp_upstream.py"):
                shutil.copyfile(ROOT / name, root / name)
            result = subprocess.run([sys.executable, str(root / "safe_range/run_mcp_gate_demo.py")],
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            status = json.loads((root / "mcp_gate_status.json").read_text())
            self.assertFalse(status["active"])
            self.assertEqual(status["note"], "proxy stopped")

    def test_standard_client_independent_upstream(self):
        # A separate, minimal server closes stderr while keeping the session up.
        # Large replies exercise frames beyond asyncio's default 64 KiB limit.
        server = '''import json,sys,os
os.close(2)
for line in sys.stdin:
 m=json.loads(line)
 if "id" not in m: continue
 if m["method"]=="initialize": result={"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"independent","version":"1"}}
 else: result={"text":"x"*100000}
 print(json.dumps({"jsonrpc":"2.0","id":m["id"],"result":result}),flush=True)
'''
        with tempfile.TemporaryDirectory() as tmp:
            # Keep heartbeats/incidents out of the working tree during tests.
            test_root = Path(tmp) / "project"
            test_root.mkdir()
            for name in ("mcp_proxy.py", "policy.py", "threat_bus.py", "threat_model.py"):
                shutil.copyfile(ROOT / name, test_root / name)
            path = Path(tmp) / "upstream.py"
            path.write_text(server)
            p = subprocess.Popen([sys.executable, str(test_root / "mcp_proxy.py"), "--", sys.executable, str(path)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={**os.environ, "SWARMGUARD_ENFORCE": "1", "SWARMGUARD_MUSE_ON_AMBIGUOUS": "0"})
            buf = bytearray()
            def rpc(i, method, params=None):
                msg={"jsonrpc":"2.0","id":i,"method":method}
                if params is not None: msg["params"]=params
                p.stdin.write(json.dumps(msg).encode()+b"\n"); p.stdin.flush()
                deadline=time.monotonic()+5
                while b"\n" not in buf:
                    with selectors.DefaultSelector() as sel:
                        sel.register(p.stdout, selectors.EVENT_READ)
                        self.assertTrue(sel.select(max(0,deadline-time.monotonic())), "stdio timeout")
                    chunk=os.read(p.stdout.fileno(),65536)
                    self.assertTrue(chunk, "unexpected EOF")
                    buf.extend(chunk)
                body,_,rest=buf.partition(b"\n");buf[:]=rest
                response=json.loads(body)
                self.assertEqual(response["id"],i)
                return response
            try:
                self.assertEqual(rpc(1,"initialize")["result"]["serverInfo"]["name"],"independent")
                self.assertEqual(len(rpc(2,"ping")["result"]["text"]),100000)
                denied=rpc(3,"tools/call",{"name":"read_file","arguments":{"path":".env"}})
                self.assertTrue(denied["result"]["isError"])
                self.assertIn("DENIED",denied["result"]["content"][0]["text"])
                self.assertIsNone(p.poll())
            finally:
                p.stdin.close()
                p.wait(timeout=6)
                p.stdout.close();p.stderr.close()


if __name__ == "__main__":
    unittest.main()
