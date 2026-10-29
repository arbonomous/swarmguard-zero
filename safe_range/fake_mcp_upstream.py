#!/usr/bin/env python3
"""Tiny fake MCP stdio server for proving the SwarmGuard gate.

Tools: read_file, run_command.
Every tools/call is appended to a log file so the harness can assert
denied calls never reached upstream.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOG = Path(__file__).resolve().parent / "fake_upstream_calls.jsonl"


def _encode(obj: dict[str, Any]) -> bytes:
    body = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body


def _write(obj: dict[str, Any]) -> None:
    sys.stdout.buffer.write(_encode(obj))
    sys.stdout.buffer.flush()


def _read() -> dict[str, Any] | None:
    content_length: int | None = None
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        if line in (b"\r\n", b"\n"):
            break
        text = line.decode("ascii", errors="replace").strip()
        if not text:
            break
        if ":" in text:
            key, value = text.split(":", 1)
            if key.strip().lower() == "content-length":
                try:
                    content_length = int(value.strip())
                except ValueError:
                    content_length = None
    if content_length is None:
        return None
    body = sys.stdin.buffer.read(content_length)
    if len(body) < content_length:
        return None
    return json.loads(body.decode("utf-8"))


def _log_call(log_path: Path, name: str, arguments: dict[str, Any]) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(
            json.dumps({"name": name, "arguments": arguments}, ensure_ascii=False) + "\n"
        )


def _ok_text(msg_id: Any, text: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "result": {"content": [{"type": "text", "text": text}], "isError": False},
    }


def _handle(msg: dict[str, Any], log_path: Path) -> None:
    method = msg.get("method")
    msg_id = msg.get("id")

    if method == "initialize":
        _write(
            {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "swarmguard-fake-upstream", "version": "0.1"},
                },
            }
        )
        return

    if method == "notifications/initialized" or method == "initialized":
        return

    if method == "ping":
        if msg_id is not None:
            _write({"jsonrpc": "2.0", "id": msg_id, "result": {}})
        return

    if method == "tools/list":
        _write(
            {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "tools": [
                        {
                            "name": "read_file",
                            "description": "Read a local file path",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"path": {"type": "string"}},
                                "required": ["path"],
                            },
                        },
                        {
                            "name": "run_command",
                            "description": "Run a shell command string",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"command": {"type": "string"}},
                                "required": ["command"],
                            },
                        },
                    ]
                },
            }
        )
        return

    if method == "tools/call":
        params = msg.get("params") or {}
        name = str(params.get("name") or "")
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            arguments = {"_raw": arguments}
        # Proof surface: if we get here, the proxy failed to deny.
        _log_call(log_path, name, arguments)

        if name == "read_file":
            path = str(arguments.get("path") or "")
            try:
                text = Path(path).read_text(encoding="utf-8", errors="replace")[:4000]
            except OSError as exc:
                text = f"read_error: {exc}"
            _write(_ok_text(msg_id, text))
            return

        if name == "run_command":
            cmd = str(arguments.get("command") or "")
            # Intentionally does NOT execute — only acknowledges for the proof log.
            _write(_ok_text(msg_id, f"would_run: {cmd}"))
            return

        _write(
            {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [{"type": "text", "text": f"unknown tool: {name}"}],
                    "isError": True,
                },
            }
        )
        return

    if msg_id is not None:
        _write(
            {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Fake MCP upstream for SwarmGuard proof")
    parser.add_argument(
        "--log",
        type=Path,
        default=DEFAULT_LOG,
        help="Append every tools/call that reaches upstream",
    )
    args = parser.parse_args()
    # Clear log at start so harness can assert emptiness for denied calls
    if args.log.exists():
        args.log.unlink()
    args.log.write_text("", encoding="utf-8")

    while True:
        msg = _read()
        if msg is None:
            break
        try:
            _handle(msg, args.log)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"fake_upstream error: {exc}\n")
            sys.stderr.flush()
            msg_id = msg.get("id") if isinstance(msg, dict) else None
            if msg_id is not None:
                _write(
                    {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {"code": -32000, "message": str(exc)},
                    }
                )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
