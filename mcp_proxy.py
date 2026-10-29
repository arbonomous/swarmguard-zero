#!/usr/bin/env python3
"""SwarmGuard MCP stdio policy proxy — deny before upstream, log to threat_bus.

Usage:
  python mcp_proxy.py -- <upstream-cmd> [args...]
  python -m swarmguard_mcp -- <upstream-cmd> [args...]

Env:
  SWARMGUARD_ENFORCE=1                 fail-closed policy (default on via policy.py)
  SWARMGUARD_MUSE_ON_AMBIGUOUS=0       optional low-cost Spark on ambiguous results / poisoned list
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MCP_MESSAGE_LIMIT = 4 * 1024 * 1024

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from policy import evaluate_tool_call, enforce_enabled  # noqa: E402
from threat_bus import append_incident, write_gate_heartbeat  # noqa: E402

# Lightweight injection / secret-shape heuristics (no API by default).
_INJECTION_RE = re.compile(
    r"("
    r"ignore\s+(all\s+)?(previous|prior)\s+instructions|"
    r"do\s+not\s+tell\s+the\s+user|"
    r"system\s*:\s*|"
    r"<\!--\s*system|"
    r"exfiltrat|"
    r"paste\s+(keys|secrets|seed)|"
    r"cat\s+\.env|"
    r"curl\s+.*webhook|"
    r"send\s+(secrets|credentials)\s+to"
    r")",
    re.I,
)
_SECRET_SHAPE_RE = re.compile(
    r"("
    r"AKIA[0-9A-Z]{16}|"
    r"-----BEGIN (RSA |OPENSSH )?PRIVATE KEY-----|"
    r"sk-[a-zA-Z0-9]{20,}|"
    r"ghp_[a-zA-Z0-9]{36}|"
    r"xox[baprs]-[0-9a-zA-Z-]{10,}"
    r")",
)


def muse_on_ambiguous() -> bool:
    return os.getenv("SWARMGUARD_MUSE_ON_AMBIGUOUS", "0").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _encode_message(obj: dict[str, Any]) -> bytes:
    return (json.dumps(obj, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


async def _read_message(reader: asyncio.StreamReader) -> dict[str, Any] | None:
    """Read standard newline-delimited MCP stdio JSON-RPC, not LSP frames."""
    line = await reader.readline()
    if not line:
        return None
    message = json.loads(line.decode("utf-8"))
    if not isinstance(message, dict):
        raise ValueError("MCP stdio message must be a JSON object")
    return message


def _tool_error_result(msg_id: Any, text: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "result": {
            "content": [{"type": "text", "text": text}],
            "isError": True,
        },
    }


def _log_policy_deny(
    *,
    tool_name: str,
    arguments: dict[str, Any],
    verdict: Any,
    source: str = "mcp_proxy",
) -> None:
    append_incident(
        {
            "kind": "policy_deny",
            "source": source,
            "trigger": "mcp_tools_call",
            "title": f"MCP gate denied `{tool_name}`",
            "headline": f"Blocked tool call: {tool_name}",
            "executive_summary": verdict.reason,
            "action": "POLICY_DENY",
            "action_detail": (
                f"SwarmGuard MCP proxy denied `{tool_name}` via rule `{verdict.rule}` "
                f"before the upstream server saw the call."
            ),
            "tool_name": tool_name,
            "arguments": arguments,
            "rule": verdict.rule,
            "threat_id": verdict.threat_id,
            "verdict": "DENIED",
            "threat_score": 100,
            "agent": "MCP Gate",
            "eliminated_at": datetime.now().strftime("%H:%M:%S"),
        }
    )


def _log_muse_quarantine(
    *,
    tool_name: str,
    reason: str,
    spark: dict[str, Any] | None = None,
) -> None:
    spark = spark or {}
    append_incident(
        {
            "kind": "muse_quarantine",
            "source": "mcp_proxy",
            "trigger": "mcp_ambiguous",
            "title": f"Muse flagged `{tool_name}`",
            "headline": spark.get("explanation") or f"Spark critical on {tool_name}",
            "executive_summary": reason,
            "action": "MUSE_QUARANTINE",
            "action_detail": (
                f"Optional Muse path blocked `{tool_name}` after ambiguous/poisoned content. "
                f"Wonder one-liner: {spark.get('explanation', reason)[:240]}"
            ),
            "tool_name": tool_name,
            "threat_score": spark.get("threat_score", 90),
            "verdict": spark.get("verdict", "CRITICAL THREAT"),
            "agent": spark.get("agent_triggered") or "Overwatch",
            "models_used": {"guard": spark.get("model")},
            "eliminated_at": datetime.now().strftime("%H:%M:%S"),
        }
    )


def _looks_ambiguous(text: str) -> bool:
    if not text:
        return False
    return bool(_INJECTION_RE.search(text) or _SECRET_SHAPE_RE.search(text))


def _extract_text_blob(obj: Any) -> str:
    if obj is None:
        return ""
    if isinstance(obj, str):
        return obj
    try:
        return json.dumps(obj, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(obj)


async def _maybe_muse_spark(evidence: str, scenario: str) -> dict[str, Any] | None:
    """One low-cost Spark call. Never Wonder-high. No-op if flag off or API missing."""
    if not muse_on_ambiguous():
        return None
    try:
        from swarm_brain import analyze_with_guard

        # Prefer Overwatch for injection-shaped text; Bloodhound for secret shapes.
        agent = "Overwatch" if _INJECTION_RE.search(evidence) else "Bloodhound"
        return await asyncio.to_thread(
            analyze_with_guard,
            agent,
            evidence[:4000],
            scenario,
            None,
            None,
        )
    except Exception as exc:  # noqa: BLE001
        return {
            "threat_score": 85 if _looks_ambiguous(evidence) else 0,
            "verdict": "CRITICAL THREAT" if _looks_ambiguous(evidence) else "SAFE",
            "agent_triggered": "heuristic",
            "explanation": f"Local heuristic only (Spark unavailable: {type(exc).__name__}).",
            "model": "offline-heuristic",
        }


def _scan_tools_list(result_obj: dict[str, Any]) -> list[str]:
    """Return tool names whose descriptions look poisoned."""
    poisoned: list[str] = []
    tools = (result_obj.get("result") or {}).get("tools") or []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        blob = f"{tool.get('name', '')} {tool.get('description', '')}"
        if _looks_ambiguous(blob):
            poisoned.append(str(tool.get("name") or "?"))
    return poisoned


class McpProxy:
    def __init__(self, upstream_cmd: list[str]) -> None:
        self.upstream_cmd = upstream_cmd
        self._proc: asyncio.subprocess.Process | None = None
        self._up_writer: asyncio.StreamWriter | None = None
        self._pending: dict[Any, dict[str, Any]] = {}
        self._client_writer_lock = asyncio.Lock()
        self._upstream_writer_lock = asyncio.Lock()
        self._denied = 0
        self._allowed = 0
        self._started_at = time.time()

    async def _write_client(self, obj: dict[str, Any]) -> None:
        data = _encode_message(obj)
        async with self._client_writer_lock:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()

    async def _write_upstream(self, obj: dict[str, Any]) -> None:
        assert self._proc and self._proc.stdin
        data = _encode_message(obj)
        async with self._upstream_writer_lock:
            self._proc.stdin.write(data)
            await self._proc.stdin.drain()

    def _heartbeat(self, note: str = "") -> None:
        write_gate_heartbeat(
            {
                "active": True,
                "pid": os.getpid(),
                "upstream": " ".join(self.upstream_cmd)[:200],
                "denied": self._denied,
                "allowed": self._allowed,
                "enforce": enforce_enabled(),
                "muse_on_ambiguous": muse_on_ambiguous(),
                "note": note or "wrapping tools",
                "uptime_s": round(time.time() - self._started_at, 1),
            }
        )

    async def _handle_tools_call(self, msg: dict[str, Any]) -> bool:
        """Return True if handled (do not forward)."""
        params = msg.get("params") or {}
        tool_name = str(params.get("name") or "")
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            arguments = {"_raw": arguments}

        verdict = evaluate_tool_call(tool_name, arguments)
        if verdict.decision == "deny":
            self._denied += 1
            _log_policy_deny(tool_name=tool_name, arguments=arguments, verdict=verdict)
            self._heartbeat(f"denied {tool_name}")
            await self._write_client(
                _tool_error_result(
                    msg.get("id"),
                    f"[SwarmGuard] DENIED — {verdict.reason} (rule={verdict.rule})",
                )
            )
            return True

        # ALLOW — track so we can optionally scan the result later
        self._allowed += 1
        if msg.get("id") is not None:
            self._pending[msg["id"]] = {
                "method": "tools/call",
                "tool_name": tool_name,
                "arguments": arguments,
            }
        self._heartbeat(f"allowed {tool_name}")
        return False

    async def _handle_tools_list_result(self, msg: dict[str, Any], meta: dict[str, Any]) -> None:
        poisoned = _scan_tools_list(msg)
        if not poisoned:
            return
        evidence = _extract_text_blob((msg.get("result") or {}).get("tools"))
        if not muse_on_ambiguous():
            # Heuristic-only note in heartbeat; do not rewrite tools/list by default
            self._heartbeat(f"poisoned tools/list: {', '.join(poisoned[:5])}")
            return
        spark = await _maybe_muse_spark(
            f"Poisoned MCP tools/list descriptions for: {poisoned}\n{evidence[:2000]}",
            "mcp_tools_list_poison",
        )
        if spark and str(spark.get("verdict", "")).upper().startswith("CRITICAL"):
            _log_muse_quarantine(
                tool_name="tools/list",
                reason=f"Poisoned tool descriptions: {', '.join(poisoned)}",
                spark=spark,
            )
            self._heartbeat("muse critical on tools/list")

    async def _handle_tools_call_result(self, msg: dict[str, Any], meta: dict[str, Any]) -> bool:
        """Optionally intercept result. Return True if replaced (already written)."""
        result = msg.get("result") or {}
        blob = _extract_text_blob(result)
        tool_name = str(meta.get("tool_name") or "?")

        if not _looks_ambiguous(blob):
            return False

        if not muse_on_ambiguous():
            # Lightweight result scan: strip/block obvious secret shapes even without Muse
            if _SECRET_SHAPE_RE.search(blob) and enforce_enabled():
                self._denied += 1
                append_incident(
                    {
                        "kind": "policy_deny",
                        "source": "mcp_proxy",
                        "trigger": "mcp_result_scan",
                        "title": f"MCP gate scrubbed `{tool_name}` result",
                        "headline": f"Blocked secret-shaped tool result: {tool_name}",
                        "executive_summary": "Tool result contained secret-like material; not returned to agent.",
                        "action": "POLICY_DENY",
                        "action_detail": (
                            f"Post-call scan blocked `{tool_name}` result (secret shape) "
                            "without forwarding full content to the agent."
                        ),
                        "tool_name": tool_name,
                        "rule": "deny_secret_result",
                        "threat_id": "secret_files",
                        "verdict": "DENIED",
                        "threat_score": 95,
                        "agent": "MCP Gate",
                        "eliminated_at": datetime.now().strftime("%H:%M:%S"),
                    }
                )
                await self._write_client(
                    _tool_error_result(
                        msg.get("id"),
                        "[SwarmGuard] DENIED — tool result looked like secrets (result scan)",
                    )
                )
                self._heartbeat(f"scrubbed result {tool_name}")
                return True
            return False

        spark = await _maybe_muse_spark(
            f"Tool `{tool_name}` result:\n{blob[:3000]}",
            "mcp_tool_result_ambiguous",
        )
        if spark and str(spark.get("verdict", "")).upper().startswith("CRITICAL"):
            self._denied += 1
            _log_muse_quarantine(
                tool_name=tool_name,
                reason="Ambiguous/poisoned tool result flagged by Spark",
                spark=spark,
            )
            await self._write_client(
                _tool_error_result(
                    msg.get("id"),
                    f"[SwarmGuard] DENIED by Muse — {spark.get('explanation', 'critical')[:300]}",
                )
            )
            self._heartbeat(f"muse denied result {tool_name}")
            return True
        return False

    async def _client_to_upstream(self, reader: asyncio.StreamReader) -> None:
        while True:
            msg = await _read_message(reader)
            if msg is None:
                break
            method = msg.get("method")
            if method == "tools/call":
                handled = await self._handle_tools_call(msg)
                if handled:
                    continue
            elif method == "tools/list" and msg.get("id") is not None:
                self._pending[msg["id"]] = {"method": "tools/list"}
            await self._write_upstream(msg)
            self._heartbeat()

    async def _upstream_to_client(self, reader: asyncio.StreamReader) -> None:
        while True:
            msg = await _read_message(reader)
            if msg is None:
                break
            msg_id = msg.get("id")
            meta = self._pending.pop(msg_id, None) if msg_id is not None else None
            if meta and meta.get("method") == "tools/call" and "result" in msg:
                replaced = await self._handle_tools_call_result(msg, meta)
                if replaced:
                    continue
            if meta and meta.get("method") == "tools/list" and "result" in msg:
                await self._handle_tools_list_result(msg, meta)
            await self._write_client(msg)
            self._heartbeat()

    async def _pump_stderr(self, reader: asyncio.StreamReader) -> None:
        while True:
            line = await reader.readline()
            if not line:
                break
            sys.stderr.buffer.write(line)
            sys.stderr.buffer.flush()

    async def _keep_heartbeat(self) -> None:
        while True:
            await asyncio.sleep(30)
            self._heartbeat()

    async def run(self) -> int:
        self._heartbeat("starting")
        self._proc = await asyncio.create_subprocess_exec(
            *self.upstream_cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=MCP_MESSAGE_LIMIT,
        )
        assert self._proc.stdin and self._proc.stdout and self._proc.stderr

        # Wrap client stdin as a StreamReader
        loop = asyncio.get_running_loop()
        client_reader = asyncio.StreamReader(limit=MCP_MESSAGE_LIMIT)
        protocol = asyncio.StreamReaderProtocol(client_reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)

        heartbeat_task = asyncio.create_task(self._keep_heartbeat(), name="heartbeat")
        stderr_task = asyncio.create_task(self._pump_stderr(self._proc.stderr), name="err")
        tasks = [
            asyncio.create_task(self._client_to_upstream(client_reader), name="c2u"),
            asyncio.create_task(self._upstream_to_client(self._proc.stdout), name="u2c"),
        ]
        self._heartbeat("wrapping tools")

        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        # stderr EOF is not the end of the protocol session. Retrieve pump
        # exceptions so malformed input cannot silently appear successful.
        failed = any(t.exception() is not None for t in done if not t.cancelled())
        for t in pending | {heartbeat_task, stderr_task}:
            t.cancel()
        await asyncio.gather(*pending, heartbeat_task, stderr_task, return_exceptions=True)
        # Prefer cooperative shutdown — never SIGKILL
        if self._proc.returncode is None:
            try:
                self._proc.stdin.close()
            except Exception:
                pass
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=3.0)
            except (asyncio.TimeoutError, ProcessLookupError):
                self._proc.terminate()
                try:
                    await asyncio.wait_for(self._proc.wait(), timeout=2.0)
                except (asyncio.TimeoutError, ProcessLookupError):
                    pass  # still no SIGKILL
        write_gate_heartbeat(
            {
                "active": False,
                "pid": os.getpid(),
                "upstream": " ".join(self.upstream_cmd)[:200],
                "denied": self._denied,
                "allowed": self._allowed,
                "note": "proxy stopped",
                "stopped_at": _utc_now(),
            }
        )
        return 1 if failed else (self._proc.returncode or 0)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SwarmGuard MCP stdio policy proxy",
        epilog="Separate upstream command with --  e.g. python mcp_proxy.py -- python fake_mcp.py",
    )
    parser.add_argument(
        "upstream",
        nargs=argparse.REMAINDER,
        help="Upstream MCP server command (prefix with --)",
    )
    ns = parser.parse_args(argv)
    cmd = list(ns.upstream or [])
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        parser.error("upstream command required after --")
    ns.upstream_cmd = cmd
    return ns


def main(argv: list[str] | None = None) -> int:
    ns = parse_args(argv)
    try:
        return asyncio.run(McpProxy(ns.upstream_cmd).run())
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
