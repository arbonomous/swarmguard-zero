#!/usr/bin/env python3
"""SwarmGuard IDE policy gate — Cursor + Claude Code PreToolUse / shell / read / MCP.

Reads hook JSON on stdin, evaluates via policy (no Muse / Meta API), writes a
permission decision on stdout. Fail-closed on empty/invalid input when possible.

DENY → permission deny + threat_bus incident (trigger=ide_hook, kind=policy_deny)
ALLOW → permission allow

No SIGKILL. Never imports swarm_brain / Model API.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from policy import (  # noqa: E402
    Verdict,
    evaluate_ide_command,
    evaluate_ide_read,
    evaluate_ide_tool_call,
    enforce_enabled,
)
from threat_bus import append_incident  # noqa: E402


def _parse_tool_input(raw: Any) -> dict[str, Any]:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return {}
        try:
            parsed = json.loads(text)
            return parsed if isinstance(parsed, dict) else {"_raw": parsed}
        except json.JSONDecodeError:
            return {"_raw": raw}
    return {"_raw": raw}


def _event_name(payload: dict[str, Any]) -> str:
    return str(
        payload.get("hook_event_name")
        or payload.get("hookEventName")
        or ""
    ).strip()


def _decide(payload: dict[str, Any]) -> tuple[str, dict[str, Any], Verdict, str]:
    """Return (tool_name, arguments, verdict, event)."""
    event = _event_name(payload)
    event_l = event.lower()
    has_tool = "tool_name" in payload or "toolName" in payload

    # Cursor beforeShellExecution — command at top level
    if event_l == "beforeshellexecution" or (
        not has_tool and "file_path" not in payload and isinstance(payload.get("command"), str)
    ):
        cmd = str(payload.get("command") or "")
        return (
            "Shell",
            {"command": cmd},
            evaluate_ide_command(cmd),
            event or "beforeShellExecution",
        )

    # Cursor beforeReadFile / beforeTabFileRead
    if event_l in {"beforereadfile", "beforetabfileread"} or (
        not has_tool and isinstance(payload.get("file_path"), str)
    ):
        path = str(payload.get("file_path") or "")
        return "Read", {"path": path}, evaluate_ide_read(path), event or "beforeReadFile"

    # Cursor beforeMCPExecution
    if event_l == "beforemcpexecution":
        tool_name = str(payload.get("tool_name") or payload.get("toolName") or "mcp_tool")
        arguments = _parse_tool_input(payload.get("tool_input") or payload.get("toolInput"))
        return tool_name, arguments, evaluate_ide_tool_call(tool_name, arguments), event

    # Generic preToolUse / PreToolUse (Cursor + Claude Code)
    tool_name = str(payload.get("tool_name") or payload.get("toolName") or "")
    arguments = _parse_tool_input(payload.get("tool_input") or payload.get("toolInput"))

    if not tool_name:
        return (
            "unknown",
            {},
            Verdict(
                "deny",
                "deny_ide_unmapped",
                "IDE hook: unmapped tool payload (fail-closed)",
                "tool:unknown",
                threat_id="ide_bypass",
            ),
            event or "preToolUse",
        )

    return tool_name, arguments, evaluate_ide_tool_call(tool_name, arguments), event or "preToolUse"


def _log_deny(
    *,
    tool_name: str,
    arguments: dict[str, Any],
    verdict: Verdict,
    event: str,
) -> None:
    # Never persist file contents from beforeReadFile
    safe_args = {k: v for k, v in arguments.items() if k != "content"}
    append_incident(
        {
            "kind": "policy_deny",
            "source": "ide_hook",
            "trigger": "ide_hook",
            "title": f"IDE hook denied `{tool_name}`",
            "headline": f"Blocked IDE tool: {tool_name}",
            "executive_summary": verdict.reason,
            "action": "POLICY_DENY",
            "action_detail": (
                f"SwarmGuard IDE hook denied `{tool_name}` via rule `{verdict.rule}` "
                f"(event={event or 'preToolUse'}). No SIGKILL; policy deny only."
            ),
            "tool_name": tool_name,
            "arguments": safe_args,
            "hook_event": event,
            "rule": verdict.rule,
            "threat_id": verdict.threat_id,
            "verdict": "DENIED",
            "threat_score": 100,
            "agent": "IDE Hook",
            "eliminated_at": datetime.now().strftime("%H:%M:%S"),
            "enforce": enforce_enabled(),
        }
    )


def _response(permission: str, reason: str, *, event: str = "PreToolUse") -> dict[str, Any]:
    """Emit Cursor-native + Claude Code-compatible decision fields."""
    # Cursor uses camelCase event names; Claude uses PascalCase PreToolUse.
    claude_event = "PreToolUse"
    if event:
        if event[:1].isupper() or event in {"PreToolUse", "PermissionRequest"}:
            claude_event = event if event[0].isupper() else "PreToolUse"
        else:
            # map beforeShellExecution etc. → still PreToolUse-shaped for Claude nested output
            claude_event = "PreToolUse"

    out: dict[str, Any] = {
        "permission": permission,
        "user_message": reason if permission == "deny" else "",
        "agent_message": reason if permission == "deny" else "",
        "hookSpecificOutput": {
            "hookEventName": claude_event,
            "permissionDecision": permission,
            "permissionDecisionReason": reason,
        },
    }
    if permission == "allow":
        # Keep payloads small on allow
        out.pop("user_message", None)
        out["agent_message"] = ""
    return out


def main() -> int:
    raw = sys.stdin.read()
    if not raw.strip():
        reason = "SwarmGuard IDE hook: empty payload (fail-closed)"
        _log_deny(
            tool_name="unknown",
            arguments={},
            verdict=Verdict("deny", "deny_ide_empty", reason, "tool:unknown", "ide_bypass"),
            event="preToolUse",
        )
        json.dump(_response("deny", reason), sys.stdout)
        sys.stdout.write("\n")
        return 0

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        reason = "SwarmGuard IDE hook: invalid JSON payload (fail-closed)"
        _log_deny(
            tool_name="unknown",
            arguments={},
            verdict=Verdict("deny", "deny_ide_bad_json", reason, "tool:unknown", "ide_bypass"),
            event="preToolUse",
        )
        json.dump(_response("deny", reason), sys.stdout)
        sys.stdout.write("\n")
        return 0

    if not isinstance(payload, dict):
        reason = "SwarmGuard IDE hook: non-object payload (fail-closed)"
        json.dump(_response("deny", reason), sys.stdout)
        sys.stdout.write("\n")
        return 0

    tool_name, arguments, verdict, event = _decide(payload)
    if verdict.decision == "deny":
        _log_deny(tool_name=tool_name, arguments=arguments, verdict=verdict, event=event)
        reason = f"[SwarmGuard] DENIED — {verdict.reason} (rule={verdict.rule})"
        json.dump(_response("deny", reason, event=event or "PreToolUse"), sys.stdout)
        sys.stdout.write("\n")
        return 0

    json.dump(_response("allow", verdict.reason, event=event or "PreToolUse"), sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # fail-closed: deny on unexpected errors
        reason = f"[SwarmGuard] IDE hook error (fail-closed): {exc}"
        try:
            append_incident(
                {
                    "kind": "policy_deny",
                    "source": "ide_hook",
                    "trigger": "ide_hook",
                    "title": "IDE hook fail-closed error",
                    "headline": "Blocked IDE tool (hook error)",
                    "executive_summary": reason,
                    "action": "POLICY_DENY",
                    "action_detail": reason,
                    "rule": "deny_ide_exception",
                    "threat_id": "ide_bypass",
                    "verdict": "DENIED",
                    "threat_score": 100,
                    "agent": "IDE Hook",
                    "eliminated_at": datetime.now().strftime("%H:%M:%S"),
                }
            )
        except Exception:
            pass
        try:
            json.dump(_response("deny", reason), sys.stdout)
            sys.stdout.write("\n")
        except Exception:
            # Last resort: exit 2 = block (Cursor / Claude)
            print(reason, file=sys.stderr)
            raise SystemExit(2)
        raise SystemExit(0)
