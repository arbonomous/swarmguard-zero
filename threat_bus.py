"""Shared threat state bus + autonomous incident log."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
STATE_PATH = ROOT / "threat_state.json"
INCIDENTS_PATH = ROOT / "incidents.jsonl"
GATE_STATUS_PATH = ROOT / "mcp_gate_status.json"

# Heartbeat is "fresh" if updated within this many seconds.
GATE_HEARTBEAT_FRESH_S = 90

SAFE_STATE: dict[str, Any] = {
    "status": "ARMED",
    "threat_score": 0,
    "verdict": "SAFE",
    "agent_triggered": None,
    "summary": "Autonomous swarm armed. Monitoring agent activity.",
    "pid": None,
    "scenario": None,
    "frozen": False,
    "mode": "autonomous",
    "last_action": None,
    "updated_at": None,
    "guards": {
        "Bloodhound": {"status": "PATROLLING", "last_score": 0},
        "Wiretap": {"status": "PATROLLING", "last_score": 0},
        "Overwatch": {"status": "PATROLLING", "last_score": 0},
    },
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_state(payload: dict[str, Any]) -> dict[str, Any]:
    data = {**SAFE_STATE, **payload, "updated_at": _utc_now()}
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(STATE_PATH.parent), prefix=".threat_", suffix=".json"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, STATE_PATH)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return data


def read_state() -> dict[str, Any]:
    if not STATE_PATH.exists():
        return write_state(SAFE_STATE.copy())
    try:
        with STATE_PATH.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return write_state(SAFE_STATE.copy())
        return {**SAFE_STATE, **data}
    except (json.JSONDecodeError, OSError):
        return write_state(SAFE_STATE.copy())


def reset_to_safe(note: str | None = None, last_action: str | None = None) -> dict[str, Any]:
    payload = SAFE_STATE.copy()
    if note:
        payload["summary"] = note
    if last_action:
        payload["last_action"] = last_action
    return write_state(payload)


def raise_threat(
    *,
    agent: str,
    threat_score: int,
    verdict: str,
    summary: str,
    pid: int | None,
    scenario: str,
    guards: dict[str, Any] | None = None,
    last_action: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "status": "CRITICAL",
        "threat_score": int(threat_score),
        "verdict": verdict,
        "agent_triggered": agent,
        "summary": summary,
        "pid": pid,
        "scenario": scenario,
        "frozen": True,
        "last_action": last_action or "threat_detected",
    }
    if guards:
        payload["guards"] = guards
    return write_state(payload)


def append_incident(incident: dict[str, Any]) -> dict[str, Any]:
    row = {**incident, "logged_at": _utc_now()}
    with INCIDENTS_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")
    return row


def read_incidents(limit: int = 12) -> list[dict[str, Any]]:
    if not INCIDENTS_PATH.exists():
        return []
    rows: list[dict[str, Any]] = []
    with INCIDENTS_PATH.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return list(reversed(rows[-limit:]))


def write_gate_heartbeat(payload: dict[str, Any]) -> dict[str, Any]:
    """MCP proxy heartbeat so the protector UI can show 'gate wrapping tools'."""
    data = {**payload, "updated_at": _utc_now()}
    GATE_STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(GATE_STATUS_PATH.parent), prefix=".mcp_gate_", suffix=".json"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, GATE_STATUS_PATH)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return data


def read_gate_status() -> dict[str, Any]:
    """Return MCP gate status. `wrapping` is True when heartbeat is fresh and active."""
    empty: dict[str, Any] = {
        "active": False,
        "wrapping": False,
        "denied": 0,
        "allowed": 0,
        "note": "no proxy heartbeat yet",
    }
    if not GATE_STATUS_PATH.exists():
        return empty
    try:
        with GATE_STATUS_PATH.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return empty
    except (json.JSONDecodeError, OSError):
        return empty

    wrapping = False
    updated = data.get("updated_at")
    if data.get("active") and updated:
        try:
            # fromisoformat handles +00:00
            ts = datetime.fromisoformat(str(updated).replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - ts).total_seconds()
            wrapping = age <= GATE_HEARTBEAT_FRESH_S
        except (TypeError, ValueError):
            wrapping = False
    return {**empty, **data, "wrapping": wrapping}
