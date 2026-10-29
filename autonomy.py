"""Autonomous detect → eliminate → report loop (safe demo quarantine only)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Callable

import psutil

from swarm_brain import SCENARIOS, run_scenario
from threat_bus import append_incident, raise_threat, reset_to_safe

StepFn = Callable[[str, dict[str, Any]], None]

# Rotating simulated agent events the patrol "hears" on the wire.
PATROL_EVENTS = ["steal_env", "mcp_exfil", "webpage_hijack"]

SUSPICIOUS_CMD_HINTS = (
    ".env",
    "id_rsa",
    "id_ed25519",
    "webhook",
    "ngrok",
    "exfil",
    "cat .env",
)


def scan_local_process_hints(limit: int = 8) -> list[dict[str, Any]]:
    """Read-only heuristic scan. Never kills real OS processes."""
    hits: list[dict[str, Any]] = []
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            info = proc.info
            cmdline = " ".join(info.get("cmdline") or []).lower()
            name = (info.get("name") or "").lower()
            blob = f"{name} {cmdline}"
            if not any(h in blob for h in SUSPICIOUS_CMD_HINTS):
                continue
            hits.append(
                {
                    "pid": info.get("pid"),
                    "name": info.get("name"),
                    "cmdline": " ".join((info.get("cmdline") or [])[:8]),
                    "matched": [h for h in SUSPICIOUS_CMD_HINTS if h in blob],
                }
            )
            if len(hits) >= limit:
                break
        except (psutil.Error, TypeError):
            continue
    return hits


def auto_eliminate(
    result: dict[str, Any],
    *,
    trigger: str = "manual_simulation",
    on_step: StepFn | None = None,
) -> dict[str, Any]:
    """Detect → freeze → quarantine without asking → return incident report."""
    top = result["top"]
    forensic = result.get("forensic") or {}

    if top.get("verdict") != "CRITICAL THREAT":
        # A SAFE result must never become a quarantine in the activity feed.
        incident = {
            "trigger": trigger,
            "scenario_id": result.get("scenario_id"),
            "title": result.get("title"),
            "threat_score": top.get("threat_score"),
            "verdict": top.get("verdict"),
            "agent": top.get("agent_triggered"),
            "headline": "No threat confirmed",
            "executive_summary": top.get("explanation") or "The analysis did not confirm a threat.",
            "action": "NO_THREAT",
            "action_detail": "No threat confirmed. No process or artifact was changed.",
            "simulation": True,
        }
        append_incident(incident)
        if on_step:
            on_step("auto:clear", incident)
        return incident

    if on_step:
        on_step("auto:threat", {"score": top.get("threat_score"), "agent": top.get("agent_triggered")})

    raise_threat(
        agent=top["agent_triggered"],
        threat_score=top["threat_score"],
        verdict=top["verdict"],
        summary=result.get("hud_summary") or top.get("explanation") or top.get("verdict"),
        pid=result["pid"],
        scenario=result["title"],
        guards=result["guards"],
        last_action="auto_freeze",
    )

    incident = {
        "trigger": trigger,
        "scenario_id": result.get("scenario_id"),
        "title": result.get("title"),
        "pid": result.get("pid"),
        "threat_score": top.get("threat_score"),
        "verdict": top.get("verdict"),
        "agent": top.get("agent_triggered"),
        "headline": forensic.get("headline"),
        "executive_summary": forensic.get("executive_summary"),
        "recommended_action": forensic.get("recommended_action"),
        "evidence_quotes": forensic.get("evidence_quotes") or [],
        "action": "AUTO_QUARANTINED",
        "simulation": True,
        "action_detail": (
            f"Simulated quarantine for demo PID {result.get('pid')}. "
            "No real process was stopped and no artifact was moved."
        ),
        "models_used": result.get("models_used"),
        "eliminated_at": datetime.now().strftime("%H:%M:%S"),
    }
    append_incident(incident)

    if on_step:
        on_step("auto:quarantine", {"pid": result.get("pid"), "title": result.get("title")})

    reset_to_safe(
        note=(
            f"AUTO-QUARANTINED · {forensic.get('headline') or result.get('title')} · "
            "Simulation only; no real process stopped."
        ),
        last_action="auto_quarantine",
    )
    return incident


def run_autonomous_scenario(
    scenario_id: str,
    *,
    trigger: str = "manual_simulation",
    on_step: StepFn | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    result = run_scenario(scenario_id, on_step=on_step)
    incident = auto_eliminate(result, trigger=trigger, on_step=on_step)
    return result, incident


def next_patrol_scenario(cursor: int) -> tuple[str, int]:
    scenario_id = PATROL_EVENTS[cursor % len(PATROL_EVENTS)]
    return scenario_id, cursor + 1


def describe_patrol_tick(cursor: int) -> dict[str, Any]:
    hints = scan_local_process_hints()
    scenario_id = PATROL_EVENTS[cursor % len(PATROL_EVENTS)]
    return {
        "cursor": cursor,
        "next_scenario": scenario_id,
        "next_title": SCENARIOS[scenario_id]["title"],
        "local_hints": hints,
        "hint_count": len(hints),
    }
