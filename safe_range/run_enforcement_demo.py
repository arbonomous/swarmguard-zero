#!/usr/bin/env python3
"""Prove SwarmGuard policy blocks the AI-agent attack catalog (no Muse tokens)."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ["SWARMGUARD_ENFORCE"] = "1"

from policy import enforce_enabled, probe_catalog_enforcement  # noqa: E402
from threat_model import summary_counts  # noqa: E402


def main() -> int:
    print(f"SWARMGUARD_ENFORCE={enforce_enabled()}")
    counts = summary_counts()
    print(
        f"Catalog: {counts['total']} threats · "
        f"active defenses {counts['active']} · planned {counts['planned']}"
    )
    print("--- probes ---")
    probes = probe_catalog_enforcement()
    failed = []
    for p in probes:
        mark = "DENY" if p["ok"] else "FAIL"
        print(f"[{mark}] {p['threat_id']:16}  {p['rule']}")
        if not p["ok"]:
            failed.append(p)

    # Live rogue agent must not exfil under enforce
    import subprocess

    env = os.environ.copy()
    env["SWARMGUARD_ENFORCE"] = "1"
    rogue = subprocess.run(
        [sys.executable, str(ROOT / "safe_range" / "rogue_agent.py")],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
        check=False,
    )
    try:
        payload = json.loads(rogue.stdout.strip())
    except json.JSONDecodeError:
        payload = {"raw": rogue.stdout[-400:]}
    blocked = bool(payload.get("blocked")) and not payload.get("exfil_sent")
    print("--- rogue ---")
    print(f"[{'PASS' if blocked else 'FAIL'}] rogue_under_enforce exfil_sent={payload.get('exfil_sent')}")

    if failed or not blocked:
        print("Enforcement demo FAILED", file=sys.stderr)
        return 1
    print(f"Enforcement demo PASSED — {len(probes)} catalog probes denied; rogue blocked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
