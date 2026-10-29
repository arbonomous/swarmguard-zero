#!/usr/bin/env python3
"""Feed safe-range telemetry + artifact into SwarmGuard (Meta stack).

Does not SIGKILL anything. Optionally writes an incident via auto_eliminate
using the existing demo bus (fake PID), after a real Muse verdict.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from autonomy import auto_eliminate  # noqa: E402
from swarm_brain import (  # noqa: E402
    analyze_with_guard,
    segment_with_sam,
    synthesize_forensic_report,
)

SAFE = Path(__file__).resolve().parent
VICTIM_README = SAFE / "victim_project" / "README.md"
TELEMETRY = SAFE / "last_telemetry.json"
ARTIFACT_PNG = SAFE / "artifact_readme.png"
REPORT_OUT = SAFE / "last_probe_report.json"


def _font(size: int = 16):
    try:
        return ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", size)
    except OSError:
        return ImageFont.load_default()


def render_readme_artifact(readme: Path, out: Path) -> Path:
    """Render the real victim README (including camouflaged block) to a PNG for Overwatch/SAM."""
    text = readme.read_text(encoding="utf-8")
    lines = text.splitlines() or [""]
    font = _font(15)
    small = _font(13)
    width, line_h, pad = 720, 22, 24
    height = pad * 2 + line_h * (len(lines) + 2)
    img = Image.new("RGB", (width, max(height, 360)), "#0f172a")
    draw = ImageDraw.Draw(img)
    draw.text((pad, 12), "safe_range/victim_project/README.md", fill="#94a3b8", font=small)
    y = 40
    for line in lines:
        # Camouflage the injection paragraph like white-on-near-white (Unit 42 class).
        if "IGNORE PREVIOUS" in line or "127.0.0.1:8765" in line or "maintenance mode" in line:
            draw.rectangle([pad - 4, y - 2, width - pad + 4, y + line_h], fill="#f8fafc")
            draw.text((pad, y), line[:110], fill="#f1f5f9", font=font)
        else:
            draw.text((pad, y), line[:110], fill="#e2e8f0", font=font)
        y += line_h
    out.parent.mkdir(parents=True, exist_ok=True)
    img.save(out)
    return out


def main() -> int:
    if not TELEMETRY.exists():
        print("Run rogue_agent.py first so last_telemetry.json exists.", file=sys.stderr)
        return 1
    if not VICTIM_README.exists():
        print(f"Missing {VICTIM_README}", file=sys.stderr)
        return 1

    telemetry = json.loads(TELEMETRY.read_text(encoding="utf-8"))
    evidence = telemetry.get("evidence") or ""
    artifact = render_readme_artifact(VICTIM_README, ARTIFACT_PNG)

    steps: list[str] = []

    def on_step(stage: str, payload: dict) -> None:
        steps.append(stage)
        print(f"  {stage}")

    print("== Overwatch (vision on real safe-range README) ==")
    overwatch = analyze_with_guard(
        "Overwatch", evidence, telemetry.get("title", "safe_range"), artifact, on_step=on_step
    )
    print(
        f"  verdict={overwatch.get('verdict')} score={overwatch.get('threat_score')} "
        f"structured={overwatch.get('structured')} source={overwatch.get('source')}"
    )

    print("== Bloodhound ==")
    bloodhound = analyze_with_guard(
        "Bloodhound", evidence, telemetry.get("title", "safe_range"), None, on_step=on_step
    )
    print(
        f"  verdict={bloodhound.get('verdict')} score={bloodhound.get('threat_score')} "
        f"source={bloodhound.get('source')}"
    )

    print("== Wiretap ==")
    wiretap = analyze_with_guard(
        "Wiretap", evidence, telemetry.get("title", "safe_range"), None, on_step=on_step
    )
    print(
        f"  verdict={wiretap.get('verdict')} score={wiretap.get('threat_score')} "
        f"source={wiretap.get('source')}"
    )

    reports = sorted(
        [overwatch, bloodhound, wiretap],
        key=lambda r: int(r.get("threat_score") or 0),
        reverse=True,
    )
    print("== Wonder forensics ==")
    forensic = synthesize_forensic_report(
        scenario=telemetry.get("title", "safe_range"),
        evidence=evidence,
        reports=reports,
        pid=48219,
        image_path=artifact,
        on_step=on_step,
    )
    print(f"  headline={forensic.get('headline')}")
    print(f"  quotes={forensic.get('evidence_quotes')}")

    print("== SAM isolation ==")
    sam = segment_with_sam(
        artifact,
        concepts=["white rectangle", "hidden text", "text"],
        fallback_boxes=[{"label": "injection block", "xyxy": [20, 80, 700, 200]}],
        on_step=on_step,
    )
    print(f"  boxes={len(sam.get('boxes') or [])} source={sam.get('source')}")

    top = reports[0]
    result = {
        "scenario_id": "safe_range_live",
        "title": telemetry.get("title"),
        "pid": 48219,
        "top": top,
        "guards": reports,
        "forensic": forensic,
        "hud_summary": forensic.get("executive_summary") or top.get("explanation"),
        "models_used": {
            "guard": overwatch.get("model"),
            "forensic": forensic.get("model"),
            "sam": sam.get("model"),
        },
        "boxes": sam.get("boxes") or [],
        "artifact": str(artifact),
        "telemetry_file": str(TELEMETRY),
    }

    incident = None
    if str(top.get("verdict", "")).upper().startswith("CRITICAL") or int(
        top.get("threat_score") or 0
    ) >= 80:
        print("== Auto-quarantine (demo bus only; no SIGKILL) ==")
        incident = auto_eliminate(result, trigger="safe_range_live_probe", on_step=on_step)
    else:
        print("== No quarantine (verdict not CRITICAL) ==")

    out = {
        "result": {
            "verdict": top.get("verdict"),
            "threat_score": top.get("threat_score"),
            "headline": forensic.get("headline"),
            "evidence_quotes": forensic.get("evidence_quotes"),
            "sam_boxes": len(sam.get("boxes") or []),
            "sam_source": sam.get("source"),
            "artifact": str(artifact),
        },
        "incident_action": (incident or {}).get("action"),
        "steps": steps,
    }
    REPORT_OUT.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps(out["result"], indent=2))
    print(f"Wrote {REPORT_OUT}")
    return 0 if str(top.get("verdict")).upper().startswith("CRITICAL") else 5


if __name__ == "__main__":
    raise SystemExit(main())
