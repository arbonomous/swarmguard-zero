#!/usr/bin/env python3
"""Generate SwarmGuard brand assets with Muse Image (Meta Model API).

Usage:
  source .venv/bin/activate
  python tools/generate_brand_muse.py

Writes under assets/brand/. ~$0.01 per image. Does not print API keys.
"""

from __future__ import annotations

import base64
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "assets" / "brand"
OUT.mkdir(parents=True, exist_ok=True)

load_dotenv(ROOT / ".env")
KEY = os.getenv("MODEL_API_KEY") or os.getenv("META_API_KEY") or ""
BASE = os.getenv("META_BASE_URL", "https://api.meta.ai/v1").rstrip("/")
MODEL = os.getenv("META_IMAGE_MODEL", "muse-image-1.0")


PROMPTS = {
    "swarmguard-mark.png": (
        "App icon logo mark for a cybersecurity product named SwarmGuard. "
        "Minimal flat vector style: a modern heraldic shield silhouette filled with a subtle "
        "network of small nodes and thin edges (a swarm lattice), not a bug or insect. "
        "Primary color signal green #3DD68C on deep ink background #0A0D12. "
        "No text, no letters, no watermark, no purple, no neon glow, no 3D chrome, "
        "no emoji. Centered square composition, generous padding, crisp edges, "
        "readable when scaled to 64px."
    ),
    "swarmguard-icon-menu.png": (
        "macOS menu bar status icon only. Tiny monochrome-friendly mark: simplified shield "
        "with 3–5 tiny node dots inside, flat vector, high contrast. "
        "Signal green #3DD68C glyph on fully transparent background. "
        "No text, no drop shadow, no glow, thick enough strokes to read at 18px. "
        "Square canvas, icon centered with padding."
    ),
    "swarmguard-popout-mock.png": (
        "UI mockup screenshot of a macOS menu-bar popover panel for SwarmGuard antivirus. "
        "Dark theme: background #0A0D12, panel surface #121821, text #E8EDF5, accents #3DD68C, "
        "danger red #FF4D4D for a short denial list. "
        "Top: small shield mark + title 'SwarmGuard'. "
        "Status line 'Protecting · Enforce ON'. "
        "MCP gate idle. List of 3 recent denials. "
        "Rounded buttons: Refresh, Run free proofs. "
        "Clean Apple HIG-like utility panel, floating under a menu bar, "
        "no purple, no clutter, no fake browser chrome, photoreal UI mock."
    ),
}


def _client() -> OpenAI:
    if not KEY:
        raise SystemExit("MODEL_API_KEY missing — set in .env")
    return OpenAI(api_key=KEY, base_url=BASE)


def _save_b64(b64: str, path: Path) -> None:
    raw = base64.b64decode(b64)
    path.write_bytes(raw)
    # Normalize to PNG RGBA via Pillow when possible
    try:
        img = Image.open(path).convert("RGBA")
        img.save(path, format="PNG")
    except OSError:
        pass
    print(f"wrote {path.relative_to(ROOT)} ({path.stat().st_size} bytes)")


def generate_one(client: OpenAI, name: str, prompt: str) -> None:
    print(f"Muse Image → {name} …")
    size = "1024x1024" if "mock" not in name else "1024x1536"
    resp = client.images.generate(
        model=MODEL,
        prompt=prompt,
        n=1,
        size=size,
        response_format="b64_json",
    )
    b64 = resp.data[0].b64_json
    if not b64:
        raise RuntimeError(f"empty image for {name}")
    _save_b64(b64, OUT / name)


def make_template_from_menu_icon() -> None:
    src = OUT / "swarmguard-icon-menu.png"
    if not src.exists():
        return
    img = Image.open(src).convert("RGBA")
    pixels = img.load()
    w, h = img.size
    for y in range(h):
        for x in range(w):
            r, g, b, a = pixels[x, y]
            if a < 20:
                pixels[x, y] = (0, 0, 0, 0)
            else:
                # Black silhouette for macOS template tinting
                pixels[x, y] = (0, 0, 0, a)
    dest = OUT / "swarmguard-icon-menu-template.png"
    img.save(dest, format="PNG")
    print(f"wrote {dest.relative_to(ROOT)}")


def make_dark_preview() -> None:
    src = OUT / "swarmguard-icon-menu.png"
    if not src.exists():
        return
    icon = Image.open(src).convert("RGBA")
    canvas = Image.new("RGBA", (256, 256), (10, 13, 18, 255))
    icon = icon.resize((160, 160), Image.Resampling.LANCZOS)
    ox = (256 - 160) // 2
    oy = (256 - 160) // 2
    canvas.alpha_composite(icon, (ox, oy))
    dest = OUT / "swarmguard-icon-menu-dark.png"
    canvas.save(dest, format="PNG")
    print(f"wrote {dest.relative_to(ROOT)}")


def main() -> int:
    client = _client()
    only = sys.argv[1:] if len(sys.argv) > 1 else list(PROMPTS)
    for name in only:
        key = name if name.endswith(".png") else f"{name}.png"
        if key not in PROMPTS:
            print(f"skip unknown {key}", file=sys.stderr)
            continue
        generate_one(client, key, PROMPTS[key])
    make_template_from_menu_icon()
    make_dark_preview()
    print("done — Quit menu bar and ./run_menubar.sh to pick up icons")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
