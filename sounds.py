"""Synthetic HUD sound cues for SwarmGuard (no external audio assets required)."""

from __future__ import annotations

import base64
import math
import struct
import wave
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parent
SOUND_DIR = ROOT / "assets" / "sounds"

# name -> list of (freq_hz, duration_ms, gain)
CUES: dict[str, list[tuple[float, int, float]]] = {
    "patrol": [(660, 60, 0.18), (880, 60, 0.14)],
    "scan": [(520, 45, 0.12)],
    "threat": [(220, 120, 0.28), (180, 160, 0.32), (140, 220, 0.35)],
    "analyzing": [(440, 70, 0.16), (554, 70, 0.16), (659, 90, 0.18)],
    "quarantine": [(523, 90, 0.22), (659, 90, 0.22), (784, 140, 0.25)],
    "armed": [(392, 80, 0.16), (523, 120, 0.18)],
}


def _synth_tone(freq: float, ms: int, gain: float = 0.2, rate: int = 22050) -> bytes:
    n = int(rate * ms / 1000)
    frames = bytearray()
    for i in range(n):
        # short attack/decay envelope so it doesn't click
        env = 1.0
        attack = int(rate * 0.008)
        release = int(rate * 0.02)
        if i < attack:
            env = i / max(attack, 1)
        elif i > n - release:
            env = max(0.0, (n - i) / max(release, 1))
        sample = gain * env * math.sin(2 * math.pi * freq * (i / rate))
        frames += struct.pack("<h", int(max(-1.0, min(1.0, sample)) * 32767))
    return bytes(frames)


def ensure_sounds() -> None:
    SOUND_DIR.mkdir(parents=True, exist_ok=True)
    rate = 22050
    for name, parts in CUES.items():
        path = SOUND_DIR / f"{name}.wav"
        if path.exists():
            continue
        pcm = b"".join(_synth_tone(freq, ms, gain, rate) for freq, ms, gain in parts)
        with wave.open(str(path), "wb") as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(rate)
            wf.writeframes(pcm)


def play(name: str) -> None:
    """Embed an autoplaying WAV in the Streamlit page."""
    ensure_sounds()
    path = SOUND_DIR / f"{name}.wav"
    if not path.exists():
        return
    b64 = base64.b64encode(path.read_bytes()).decode("ascii")
    # unique key avoids browser ignoring repeated identical audio tags
    stamp = f"{name}-{st.session_state.get('_sound_i', 0)}"
    st.session_state["_sound_i"] = int(st.session_state.get("_sound_i", 0)) + 1
    st.markdown(
        f"""
        <audio autoplay="true" style="display:none" id="{stamp}">
          <source src="data:audio/wav;base64,{b64}" type="audio/wav" />
        </audio>
        """,
        unsafe_allow_html=True,
    )
