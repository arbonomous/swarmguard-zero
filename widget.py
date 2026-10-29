#!/usr/bin/env python3
"""Always-on-top SwarmGuard floating HUD.

Drawn on a Canvas so macOS system Tk actually shows colors (Labels often render
as blank white on deprecated Aqua Tk). Uses a normal always-on-top window so
clicks reach the Kill button reliably.
"""

from __future__ import annotations

import os
import sys

os.environ.setdefault("TK_SILENCE_DEPRECATION", "1")


def _require_tk():
    try:
        import tkinter as tk  # noqa: F401
        return
    except ModuleNotFoundError as exc:
        sys.stderr.write(
            "\n[SWARMGUARD] This Python has no Tk support.\n"
            "Run:  /usr/bin/python3 widget.py\n"
            f"Detail: {exc}\n"
        )
        raise SystemExit(1) from exc


_require_tk()

import tkinter as tk

from threat_bus import read_state, reset_to_safe

POLL_MS = 350
W = 400
H = 250

BG = "#07090d"
PANEL = "#121821"
ARMED = "#3dd68c"
THREAT = "#ff4d4d"
AMBER = "#f0b429"
MUTED = "#9aa6b8"
INK = "#f2f5fa"
DIM = "#1b2433"


class SwarmGuardWidget(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("SWARMGUARD // ZERO")
        self.configure(bg=BG)
        self.attributes("-topmost", True)
        self.resizable(False, False)
        # Do NOT use overrideredirect on macOS Tk — it breaks painting + clicks.

        sw = self.winfo_screenwidth()
        self.geometry(f"{W}x{H}+{sw - W - 28}+40")

        self.canvas = tk.Canvas(
            self,
            width=W,
            height=H,
            bg=BG,
            highlightthickness=0,
            bd=0,
        )
        self.canvas.pack(fill="both", expand=True)

        # Hit target for quarantine
        self.canvas.tag_bind("killbtn", "<Button-1>", self._on_kill)
        self.canvas.tag_bind("killbtn", "<Enter>", lambda _e: self._hover_kill(True))
        self.canvas.tag_bind("killbtn", "<Leave>", lambda _e: self._hover_kill(False))

        self._alert = False
        self._flash = False
        self._kill_hover = False
        self._last_fingerprint = None
        self._draw_armed("Spark · Wonder · SAM standing by")
        self.after(POLL_MS, self.poll)

    def _on_kill(self, _event=None) -> None:
        reset_to_safe("Threat quarantined. Simulated rogue agent released. Swarm re-armed.")
        self._alert = False
        self._draw_armed("Threat quarantined. Swarm re-armed.")
        # Brief flash so the click is obviously acknowledged
        self.canvas.create_rectangle(0, 0, W, H, fill=ARMED, outline="", tags="ack")
        self.canvas.create_text(
            W // 2,
            H // 2,
            text="QUARANTINED",
            fill=BG,
            font=("Menlo", 22, "bold"),
            tags="ack",
        )
        self.after(450, self._clear_ack)

    def _clear_ack(self) -> None:
        self.canvas.delete("ack")
        self._draw_armed("Threat quarantined. Swarm re-armed.")

    def _hover_kill(self, on: bool) -> None:
        self._kill_hover = on
        if self._alert:
            state = read_state()
            self._draw_critical(state)

    def _draw_frame(self, border: str) -> None:
        self.canvas.delete("all")
        self.canvas.create_rectangle(0, 0, W, H, fill=BG, outline="")
        self.canvas.create_rectangle(8, 8, W - 8, H - 8, fill=border, outline="")
        self.canvas.create_rectangle(12, 12, W - 12, H - 12, fill=PANEL, outline="")

    def _draw_armed(self, detail: str) -> None:
        self._draw_frame(ARMED)
        self.canvas.create_text(
            28, 34, anchor="w", text="SWARMGUARD // ZERO", fill=INK, font=("Helvetica", 12, "bold")
        )
        self.canvas.create_text(
            W - 28, 34, anchor="e", text="LIVE", fill=ARMED, font=("Menlo", 10, "bold")
        )
        self.canvas.create_text(
            28, 88, anchor="w", text="ARMED", fill=ARMED, font=("Helvetica", 36, "bold")
        )
        self.canvas.create_text(
            28,
            140,
            anchor="w",
            text=self._wrap(detail, 42),
            fill=MUTED,
            font=("Menlo", 11),
            width=W - 56,
        )
        self.canvas.create_text(
            28,
            H - 36,
            anchor="w",
            text="waiting for War Room attack simulation",
            fill=AMBER,
            font=("Menlo", 10),
        )

    def _draw_critical(self, state: dict) -> None:
        border = THREAT if self._flash else "#6f1524"
        self._draw_frame(border)
        score = state.get("threat_score", 0)
        pid = state.get("pid")
        agent = state.get("agent_triggered") or "swarm"
        summary = str(state.get("summary") or "Critical threat detected.")

        self.canvas.create_text(
            28, 34, anchor="w", text="SWARMGUARD // ZERO", fill=INK, font=("Helvetica", 12, "bold")
        )
        self.canvas.create_text(
            W - 28, 34, anchor="e", text="ALERT", fill=THREAT, font=("Menlo", 10, "bold")
        )
        self.canvas.create_text(
            28, 82, anchor="w", text="CRITICAL", fill=THREAT, font=("Helvetica", 34, "bold")
        )
        self.canvas.create_text(
            28,
            118,
            anchor="w",
            text=f"score {score}   PID {pid} FROZEN   {agent}",
            fill=AMBER,
            font=("Menlo", 10),
        )
        self.canvas.create_text(
            28,
            148,
            anchor="nw",
            text=self._wrap(summary, 44),
            fill=INK,
            font=("Menlo", 10),
            width=W - 56,
        )

        btn_y1, btn_y2 = H - 58, H - 22
        btn_fill = "#ff7777" if self._kill_hover else THREAT
        self.canvas.create_rectangle(
            28, btn_y1, W - 28, btn_y2, fill=btn_fill, outline="", tags=("killbtn",)
        )
        self.canvas.create_text(
            W // 2,
            (btn_y1 + btn_y2) // 2,
            text="KILL & QUARANTINE",
            fill=BG,
            font=("Helvetica", 12, "bold"),
            tags=("killbtn",),
        )

    @staticmethod
    def _wrap(text: str, width: int) -> str:
        words = text.split()
        lines = []
        cur = []
        for word in words:
            trial = (" ".join(cur + [word])).strip()
            if len(trial) > width and cur:
                lines.append(" ".join(cur))
                cur = [word]
            else:
                cur.append(word)
        if cur:
            lines.append(" ".join(cur))
        return "\n".join(lines[:4])

    def poll(self) -> None:
        state = read_state()
        status = str(state.get("status", "ARMED")).upper()
        fingerprint = (
            status,
            state.get("threat_score"),
            state.get("summary"),
            state.get("pid"),
            state.get("updated_at"),
        )

        if status == "CRITICAL":
            self._alert = True
            self._flash = not self._flash
            self._draw_critical(state)
        elif self._alert or (self._last_fingerprint and self._last_fingerprint[0] == "CRITICAL"):
            self._alert = False
            self._draw_armed(state.get("summary") or "All swarm guards nominal.")
        elif fingerprint != self._last_fingerprint:
            self._draw_armed(state.get("summary") or "Spark · Wonder · SAM standing by")

        self._last_fingerprint = fingerprint
        self.after(POLL_MS, self.poll)


def main() -> None:
    read_state()
    app = SwarmGuardWidget()
    print("SWARMGUARD HUD running — leave this terminal open.", flush=True)
    app.mainloop()


if __name__ == "__main__":
    main()
