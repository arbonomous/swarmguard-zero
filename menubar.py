#!/usr/bin/env python3
"""SwarmGuard macOS menu-bar Protector — primary always-on AV UX.

Menu-bar first: native NSPanel is the Protector surface. Streamlit dashboard is
an optional advanced console. No Muse/Meta API calls. No SIGKILL of user processes.
Prefers rumps when installed; falls back to PyObjC AppKit (framework Python).
"""

from __future__ import annotations

import atexit
import os
import subprocess
import sys
import threading
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from policy import enforce_enabled  # noqa: E402
from threat_bus import read_gate_status, read_incidents  # noqa: E402

REFRESH_S = 7
PROTECTOR_URL = "http://127.0.0.1:8501"
DENY_MENU_LIMIT = 1
DENY_PANEL_LIMIT = 8
PANEL_W = 360
PANEL_H = 460
# Brand tokens (assets/brand/BRAND.md)
_BRAND_INK = (10 / 255.0, 13 / 255.0, 18 / 255.0, 1.0)  # #0A0D12
_BRAND_SURFACE = (18 / 255.0, 24 / 255.0, 33 / 255.0, 1.0)  # #121821
_BRAND_SIGNAL = (61 / 255.0, 214 / 255.0, 140 / 255.0, 1.0)  # #3DD68C
_BRAND_TEXT = (232 / 255.0, 237 / 255.0, 245 / 255.0, 1.0)  # #E8EDF5
_BRAND_MUTED = (139 / 255.0, 149 / 255.0, 168 / 255.0, 1.0)  # #8B95A8
_BRAND_DANGER = (255 / 255.0, 77 / 255.0, 77 / 255.0, 1.0)  # #FF4D4D
PID_FILE = Path(
    os.environ.get("SWARMGUARD_MENUBAR_PID", "/tmp/swarmguard-menubar.pid")
)
BRAND_DIR = ROOT / "assets" / "brand"
ICON_MENU = BRAND_DIR / "swarmguard-icon-menu.png"
ICON_TEMPLATE = BRAND_DIR / "swarmguard-icon-menu-template.png"
ICON_MARK = BRAND_DIR / "swarmguard-mark.png"


def _menu_icon_path(*, template: bool = False) -> Path | None:
    """Prefer menu-bar mark; fall back to square product mark."""
    if template and ICON_TEMPLATE.exists():
        return ICON_TEMPLATE
    if ICON_MENU.exists():
        return ICON_MENU
    if ICON_MARK.exists():
        return ICON_MARK
    return None


def _load_ns_status_image() -> Any | None:
    """NSImage for NSStatusItem (template-tinted). Returns None if AppKit/path missing."""
    path = _menu_icon_path(template=True) or _menu_icon_path()
    if path is None:
        return None
    try:
        from AppKit import NSImage
    except ImportError:
        return None
    image = NSImage.alloc().initWithContentsOfFile_(str(path))
    if image is None:
        return None
    image.setTemplate_(True)
    image.setSize_((18.0, 18.0))
    return image


def _is_policy_or_ide_deny(row: dict[str, Any]) -> bool:
    kind = str(row.get("kind") or "").lower()
    source = str(row.get("source") or "").lower()
    trigger = str(row.get("trigger") or "").lower()
    action = str(row.get("action") or "").upper()
    if source == "ide_hook" or trigger == "ide_hook":
        return True
    if kind == "policy_deny":
        return True
    if action == "POLICY_DENY":
        return True
    return False


def _deny_label(row: dict[str, Any]) -> str:
    rule = str(row.get("rule") or row.get("reason") or "")
    if "env" in rule or "secret" in rule or "ssh" in rule:
        return "Sensitive-file request refused"
    if "localhost" in rule or "egress" in rule or "http" in rule:
        return "Outside-network request refused"
    return "Connected tool request refused"


def _gate_label(mcp: dict[str, Any]) -> str:
    return "Tool connection: active (routed calls only)" if mcp.get("wrapping") else "No active tool connection confirmed"


def _gate_short(mcp: dict[str, Any]) -> str:
    return _gate_label(mcp)


def _protecting_line(enforce: bool) -> str:
    return "Tool policy ready (scoped, not whole-Mac)" if enforce else "Tool blocking is OFF"


def _activity_summary(rows: list[dict]) -> str:
    if not rows:
        return "No tool denials recorded"
    return f"{len(rows)} recent tool denials (may include tests)"


def _status_snapshot() -> dict[str, Any]:
    enforce = enforce_enabled()
    mcp = read_gate_status()
    denials = [
        r for r in read_incidents(24) if _is_policy_or_ide_deny(r)
    ][:DENY_PANEL_LIMIT]
    # When an icon is present, keep the status title minimal (suffix only).
    has_icon = _menu_icon_path() is not None
    if not enforce:
        title = "·" if has_icon else "SG·"
    else:
        title = "" if has_icon else "SG"
    tip_bits = [
        "SwarmGuard",
        "Tool policy ready" if enforce else "Tool policy off",
        "wrapping" if mcp.get("wrapping") else "gate idle",
    ]
    if denials:
        tip_bits.append("Recorded activity may include tests")
    return {
        "enforce": enforce,
        "mcp": mcp,
        "denials": denials,
        "title": title,
        "tooltip": " · ".join(tip_bits),
    }


def _protector_up() -> bool:
    try:
        with urllib.request.urlopen(PROTECTOR_URL, timeout=0.6) as resp:
            return 200 <= int(getattr(resp, "status", 200)) < 500
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def open_full_console(*, workspace: bool = False) -> str:
    """Optional advanced Streamlit console in the browser (not the primary Protector)."""
    url = PROTECTOR_URL + ("/#offline-workspace" if workspace else "")
    if _protector_up():
        webbrowser.open(url)
        return "Opened full console (Streamlit) in browser."
    env = os.environ.copy()
    env.setdefault("SWARMGUARD_MUSE_ON_AMBIGUOUS", "0")
    streamlit = ROOT / ".venv" / "bin" / "streamlit"
    if streamlit.exists():
        cmd = [str(streamlit), "run", str(ROOT / "dashboard.py")]
    else:
        cmd = [sys.executable, "-m", "streamlit", "run", str(ROOT / "dashboard.py")]
    subprocess.Popen(  # noqa: S603 — local Streamlit launch only
        cmd,
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    webbrowser.open(url)
    return "Starting full console (streamlit)…"


# Back-compat alias (older call sites / docs)
open_protector = open_full_console


def show_native_section(section: str = "Status", status_item=None) -> None:
    """Keep native construction failures visible instead of losing menu actions."""
    print("[SwarmGuard] Opening native section: " + section, flush=True)
    try:
        from native_workspace import open_workspace
        open_workspace(section=section, status_item=status_item)
        print("[SwarmGuard] Native section opened", flush=True)
    except Exception as exc:
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.stderr.flush()
        from AppKit import NSAlert
        alert = NSAlert.alloc().init()
        alert.setMessageText_("SwarmGuard could not open this panel")
        alert.setInformativeText_(type(exc).__name__ + ": " + str(exc)[:400] +
                                 "\nNo workload was launched. Send this message for help.")
        alert.addButtonWithTitle_("OK")
        alert.runModal()


def open_offline_workspace(status_item=None) -> str:
    """Native menu-owned workspace. Never starts or opens a browser."""
    show_native_section("Workspace", status_item)
    return "Opened native offline workspace."


def run_free_proofs() -> str:
    """Run IDE hook + MCP gate demos (no Muse / Meta API)."""
    env = os.environ.copy()
    env["SWARMGUARD_ENFORCE"] = "1"
    env["SWARMGUARD_MUSE_ON_AMBIGUOUS"] = "0"
    py = ROOT / ".venv" / "bin" / "python"
    python = str(py) if py.exists() else sys.executable
    scripts = [
        ROOT / "safe_range" / "run_ide_hook_demo.py",
        ROOT / "safe_range" / "run_mcp_gate_demo.py",
    ]
    lines: list[str] = []
    for script in scripts:
        try:
            proc = subprocess.run(  # noqa: S603
                [python, str(script)],
                cwd=str(ROOT),
                env=env,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            name = script.name
            if proc.returncode == 0:
                lines.append(f"{name}: OK")
            else:
                tail = (proc.stderr or proc.stdout or "").strip().splitlines()
                detail = tail[-1] if tail else f"exit {proc.returncode}"
                lines.append(f"{name}: FAIL — {detail[:80]}")
        except subprocess.TimeoutExpired:
            lines.append(f"{script.name}: TIMEOUT")
        except OSError as exc:
            lines.append(f"{script.name}: {exc}")
    return "\n".join(lines) if lines else "No proofs ran."


# ---------------------------------------------------------------------------
# Single-instance lock (PID file)
# ---------------------------------------------------------------------------


def _pid_alive(pid: int) -> bool:
    if pid <= 0 or pid == os.getpid():
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _pid_looks_like_menubar(pid: int) -> bool:
    """True when ps shows menubar.py for this pid (best-effort)."""
    try:
        out = subprocess.check_output(  # noqa: S603
            ["ps", "-p", str(pid), "-o", "command="],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, OSError, FileNotFoundError):
        return True
    cmd = out.strip().lower()
    return "menubar.py" in cmd


def _release_instance_lock() -> None:
    try:
        if PID_FILE.exists():
            text = PID_FILE.read_text(encoding="utf-8").strip()
            if text == str(os.getpid()):
                PID_FILE.unlink(missing_ok=True)
    except OSError:
        pass


def acquire_single_instance() -> None:
    """Exit if another SwarmGuard menu-bar process already holds the lock."""
    if PID_FILE.exists():
        try:
            old = int(PID_FILE.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            old = 0
        if old and _pid_alive(old) and _pid_looks_like_menubar(old):
            sys.stderr.write(
                f"[SWARMGUARD] Menu bar already running (pid {old}).\n"
                "  Quit via the SwarmGuard menu → Quit SwarmGuard menu, then relaunch.\n"
                f"  Stale lock only: rm {PID_FILE}\n"
            )
            raise SystemExit(0)
        try:
            PID_FILE.unlink(missing_ok=True)
        except OSError:
            pass
    try:
        PID_FILE.write_text(str(os.getpid()), encoding="utf-8")
    except OSError as exc:
        sys.stderr.write(f"[SWARMGUARD] Could not write PID lock {PID_FILE}: {exc}\n")
        return
    atexit.register(_release_instance_lock)


# ---------------------------------------------------------------------------
# Native Protector panel (AppKit NSPanel — shared by rumps + AppKit paths)
# ---------------------------------------------------------------------------


def _ns_color(rgba: tuple[float, float, float, float]) -> Any:
    from AppKit import NSColor

    r, g, b, a = rgba
    return NSColor.colorWithCalibratedRed_green_blue_alpha_(r, g, b, a)


def _make_label(
    text: str,
    *,
    bold: bool = False,
    size: float = 12.0,
    color: tuple[float, float, float, float] | None = None,
) -> Any:
    from AppKit import NSFont, NSTextField

    field = NSTextField.alloc().initWithFrame_(((0, 0), (PANEL_W - 24, 18)))
    field.setStringValue_(text)
    field.setBezeled_(False)
    field.setDrawsBackground_(False)
    field.setEditable_(False)
    field.setSelectable_(False)
    font = NSFont.boldSystemFontOfSize_(size) if bold else NSFont.systemFontOfSize_(size)
    field.setFont_(font)
    try:
        field.setTextColor_(_ns_color(color or _BRAND_TEXT))
    except Exception:
        pass
    return field


def _make_button(
    title: str,
    action: str,
    target: Any,
    *,
    primary: bool = False,
) -> Any:
    from AppKit import NSButton, NSRoundedBezelStyle

    btn = NSButton.alloc().initWithFrame_(((0, 0), (100, 28)))
    btn.setTitle_(title)
    btn.setBezelStyle_(NSRoundedBezelStyle)
    btn.setTarget_(target)
    btn.setAction_(action)
    if primary:
        try:
            btn.setBordered_(True)
            # Highlight primary action (Run free proofs) toward brand signal.
            btn.setBezelColor_(_ns_color(_BRAND_SIGNAL))
        except Exception:
            pass
    return btn


class _ProtectorPanelState:
    """Holds the singleton NSPanel + AppKit controller across rumps/AppKit hosts."""

    def __init__(self) -> None:
        self.controller: Any = None
        self.panel: Any = None
        self.status_item: Any = None
        self.on_refresh: Callable[[], None] | None = None

    def ensure(self, status_item: Any, on_refresh: Callable[[], None] | None = None) -> Any:
        self.status_item = status_item
        if on_refresh is not None:
            self.on_refresh = on_refresh
        if self.controller is not None:
            return self.controller
        self.controller = _build_panel_controller(self)
        return self.controller

    def toggle(self, status_item: Any, on_refresh: Callable[[], None] | None = None) -> None:
        ctrl = self.ensure(status_item, on_refresh)
        ctrl.togglePanel_(None)

    def refresh_if_visible(self) -> None:
        if self.controller is None or self.panel is None:
            return
        if self.panel.isVisible():
            self.controller.reloadSnapshot_(None)


_PANEL = _ProtectorPanelState()


def _build_panel_controller(state: _ProtectorPanelState) -> Any:
    import objc
    from AppKit import (
        NSBackingStoreBuffered,
        NSColor,
        NSFont,
        NSMakeRect,
        NSPanel,
        NSScrollView,
        NSView,
        NSWindowStyleMaskClosable,
        NSWindowStyleMaskNonactivatingPanel,
        NSWindowStyleMaskTitled,
        NSWindowStyleMaskUtilityWindow,
        NSFloatingWindowLevel,
    )
    from Foundation import NSObject

    style = (
        NSWindowStyleMaskTitled
        | NSWindowStyleMaskClosable
        | NSWindowStyleMaskUtilityWindow
        | NSWindowStyleMaskNonactivatingPanel
    )

    class PanelController(NSObject):
        def init(self):
            self = objc.super(PanelController, self).init()
            if self is None:
                return None
            self.panel = None
            self.status_label = None
            self.gate_label = None
            self.denials_field = None
            self.proof_status = None
            self._proof_busy = False
            return self

        def build(self) -> None:
            panel = NSPanel.alloc().initWithContentRect_styleMask_backing_defer_(
                NSMakeRect(0, 0, PANEL_W, PANEL_H),
                style,
                NSBackingStoreBuffered,
                False,
            )
            panel.setTitle_("SwarmGuard")
            panel.setLevel_(NSFloatingWindowLevel)
            panel.setHidesOnDeactivate_(False)
            panel.setReleasedWhenClosed_(False)
            panel.setFloatingPanel_(True)
            panel.setBecomesKeyOnlyIfNeeded_(True)
            try:
                panel.setBackgroundColor_(_ns_color(_BRAND_INK))
                panel.setTitlebarAppearsTransparent_(True)
            except Exception:
                try:
                    panel.setBackgroundColor_(NSColor.windowBackgroundColor())
                except Exception:
                    pass

            content = NSView.alloc().initWithFrame_(NSMakeRect(0, 0, PANEL_W, PANEL_H))
            try:
                content.setWantsLayer_(True)
                content.layer().setBackgroundColor_(_ns_color(_BRAND_INK).CGColor())
            except Exception:
                pass
            y = PANEL_H - 28

            title_x = 12.0
            # Prefer crisp menu mark for panel header; fall back to full product mark.
            mark_path = ICON_MENU if ICON_MENU.exists() else ICON_MARK
            if mark_path.exists():
                try:
                    from AppKit import NSImage, NSImageView

                    mark = NSImage.alloc().initWithContentsOfFile_(str(mark_path))
                    if mark is not None:
                        mark.setSize_((24.0, 24.0))
                        iv = NSImageView.alloc().initWithFrame_(
                            NSMakeRect(12, y - 10, 24, 24)
                        )
                        iv.setImage_(mark)
                        iv.setImageScaling_(3)  # NSImageScaleProportionallyUpOrDown
                        content.addSubview_(iv)
                        title_x = 44.0
                except Exception:
                    pass

            title = _make_label("SwarmGuard", bold=True, size=17.0)
            title.setFrame_(NSMakeRect(title_x, y - 8, PANEL_W - title_x - 12, 24))
            content.addSubview_(title)
            y -= 36

            self.status_label = _make_label("Status: …", color=_BRAND_SIGNAL)
            self.status_label.setFrame_(NSMakeRect(12, y, PANEL_W - 24, 18))
            content.addSubview_(self.status_label)
            y -= 22

            self.gate_label = _make_label("MCP gate: …", size=11.0, color=_BRAND_MUTED)
            self.gate_label.setFrame_(NSMakeRect(12, y, PANEL_W - 24, 18))
            content.addSubview_(self.gate_label)
            y -= 28

            denials_hdr = _make_label("RECORDED TOOL ACTIVITY (MAY INCLUDE TESTS)", bold=True, size=11.0, color=_BRAND_MUTED)
            denials_hdr.setFrame_(NSMakeRect(12, y, PANEL_W - 24, 18))
            content.addSubview_(denials_hdr)
            y -= 8

            scroll_h = 180
            from AppKit import NSTextView

            scroll = NSScrollView.alloc().initWithFrame_(
                NSMakeRect(12, y - scroll_h, PANEL_W - 24, scroll_h)
            )
            scroll.setHasVerticalScroller_(True)
            scroll.setBorderType_(1)  # NSBezelBorder
            scroll.setAutohidesScrollers_(True)
            scroll.setHasHorizontalScroller_(False)
            try:
                scroll.setDrawsBackground_(True)
                scroll.setBackgroundColor_(_ns_color(_BRAND_SURFACE))
            except Exception:
                pass

            self.denials_field = NSTextView.alloc().initWithFrame_(
                NSMakeRect(0, 0, PANEL_W - 40, scroll_h)
            )
            self.denials_field.setString_("(no recent policy/IDE denials)")
            self.denials_field.setEditable_(False)
            self.denials_field.setSelectable_(True)
            self.denials_field.setRichText_(False)
            self.denials_field.setFont_(NSFont.systemFontOfSize_(11.0))
            try:
                self.denials_field.setTextColor_(_ns_color(_BRAND_TEXT))
                self.denials_field.setBackgroundColor_(_ns_color(_BRAND_SURFACE))
                self.denials_field.setDrawsBackground_(True)
            except Exception:
                self.denials_field.setDrawsBackground_(False)
            try:
                self.denials_field.setHorizontallyResizable_(False)
                self.denials_field.setVerticallyResizable_(True)
                self.denials_field.textContainer().setWidthTracksTextView_(True)
                self.denials_field.textContainer().setContainerSize_(
                    ((PANEL_W - 40), 1.0e7)
                )
            except Exception:
                pass
            scroll.setDocumentView_(self.denials_field)
            content.addSubview_(scroll)
            y = y - scroll_h - 16

            self.proof_status = _make_label("", size=10.0, color=_BRAND_MUTED)
            self.proof_status.setFrame_(NSMakeRect(12, y, PANEL_W - 24, 16))
            content.addSubview_(self.proof_status)
            y -= 28

            btn_y = y - 4
            refresh_btn = _make_button("Refresh", "refreshClicked:", self)
            refresh_btn.setFrame_(NSMakeRect(12, btn_y, 100, 30))
            content.addSubview_(refresh_btn)

            proof_btn = _make_button(
                "Safety check...", "proofsClicked:", self, primary=True
            )
            proof_btn.setFrame_(NSMakeRect(120, btn_y, 140, 30))
            content.addSubview_(proof_btn)

            console_btn = _make_button(
                "Offline workspace…", "consoleClicked:", self
            )
            console_btn.setFrame_(NSMakeRect(12, btn_y - 38, PANEL_W - 24, 28))
            content.addSubview_(console_btn)

            hint = _make_label(
                "Local copied files and offline checks - no browser",
                size=10.0,
                color=_BRAND_MUTED,
            )
            hint.setFrame_(NSMakeRect(12, btn_y - 58, PANEL_W - 24, 14))
            content.addSubview_(hint)

            panel.setContentView_(content)
            self.panel = panel
            state.panel = panel
            self.reloadSnapshot_(None)

        def reloadSnapshot_(self, _sender) -> None:
            snap = _status_snapshot()
            if self.status_label is not None:
                self.status_label.setStringValue_(_protecting_line(bool(snap["enforce"])))
                try:
                    self.status_label.setTextColor_(
                        _ns_color(_BRAND_SIGNAL if snap["enforce"] else _BRAND_DANGER)
                    )
                except Exception:
                    pass
            if self.gate_label is not None:
                self.gate_label.setStringValue_(_gate_short(snap["mcp"]))
            denials = snap["denials"]
            if self.denials_field is not None:
                if denials:
                    text = "\n".join(_deny_label(r) for r in denials[:DENY_PANEL_LIMIT])
                else:
                    text = "(no recent policy/IDE denials)"
                # NSTextView uses setString_; keep setStringValue_ fallback
                if hasattr(self.denials_field, "setString_"):
                    self.denials_field.setString_(text)
                else:
                    self.denials_field.setStringValue_(text)
            if state.on_refresh is not None:
                try:
                    state.on_refresh()
                except Exception:
                    pass

        def _position_below_status_item(self) -> None:
            if self.panel is None:
                return
            item = state.status_item
            screen = None
            anchor_x = None
            anchor_y = None
            if item is not None:
                button = item.button() if hasattr(item, "button") else None
                if button is not None:
                    win = button.window()
                    if win is not None:
                        rect = button.convertRect_toView_(button.bounds(), None)
                        screen_rect = win.convertRectToScreen_(rect)
                        anchor_x = screen_rect.origin.x + screen_rect.size.width / 2.0
                        anchor_y = screen_rect.origin.y
                        screen = win.screen()
            if screen is None:
                from AppKit import NSScreen

                screens = NSScreen.screens()
                screen = screens[0] if screens else None
            if screen is None:
                self.panel.center()
                return
            visible = screen.visibleFrame()
            if anchor_x is None:
                anchor_x = visible.origin.x + visible.size.width / 2.0
            if anchor_y is None:
                anchor_y = visible.origin.y + visible.size.height - 4

            x = anchor_x - PANEL_W / 2.0
            y = anchor_y - PANEL_H - 6
            # Clamp into visible frame
            min_x = visible.origin.x + 8
            max_x = visible.origin.x + visible.size.width - PANEL_W - 8
            x = max(min_x, min(x, max_x))
            min_y = visible.origin.y + 8
            if y < min_y:
                y = min_y
            self.panel.setFrameOrigin_((x, y))

        def togglePanel_(self, _sender) -> None:
            if self.panel is None:
                self.build()
            assert self.panel is not None
            if self.panel.isVisible():
                self.panel.orderOut_(None)
                return
            self.reloadSnapshot_(None)
            self._position_below_status_item()
            self.panel.makeKeyAndOrderFront_(None)
            try:
                from AppKit import NSApp

                NSApp.activateIgnoringOtherApps_(True)
            except Exception:
                pass

        def refreshClicked_(self, _sender) -> None:
            self.reloadSnapshot_(None)
            if self.proof_status is not None:
                self.proof_status.setStringValue_("Refreshed.")

        def proofsClicked_(self, _sender) -> None:
            if self._proof_busy:
                return
            self._proof_busy = True
            if self.proof_status is not None:
                self.proof_status.setStringValue_("Running IDE + MCP demos…")

            def worker() -> None:
                msg = run_free_proofs()
                summary = msg.replace("\n", " · ")[:120]

                def done() -> None:
                    self._proof_busy = False
                    if self.proof_status is not None:
                        self.proof_status.setStringValue_(summary)
                    self.reloadSnapshot_(None)

                # Bounce back to main thread via performSelectorOnMainThread
                try:
                    self.performSelectorOnMainThread_withObject_waitUntilDone_(
                        "proofsFinished:", summary, False
                    )
                except Exception:
                    done()

            threading.Thread(target=worker, daemon=True).start()

        def proofsFinished_(self, summary) -> None:
            self._proof_busy = False
            if self.proof_status is not None:
                text = str(summary) if summary is not None else "Done."
                self.proof_status.setStringValue_(text)
            self.reloadSnapshot_(None)

        def consoleClicked_(self, _sender) -> None:
            msg = open_offline_workspace()
            if self.proof_status is not None:
                self.proof_status.setStringValue_(msg)

        def windowShouldClose_(self, _sender) -> bool:
            if self.panel is not None:
                self.panel.orderOut_(None)
            return False

    ctrl = PanelController.alloc().init()
    ctrl.build()
    if ctrl.panel is not None:
        ctrl.panel.setDelegate_(ctrl)
    return ctrl


def toggle_protector_panel(
    status_item: Any,
    on_refresh: Callable[[], None] | None = None,
) -> None:
    """Show or hide the native SwarmGuard Protector NSPanel under the status item."""
    _PANEL.toggle(status_item, on_refresh)


def refresh_protector_panel_if_visible() -> None:
    _PANEL.refresh_if_visible()


def _rumps_status_item(app: Any) -> Any:
    """Best-effort NSStatusItem from a rumps.App instance."""
    for attr in ("_nsstatusitem", "statusitem", "_status_item", "nsstatusitem"):
        item = getattr(app, attr, None)
        if item is not None:
            return item
    # rumps 0.4 stores under app._nsapp internals inconsistently
    nsapp = getattr(app, "_nsapp", None)
    if nsapp is not None:
        for attr in ("_status_bar_item", "statusItem", "_nsstatusitem"):
            item = getattr(nsapp, attr, None)
            if item is not None:
                return item
    return None


# ---------------------------------------------------------------------------
# rumps path
# ---------------------------------------------------------------------------


def _run_rumps() -> None:
    import rumps

    class SwarmGuardMenuBar(rumps.App):
        def __init__(self) -> None:
            icon = _menu_icon_path(template=True) or _menu_icon_path()
            kw: dict[str, Any] = {
                "name": "SwarmGuard",
                "title": "",
                "quit_button": None,
            }
            if icon is not None:
                kw["icon"] = str(icon)
                kw["template"] = True
            super().__init__(**kw)
            self._enforce_item = rumps.MenuItem("Enforce: …")
            self._enforce_item.set_callback(None)
            self._gate_item = rumps.MenuItem("MCP gate: …")
            self._gate_item.set_callback(None)
            self._deny_items: list[rumps.MenuItem] = [
                rumps.MenuItem("(no recent denials)") for _ in range(DENY_MENU_LIMIT)
            ]
            for item in self._deny_items:
                item.set_callback(None)
            header = rumps.MenuItem("SwarmGuard")
            header.set_callback(None)
            self.menu = [
                header,
                None,
                rumps.MenuItem("Open SwarmGuard...", callback=self._on_open),
                rumps.MenuItem("Safety check...", callback=self._on_proofs),
                rumps.MenuItem("Activity...", callback=self._on_activity),
                rumps.MenuItem("Workspace...", callback=self._on_workspace),
                rumps.MenuItem("Quit SwarmGuard", callback=self._on_quit),
            ]
            self._apply_snapshot(_status_snapshot())

        def _apply_snapshot(self, snap: dict[str, Any]) -> None:
            self.title = snap["title"]
            self._enforce_item.title = (
                _protecting_line(snap["enforce"])
            )
            self._gate_item.title = _gate_label(snap["mcp"])
            self._deny_items[0].title = _activity_summary(snap["denials"])
            refresh_protector_panel_if_visible()

        @rumps.timer(REFRESH_S)
        def refresh(self, _sender: Any) -> None:
            self._apply_snapshot(_status_snapshot())

        def _on_open(self, _sender: Any) -> None:
            show_native_section(section="Status", status_item=_rumps_status_item(self))

        def _on_proofs(self, _sender: Any) -> None:
            show_native_section(section="Safety check", status_item=_rumps_status_item(self))

        def _on_activity(self, _sender: Any) -> None:
            show_native_section(section="Activity and evidence", status_item=_rumps_status_item(self))

        def _on_workspace(self, _sender: Any) -> None:
            open_offline_workspace(_rumps_status_item(self))

        def _on_console(self, _sender: Any) -> None:
            msg = open_full_console()
            rumps.notification("SwarmGuard", "Full console", msg)

        def _on_quit(self, _sender: Any) -> None:
            from native_workspace import is_busy
            if is_busy():
                open_offline_workspace(_rumps_status_item(self))
                return
            _release_instance_lock()
            rumps.quit_application()

    SwarmGuardMenuBar().run()


# ---------------------------------------------------------------------------
# AppKit path (PyObjC — primary when rumps missing; native panel host)
# ---------------------------------------------------------------------------


def _run_appkit() -> None:
    import objc
    from AppKit import (
        NSApp,
        NSApplication,
        NSApplicationActivationPolicyAccessory,
        NSMenu,
        NSMenuItem,
        NSStatusBar,
        NSVariableStatusItemLength,
    )
    from Foundation import NSObject, NSTimer

    class Delegate(NSObject):
        def init(self):
            self = objc.super(Delegate, self).init()
            if self is None:
                return None
            self.status_item = None
            self.menu = None
            self.enforce_item = None
            self.gate_item = None
            self.deny_items: list[Any] = []
            self.timer = None
            self._status_image = None
            return self

        def applicationDidFinishLaunching_(self, _notification) -> None:
            # Guard: Cocoa may deliver this once via app.run(); never create
            # a second NSStatusItem (keep single status item + PID lock).
            if self.status_item is not None:
                return

            bar = NSStatusBar.systemStatusBar()
            self.status_item = bar.statusItemWithLength_(NSVariableStatusItemLength)
            self._status_image = _load_ns_status_image()
            button = self.status_item.button()
            if button is not None:
                if self._status_image is not None:
                    button.setImage_(self._status_image)
                    button.setTitle_("")
                else:
                    button.setTitle_("SG")

            self.menu = NSMenu.alloc().initWithTitle_("SwarmGuard")
            brand_item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
                "SwarmGuard", None, ""
            )
            self.menu.addItem_(brand_item)
            self.menu.addItem_(NSMenuItem.separatorItem())

            self.enforce_item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
                "Enforce: …", None, ""
            )
            self.gate_item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
                "MCP gate: …", None, ""
            )

            self.deny_items = []
            for _ in range(DENY_MENU_LIMIT):
                item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
                    "(no recent denials)", None, ""
                )
                self.deny_items.append(item)


            open_item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
                "Open SwarmGuard...", "openProtector:", ""
            )
            open_item.setTarget_(self)
            self.menu.addItem_(open_item)

            proof_item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
                "Safety check...", "runProofs:", ""
            )
            proof_item.setTarget_(self)
            self.menu.addItem_(proof_item)

            activity_item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
                "Activity...", "openActivity:", ""
            )
            activity_item.setTarget_(self)
            self.menu.addItem_(activity_item)

            workspace_item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
                "Workspace...", "openWorkspace:", ""
            )
            workspace_item.setTarget_(self)
            self.menu.addItem_(workspace_item)

            quit_item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
                "Quit SwarmGuard", "quitApp:", ""
            )
            quit_item.setTarget_(self)
            self.menu.addItem_(quit_item)

            self.status_item.setMenu_(self.menu)
            self.applySnapshot_(_status_snapshot())
            if self.timer is None:
                self.timer = NSTimer.scheduledTimerWithTimeInterval_target_selector_userInfo_repeats_(
                    float(REFRESH_S),
                    self,
                    "tick:",
                    None,
                    True,
                )

        def tick_(self, _timer) -> None:
            self.applySnapshot_(_status_snapshot())

        def applySnapshot_(self, snap: dict[str, Any]) -> None:
            button = self.status_item.button() if self.status_item else None
            if button is not None:
                if self._status_image is not None and button.image() is None:
                    button.setImage_(self._status_image)
                button.setTitle_(snap["title"])
                button.setToolTip_(snap["tooltip"])
            self.enforce_item.setTitle_(
                _protecting_line(snap["enforce"])
            )
            self.gate_item.setTitle_(_gate_label(snap["mcp"]))
            self.deny_items[0].setTitle_(_activity_summary(snap["denials"]))
            refresh_protector_panel_if_visible()

        def openProtector_(self, _sender) -> None:
            show_native_section(section="Status", status_item=self.status_item)

        def runProofs_(self, _sender) -> None:
            show_native_section(section="Safety check", status_item=self.status_item)

        def openActivity_(self, _sender) -> None:
            show_native_section(section="Activity and evidence", status_item=self.status_item)

        def openWorkspace_(self, _sender) -> None:
            open_offline_workspace(self.status_item)

        def openConsole_(self, _sender) -> None:
            open_full_console()

        def quitApp_(self, _sender) -> None:
            from native_workspace import is_busy
            if is_busy():
                open_offline_workspace(self.status_item)
                return
            if self.timer is not None:
                self.timer.invalidate()
                self.timer = None
            if _PANEL.panel is not None:
                _PANEL.panel.orderOut_(None)
            if self.status_item is not None:
                NSStatusBar.systemStatusBar().removeStatusItem_(self.status_item)
                self.status_item = None
            _release_instance_lock()
            NSApp.terminate_(None)

    app = NSApplication.sharedApplication()
    app.setActivationPolicy_(NSApplicationActivationPolicyAccessory)
    delegate = Delegate.alloc().init()
    app.setDelegate_(delegate)
    # Do NOT call applicationDidFinishLaunching_ here — app.run() delivers it
    # once. A manual call plus Cocoa's delivery created two NSStatusItems.
    app.run()


def main() -> None:
    # Never call Muse / Meta from the menu bar / Protector panel.
    os.environ.setdefault("SWARMGUARD_MUSE_ON_AMBIGUOUS", "0")
    acquire_single_instance()
    try:
        import rumps  # noqa: F401

        print("SwarmGuard menu bar (rumps) — leave this terminal open.", flush=True)
        print("  Open Protector → native panel (not browser).", flush=True)
        _run_rumps()
        return
    except ImportError:
        pass

    try:
        import AppKit  # noqa: F401

        print("SwarmGuard menu bar (AppKit) — leave this terminal open.", flush=True)
        print("  Open Protector → native panel (not browser).", flush=True)
        _run_appkit()
        return
    except ImportError as exc:
        sys.stderr.write(
            "\n[SWARMGUARD] Need rumps or PyObjC AppKit for the menu bar.\n"
            "  Option A: add rumps to the project venv, then ./run_menubar.sh\n"
            "  Option B: use Framework Python 3.13 (has AppKit) via ./run_menubar.sh\n"
            f"Detail: {exc}\n"
        )
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
