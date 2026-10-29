#!/bin/zsh
# Launch SwarmGuard macOS menu-bar Protector (rumps or AppKit) — primary UX.
# Open Protector → native NSPanel (not browser). Streamlit is optional advanced console.
# Does not replace MCP proxy / Cursor hooks. Single process: exec + PID lock.
cd "$(dirname "$0")"
ROOT="$PWD"
export SWARMGUARD_MUSE_ON_AMBIGUOUS="${SWARMGUARD_MUSE_ON_AMBIGUOUS:-0}"
PID_FILE="${SWARMGUARD_MENUBAR_PID:-/tmp/swarmguard-menubar.pid}"

pick_python() {
  local vpy="$ROOT/.venv/bin/python"
  if [[ -x "$vpy" ]] && "$vpy" -c "import rumps" 2>/dev/null; then
    echo "$vpy"
    return 0
  fi
  # Framework Python ships PyObjC AppKit on this Mac (rumps optional).
  local fw="/Library/Frameworks/Python.framework/Versions/3.13/bin/python3"
  if [[ -x "$fw" ]] && "$fw" -c "import AppKit" 2>/dev/null; then
    echo "$fw"
    return 0
  fi
  if [[ -x "$vpy" ]] && "$vpy" -c "import AppKit" 2>/dev/null; then
    echo "$vpy"
    return 0
  fi
  return 1
}

if [[ -f "$PID_FILE" ]]; then
  old_pid="$(tr -d '[:space:]' <"$PID_FILE" 2>/dev/null || true)"
  if [[ "$old_pid" == <-> ]] && kill -0 "$old_pid" 2>/dev/null; then
    cmd="$(ps -p "$old_pid" -o command= 2>/dev/null || true)"
    if [[ "$cmd" == *menubar.py* ]]; then
      echo "[SWARMGUARD] Menu bar already running (pid $old_pid)."
      echo "  Quit via the SG / SG! menu → Quit SwarmGuard menu, then relaunch."
      echo "  Stale lock only: rm $PID_FILE"
      exit 0
    fi
  fi
fi

PY="$(pick_python)" || {
  echo "[SWARMGUARD] No rumps / AppKit Python found."
  echo "  Activate .venv and add rumps (see requirements.txt), or install PyObjC."
  exit 1
}

echo "Using: $PY"
# exec: one Python replaces this shell — never background a second copy here.
exec "$PY" "$ROOT/menubar.py"
