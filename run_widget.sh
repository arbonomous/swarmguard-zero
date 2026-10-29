#!/bin/zsh
# Launch the floating HUD with macOS system Python (has Tk).
cd "$(dirname "$0")"
export TK_SILENCE_DEPRECATION=1
exec /usr/bin/python3 widget.py
