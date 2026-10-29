# SwarmGuard

<p align="center">
  <img src="assets/brand/swarmguard-mark.png" alt="SwarmGuard mark" width="96" />
</p>

A scoped policy gate for AI-agent tools - Meta Global AI Developer Hackathon (Indie Track). Not OS-wide antivirus.

**Brand:** [`assets/brand/BRAND.md`](./assets/brand/BRAND.md) · **North star:** [`WIN_PLAN.md`](./WIN_PLAN.md) · Research: [`swarmguard_zero_meta_hackathon_blueprint.md`](./swarmguard_zero_meta_hackathon_blueprint.md) · Meta API: [`meta_model_api_muse_code_expert_guide.md`](./meta_model_api_muse_code_expert_guide.md)

## Claim

**Fail-closed on the wire + Meta multimodal forensics.**  
SwarmGuard is a scoped agent-tool gate: an IDE PreToolUse hook + MCP stdio policy proxy deny dangerous tool calls *before* they run, and a Meta Muse swarm (Spark + Wonder + SAM) sees concealed injections when you opt in.

```
Cursor / Claude Code  →  IDE hook (hooks/swarmguard_pretool.py)
Agent MCP tools       →  MCP proxy (mcp_proxy.py)
                              │ both → policy.py
                              ▼ deny
                       threat_bus + protector UI
```

## What it is

1. **IDE policy hook** — Cursor `.cursor/hooks.json` + Claude Code `.claude/settings.json` run `hooks/swarmguard_pretool.py` on PreToolUse / shell / read / MCP; denies `.env` reads and evil curl; logs `policy_deny` with `trigger=ide_hook`
2. **MCP policy proxy** — `mcp_proxy.py` intercepts `tools/call`, runs `policy.evaluate_tool_call`, denies before upstream, logs `policy_deny` incidents
3. **Policy catalog** — 16+ attack classes with no API spend — see `threat_model.py`
4. **Meta AI swarm** — Muse Spark + Wonder + SAM inspect poisoned docs / helper behavior
5. **Protector UI** — macOS menu-bar native panel (primary) + optional Streamlit deep console; status + MCP gate heartbeat + activity (IDE hook / MCP policy deny vs Muse quarantine)

The status label confirms policy configuration only, not that IDE hooks have run or that the whole computer is protected. The MCP heartbeat confirms a running wrapper, not coverage of other tools. IDE command matching is heuristic and can be bypassed by scripts or obfuscation. Strict MCP defaults currently deny unrecognized calls, including normal reads; configure/review policy before using it for everyday work.

Prove the gates (free, no Meta tokens):

```bash
python -m unittest discover -s tests -v  # independent stdio and status regressions
python safe_range/run_enforcement_demo.py   # catalog + rogue
python safe_range/run_mcp_gate_demo.py      # proxy denies .env/exfil; upstream never sees them
python safe_range/run_ide_hook_demo.py      # IDE hook denies Read .env + curl evil
```

### IDE hook install (this repo)

Already checked in:

| Surface | Path |
|---------|------|
| Hook script | `hooks/swarmguard_pretool.py` |
| Cursor project hooks | `.cursor/hooks.json` → `python3 hooks/swarmguard_pretool.py` (`failClosed: true`) |
| Claude Code project hooks | `.claude/settings.json` → same script via `$CLAUDE_PROJECT_DIR` |

Cursor reloads hooks on save (or restart Cursor). Confirm in **Cursor Settings → Hooks**.  
Optional user-wide Cursor install: copy/merge into `~/.cursor/hooks.json` with a command that points at this repo’s absolute script path (project hooks are preferred so other workspaces stay unaffected).

**Honest limits:** the IDE hook soft-allows pure “unknown path/cmd” so normal coding still works; catalog denials (secrets, egress, reverse shells, …) still block. MCP proxy stays hard fail-closed for untrusted tools. Cloud/remote agents may not deliver hook stdin (known Cursor limitation). Hooks only apply where Cursor/Claude Code loads this project’s config.

## Run (menu-bar first)

Primary UX on macOS is the **menu-bar Protector** — quiet AV vibes, native in-app panel (not a browser).

```bash
cd swarmguard-zero
./run_menubar.sh
```

1. Look for the **SwarmGuard mark** in the menu bar (`assets/brand/swarmguard-icon-menu.png`) — status suffixes `!` / `·` when denials or enforce-off.
2. Click the status item → **Open Protector** to toggle the native panel (mark + SwarmGuard title, status, MCP gate, recent denials, Refresh, Run free proofs).
3. **Open full console (advanced)…** is optional — launches Streamlit `dashboard.py` in a browser for the deep console.
4. **Refresh the icon:** menu → **Quit SwarmGuard menu**, then `./run_menubar.sh` again. Stale lock only: `rm /tmp/swarmguard-menubar.pid`.

Brand tokens/usage: [`assets/brand/BRAND.md`](./assets/brand/BRAND.md). Mark + popout mock generated with **Muse Image** (`python tools/generate_brand_muse.py`). Runtime menu bar / Protector panel make **no Muse calls**. Single status item + PID lock (`/tmp/swarmguard-menubar.pid`).

Install rumps into the venv when you can (`rumps` is in `requirements.txt`). If rumps is missing, `run_menubar.sh` falls back to Framework Python 3.13 + AppKit/PyObjC when present.

### Optional deep console (Streamlit)

```bash
source .venv/bin/activate
streamlit run dashboard.py
```

Browser console: **Scoped agent-tool policy**, MCP gate idle/wrapping, activity feed, optional Attack 01 (Meta API credits). The MCP proxy and Cursor/Claude hooks are unchanged — menu bar does not replace them.

The stdio wrapper uses newline-delimited JSON-RPC per the [MCP transport specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports). It does not use Content-Length framing.

### Wrap a real (or fake) MCP server

```bash
# Proof / demo upstream
python mcp_proxy.py -- python safe_range/fake_mcp_upstream.py

# Or: python -m swarmguard_mcp -- <your-mcp-server> [args...]
```

Env flags:

| Flag | Default | Meaning |
|------|---------|---------|
| `SWARMGUARD_ENFORCE` | `1` | Fail-closed policy |
| `SWARMGUARD_MUSE_ON_AMBIGUOUS` | `0` | Optional low-cost Spark on poisoned `tools/list` / ambiguous results (off = token discipline) |

## 2-minute demo story

1. Menu bar **Open Protector**: **Policy ON · scoped hooks only**; start MCP proxy → panel shows **MCP gate: wrapping**.
2. Agent (or menu **Run free proofs** / `run_ide_hook_demo.py` / `run_mcp_gate_demo.py`) tries `read .env` / evil curl → **hard deny** (no Muse needed); denials appear in the panel.
3. Optional advanced: Streamlit **See it work** → Attack 01 poisoned README → Spark + SAM + Wonder report.
4. Tagline: antivirus for agents — on the wire, with Meta eyes.

## Safety

- Policy defaults to `SWARMGUARD_ENFORCE=1`
- Demos are simulated; we never SIGKILL real OS processes
- Safe-range canary lab: `safe_range/README.md`

## Meta stack

| Role | Model |
|------|--------|
| Guards | `muse-spark-1.3` |
| Forensics | `muse-wonder-1.0` |
| Vision | `sam-3.1` |
