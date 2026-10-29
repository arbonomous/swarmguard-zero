# SwarmGuard

Protection for your computer against sneaky AI helpers — Meta Global AI Developer Hackathon (Indie Track).

**North star:** [`WIN_PLAN.md`](./WIN_PLAN.md) · Research: [`swarmguard_zero_meta_hackathon_blueprint.md`](./swarmguard_zero_meta_hackathon_blueprint.md) · Meta API: [`meta_model_api_muse_code_expert_guide.md`](./meta_model_api_muse_code_expert_guide.md)

## Claim

**Fail-closed on the wire + Meta multimodal forensics.**  
SwarmGuard is autonomous antivirus for agents: an IDE PreToolUse hook + MCP stdio policy proxy deny dangerous tool calls *before* they run, and a Meta Muse swarm (Spark + Wonder + SAM) sees concealed injections when you opt in.

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
5. **Protector UI** — status + MCP gate heartbeat + activity (IDE hook / MCP policy deny vs Muse quarantine)

Prove the gates (free, no Meta tokens):

```bash
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

## Run

```bash
cd swarmguard-zero
source .venv/bin/activate
streamlit run dashboard.py
```

You should see **Protecting this computer**, MCP gate idle/wrapping, and an activity feed.  
Optional: **See it work** → Attack 01 (uses Meta API credits).

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

1. Protector: **Protecting** — policy on; IDE hooks installed; start MCP proxy → UI shows **MCP gate: wrapping tools**.
2. Agent (or `run_ide_hook_demo.py` / `run_mcp_gate_demo.py`) tries `read .env` / evil curl → **hard deny** (no Muse needed).
3. Optional: **See it work** → Attack 01 poisoned README → Spark + SAM + Wonder report.
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
