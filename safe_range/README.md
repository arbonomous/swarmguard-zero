# SwarmGuard Safe Range

Live-ish red-team probe that **cannot** hurt your real machine if you follow the rules.

## What this proves

A disposable “victim project” contains a poisoned README + **fake** canary secrets.  
A **rogue agent simulator** follows the injection (read canary → POST to localhost).  
A **localhost sink** records whether exfil would have happened.  
SwarmGuard then analyzes the **real artifact + real telemetry** from that run.

This is closer to a real threat than the War Room inject buttons. Production gates: IDE hook + MCP proxy (see repo README).

## Hard safety rules

1. **Only** fake secrets under `safe_range/victim_project/` (names contain `CANARY`).
2. Exfil target is **only** `http://127.0.0.1:8765/...` — never a public URL.
3. Do **not** point the rogue agent at your real `.env`, `~/.ssh`, Keychain, or wallet.
4. Do **not** open the victim project in an agent that has broad filesystem + network tools unless you accept residual risk (prefer the included simulator).
5. Keep your real Meta `MODEL_API_KEY` out of `victim_project/`.
6. **`SWARMGUARD_ENFORCE=1` (default)** — policy gate denies secret reads + egress (protects you).
7. **`SWARMGUARD_ENFORCE=0`** — lab-only mode so detection demos can complete a canary→localhost exfil.

## Prove enforcement (safe — no Muse tokens)

```bash
source .venv/bin/activate
python safe_range/run_enforcement_demo.py
python safe_range/run_mcp_gate_demo.py
python safe_range/run_ide_hook_demo.py
```

Expect: real `.env` / `~/.ssh` / public URLs DENY; canary exfil DENY under enforce; nothing harmful runs.  
MCP gate proof: proxy denies `.env` read + evil curl; `fake_mcp_upstream` call log stays empty for those attacks; `policy_deny` rows land in `incidents.jsonl`.  
IDE hook proof: simulated Cursor/Claude PreToolUse payloads for Read `.env` + curl evil → DENY; `trigger=ide_hook` incidents logged.

Wrap the fake upstream yourself:

```bash
python mcp_proxy.py -- python safe_range/fake_mcp_upstream.py
```

## Detection lab (enforce off for the canary path)

```bash
SWARMGUARD_ENFORCE=0 python safe_range/sink_server.py   # terminal 1 — or just start sink
# terminal 2:
SWARMGUARD_ENFORCE=0 python safe_range/rogue_agent.py
SWARMGUARD_ENFORCE=0 python safe_range/run_live_probe.py
```

Expect: sink logs a canary hit, SwarmGuard returns CRITICAL + quotes (uses Meta API).
