# SwarmGuard // ZERO — Win Plan
**Goal:** Place as high as possible in the Meta Global AI Developer Hackathon (Indie Track).  
**Deadline:** Tuesday, Nov 4, 2026 · 9:00 PM ET (submit by ~6:00 PM ET).  
**Today’s date when written:** Wednesday, Oct 28, 2026 → **~7 days left.**

Product name **SwarmGuard**; **ZERO** is the edition tagline (use sparingly). Brand mark + tokens: [`assets/brand/BRAND.md`](./assets/brand/BRAND.md) · mark: [`assets/brand/swarmguard-mark.png`](./assets/brand/swarmguard-mark.png).

This file is the single “make it make sense” plan. Everything else supports it:

| Doc | Job |
|-----|-----|
| `WIN_PLAN.md` (this) | Strategy + calendar + decisions |
| `assets/brand/BRAND.md` | Logo, color tokens, do/don’t |
| `swarmguard_zero_meta_hackathon_blueprint.md` | Product + threat research + do/don’t |
| `meta_model_api_muse_code_expert_guide.md` | How to use Meta stack at full capacity |
| `meta_hackathon_rules_daily_tracker.md` | Live rules / dates / credits |
| `README.md` | How a stranger runs the demo |

---

## 1. The winning idea in one breath

**Problem:** Developers now give AI agents terminals, files, and MCP tools. Traditional antivirus cannot see a prompt injection that says “steal `.env`.” That attack class is documented in the wild (Unit 42, HiddenLayer, OWASP MCP).

**Product:** SwarmGuard is **autonomous antivirus for agents** — fail-closed **IDE PreToolUse hook + MCP policy proxy on the wire**, plus Muse Spark *sees* poisoned artifacts, Muse Wonder *explains*, SAM *isolates*, then the swarm **quarantines without asking** and **reports**.

**Claim line:** *fail-closed on the wire + Meta multimodal forensics.*

```
Cursor / Claude Code → IDE hook (policy.py) ─┐
Agent MCP tools      → MCP proxy (policy.py) ─┴─ deny → threat_bus + protector UI
```

**Why Meta judges should care:**
- **Build for Your World** — firsthand builder pain (Cursor/agent + secrets).
- **Push the Frontier** — new control surface: runtime defense for agentic systems.
- **Meta tooling** — not one model bolted on; a *composed* Spark + Wonder + SAM pipeline on Model API.

**Indie track filter:** creativity + ambition + **it works**. Demo = **IDE + MCP hard deny** + **Attack 01 Meta path**.

---

## 2. How judging actually works (and how we score)

Public Indie framing: creativity, technical ambition, whether it works.  
Waiver-style weights (verify vs Official Rules PDF):

| Bucket | ~Weight | Our weapon | Must show on video |
|--------|---------|------------|--------------------|
| Impact | 30% | “AV is blind to agent hijacks” + real attack citations | Problem → consequence → SwarmGuard |
| Meta tooling | 25% | Spark multimodal + Wonder high + SAM on same artifact | Say model IDs out loud; chips on screen |
| Demo | 25% | Autonomous inject → chain → auto-quarantine → report | One continuous real run |
| Execution | 20% | Clean happy path, honest safety, readable repo | No crashes, no Tk detour |

**Winning formula:**  
`Clear stakes` × `Unexpected Meta combo` × `Flawless 90s demo` × `Honest scope`

**Losing formula:**  
`Feature zoo` × `Fragile desktop widget` × `LLM-only vibes with no action` × `Claims we can’t defend`

---

## 3. What we already have (assets, not homework)

Treat these as **done foundation**:

- Protector UI (`dashboard.py` + menu-bar mark) — inject → Muse pipeline → auto-quarantine → incident log + sounds (not a War Room game HUD)
- Brand assets (`assets/brand/`) — shield + swarm mark, menu-bar icon, tokens
- Multi-model brain (`swarm_brain.py`) — Spark guards (Overwatch multimodal), Wonder forensics, SAM boxes
- Autonomy + bus (`autonomy.py`, `threat_bus.py`, `sounds.py`)
- Live verification already proved: Overwatch *read* white-on-white text; Wonder quoted it; SAM boxed; auto-quarantine logged

**Do not rebuild.** Polish and productize the one path.

---

## 4. The north-star demo (this is the product)

**Locked 2-minute story: gate deny + Attack 01.**

```
1. Protector: “Protecting — gate on.”
2. IDE hooks live (Cursor `.cursor/hooks.json`) + start MCP proxy → UI: “MCP gate: wrapping tools.”
3. Agent tries read .env / exfil curl → HARD DENY (policy only; no Muse tokens).
4. Optional / second beat: See it work → Attack 01 poisoned README
       → Spark Overwatch (vision) + Bloodhound
       → Wonder forensics + SAM boxes
       → AUTO-QUARANTINE + activity log
5. Tagline: antivirus for agents — on the wire, with Meta eyes.
```

**Narration spine (≤2:00):**
1. Agents have terminals, files, and MCP tools; classic AV never sees the call.  
2. SwarmGuard sits in the IDE hook *and* on the MCP wire — `.env` theft dies at the gate.  
3. Meta Spark/Wonder/SAM still catch the *hidden* injection path.  
4. Indie track. SwarmGuard Zero.

Prove locally (no API):  
`python safe_range/run_mcp_gate_demo.py` · `python safe_range/run_ide_hook_demo.py`  

Honest limits: IDE hook soft-allows benign unknown paths/cmds so coding stays usable; MCP proxy remains hard fail-closed. No SIGKILL.

---

## 5. Strategic decisions (locked)

| Decision | Choice | Why |
|----------|--------|-----|
| Track | Indie solo | Matches status; ambition via idea not headcount |
| Theme | Lead **Build for Your World**, nod **Push the Frontier** | Personal agent-security pain + new control capability |
| Primary UI | macOS **menu-bar Protector** (`menubar.py` native NSPanel) | Quiet AV vibes; stay in-app |
| Optional deep console | Streamlit `dashboard.py` | Advanced / demo secondary — not required for core status |
| Primary behavior | IDE hook + MCP proxy deny-before-run + AI inspect + report | Feels like AV, not a SOC toy |
| Meta stack | Spark + Wonder + SAM on Model API | Maximizes tooling score |
| Muse on every tool call | **OFF** by default (`SWARMGUARD_MUSE_ON_AMBIGUOUS=0`) | Token discipline |
| Safety claim | Simulated quarantine; no real SIGKILL | Survives Q&A; still dramatic |
| Scope lock | Gate proof + Attack 01 > five half features | Indie judges punish sprawl |

---

## 6. Gap analysis — only build what moves score

### P0 — must ship (wins demo + tooling + execution)
1. **Bulletproof Attack 01** — structured JSON output (`response_format`) so forensics never parse-fail mid-demo.  
2. **Visible Muse proof** — on-screen model IDs + optional Wonder `reasoning.summary` line in the chain.  
3. **Record 2 takes** of the north-star demo; keep a known-good backup recording.  
4. **GitHub + README** that runs in 2 commands; commits inside Oct 26–Nov 4 window.  
5. **Submission writeup** mapped to Impact / Tooling / Demo / Execution.  
6. Confirm Official Rules accepted; claim partner credits only if needed for scale.

### P1 — if ≥1–2 days remain (raises tooling + impact credibility)
1. ~~Fail-closed policy layer~~ **Done** — `policy.py` + `threat_model.py` (16+ gate probes + Muse for injection).  
2. ~~MCP stdio policy proxy~~ **Done** — `mcp_proxy.py` + `safe_range/run_mcp_gate_demo.py` (deny before upstream; dashboard heartbeat).  
3. ~~IDE PreToolUse hook~~ **Done** — `hooks/swarmguard_pretool.py` + `.cursor/hooks.json` + `.claude/settings.json` + `safe_range/run_ide_hook_demo.py` (deny `.env` / evil curl; `trigger=ide_hook`).  
4. **Mission policy banner** — “goal: refactor UI → secrets/egress denied” (ClawGuard-inspired, visible).

### P2 — skip unless ahead of schedule
- Muse Image fixture generator, voice narration, Sunglasses-scale DLP encyclopedia, SSE stream DLP, cross-platform installers, Tk widget revival.

---

## 7. How the Meta stack should be framed (tooling score)

From the expert guide — **compose**, don’t sprinkle:

| Layer | Model | Job in the story |
|-------|--------|------------------|
| Perception | `muse-spark-1.3` | Specialist guards; Overwatch multimodal on artifact |
| Judgment | `muse-wonder-1.0` | Chief forensics, evidence quotes, high reasoning |
| Localization | `sam-3.1` | Pixel/box isolation of the trap |
| Build tooling | Muse Code (optional credit) | “We built faster with Muse Code” in writeup, not the demo hero |

**Say on video:** “muse-spark-1.3, muse-wonder-1.0, sam-3.1 on Meta Model API.”

**Protocol note:** Chat Completions is fine for one-shot guards; prefer Responses for Wonder if we add tool loops / reasoning summaries before submit.

---

## 8. Narrative for the written submission (copy base)

**Title:** SwarmGuard // ZERO — Autonomous Antivirus for the Agentic Era  

**Problem:** Indirect prompt injection and MCP tool abuse can turn trusted coding/browser agents into credential thieves. Classic AV looks for malware files, not hijacked tool calls. Research from Unit 42, HiddenLayer, and OWASP documents these attacks in the wild.

**Solution:** An IDE **PreToolUse hook** plus MCP stdio **policy proxy** that deny dangerous tool calls before they run, plus a Meta-powered swarm that scores threats with Muse Spark, synthesizes forensics with Muse Wonder, isolates visual traps with SAM 3.1, then **auto-quarantines and reports** without waiting for a human kill click.

**Meta usage:** Multimodal Spark (image+text), high-reasoning Wonder reports, SAM segmentation on the same artifact — one incident, three Meta surfaces.

**Track/theme:** Indie · Build for Your World (and frontier runtime control for agents).

**Safety:** Demo harness simulates rogue agents; host process inspection is read-only; we do not SIGKILL arbitrary OS processes.

---

## 9. Day-by-day calendar (Oct 29 → Nov 4)

| Day | Focus | Done when |
|-----|--------|-----------|
| **Thu Oct 29** | P0 reliability: structured output + demo dry run #1 | Attack 01 succeeds 3× in a row |
| **Fri Oct 30** | Polish protector proof chips / chain clarity; draft writeup | Writeup skeleton filled |
| **Sat Oct 31** | P1 fail-closed rules *or* polish only if tired | Either policy banner ships or consciously skipped |
| **Sun Nov 1** | Record demo takes (2+); pick best; upload draft private | Video file exists |
| **Mon Nov 2** | GitHub cleanup, README, screenshots, final writeup | Repo cloneable by a stranger |
| **Tue Nov 3** | Buffer / workshops / Official Rules re-read | Submission packet staged |
| **Wed Nov 4** | Submit by **6:00 PM ET**; do not touch code after | Portal confirmation saved |

Workshops/Discord: only attend if it unblocks credits or Official Rules — do not sacrifice the demo for FOMO.

### API spend discipline
Oct 28 stress runs burned most of a day’s Model API usage (~$1.80 / 225 requests). Remaining week:
- Do **not** re-run `python stress_test.py 3` casually (already proven 18/18).
- Practice/demo: Protector **Attack 01 only**, or `python stress_test.py smoke`.
- Claim partner credits (Fireworks/Modal/Baseten) if Meta Model API budget is tight — keep Meta API for the recorded demo.

---

## 10. Anti-goals (explicit)

- Do not make SwarmGuard a general malware scanner.  
- Do not auto-kill real user processes.  
- Do not center the Tk widget.  
- Menu-bar companion (`./run_menubar.sh`) is optional AV chrome — never call Muse from it; never SIGKILL.  
- Do not add dashboards, settings pages, or auth walls before the core loop is cinematic.  
- Do not burn API credits on continuous auto-fire during practice unless testing.  
- Do not claim “prompt injection solved.”

---

## 11. Submission packet checklist

- [ ] GitHub repo public (or accessible per rules) with hackathon-window commits  
- [ ] `README.md` run steps (venv → streamlit)  
- [ ] Demo video ≤2 min on YouTube/Loom/Vimeo — **real product**  
- [ ] Written description: problem, Meta architecture, track/theme  
- [ ] Disclose any boilerplate  
- [ ] Official Rules accepted  
- [ ] Submitted ≥3 hours early  

---

## 12. If we only do three things from here

1. **Make Attack 01 unbreakable** (structured output + rehearsal).  
2. **Record the autonomous demo** with model names spoken.  
3. **Ship a clean repo + rubric-shaped writeup.**

That is the highest-probability path to win Indie: one story, Meta-native intelligence, undeniable proof on video.

---

## 13. Operating rule for the remaining week

Every feature request must answer: **Does this make Attack 01 more convincing on a 2-minute judge screen?**  
If no → defer.

When uncertain, open this file first — not a new brainstorm.
