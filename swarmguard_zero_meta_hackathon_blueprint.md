# SWARMGUARD // ZERO — Meta Hackathon Blueprint & Research Brief
**Tagline:** The autonomous antivirus swarm for the agentic era  
**Track:** Indie Developer · Themes: Build for Your World + Push the Frontier  
**Deadline:** Nov 4, 2026 · 9:00 PM ET · Prize pool $1M  
**Last research sync:** Oct 28, 2026  
**Win strategy (read first):** [`WIN_PLAN.md`](./WIN_PLAN.md)

---

## 0. One-sentence product

SwarmGuard watches local AI-agent activity, uses **Meta Muse Spark + Muse Wonder + SAM 3.1** to detect prompt-injected / MCP-abusive behavior, **auto-quarantines without asking**, then reports what it did — with sound cues and a War Room incident log.

Traditional AV looks for malware files. SwarmGuard looks for **hijacked agents**.

---

## 1. What we have built (current truth — Oct 28)

| Layer | Reality today |
|-------|----------------|
| War Room | Streamlit app — primary UI (in-app HUD, sounds, incident log) |
| Autonomy | Detect → freeze → **auto-quarantine** → report (no Kill approval required) |
| Bloodhound / Wiretap / Overwatch | Muse Spark guards; Overwatch is **multimodal** on artifact images |
| Forensics | Muse Wonder (`reasoning_effort=high`) with evidence quotes |
| Vision | SAM 3.1 isolation boxes + Spark visual findings |
| Safety | Simulated threats only; **never SIGKILL real OS processes**; process scan is read-only |
| Optional | Tk desktop widget — **demoted** (macOS Tk is fragile); do not depend on it for demo |

**Run only this:**
```bash
source .venv/bin/activate
streamlit run dashboard.py
```
Click **Enable sound** once → keep **Autonomous mode** on → **Inject event 01**.

---

## 2. Why this problem is real (research notes)

### 2.1 Indirect prompt injection is in the wild
- **Unit 42 (Palo Alto):** web-based indirect prompt injection observed live; concealment includes white-on-white, `opacity:0`, `font-size:0`, off-screen CSS, `display:none`, HTML comments.  
  Source: https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/
- **HiddenLayer:** hidden injections in repos/comments can hijack coding assistants (e.g. Cursor-class tools) when agents ingest project files.  
  Source: https://www.hiddenlayer.com/research/how-hidden-prompt-injections-can-hijack-ai-code-assistants-like-cursor
- **arXiv “Invisible Prompts, Visible Threats”:** malicious font / glyph tricks + MCP tool channels for sensitive data leakage.  
  Source: https://arxiv.org/html/2505.16957
- README / GitHub honeypot writeups show agents treating untrusted markdown as instructions.  
  Example: https://blog.tripvento.com/i-prompt-injected-my-own-github-readme

**Implication for us:** Attack 01 (poisoned README + white-on-white) is not a toy — it mirrors documented attack classes. Lead the demo with it. Expand concealment library later (opacity-0, zero-width, HTML comments — already partly in Attack 03).

### 2.2 MCP is a new attack surface (OWASP / Microsoft / MCP docs)
Common patterns from OWASP GenAI + MCP cheat sheets + Microsoft:
- **Tool poisoning** — malicious text in tool descriptions/schemas
- **Rug pulls** — tool changes after user approved it
- **Tool shadowing / cross-server escalation**
- **Confused deputy** — server runs with broad host privileges
- **Exfil via “legitimate” tools** — encode secrets into search/webhook args
- **Local MCP = full user privileges** unless sandboxed

Sources:
- https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html
- https://genai.owasp.org/ (Practical Guide for Third-Party MCP Servers PDF)
- https://developer.microsoft.com/blog/protecting-against-indirect-injection-attacks-mcp/
- https://modelcontextprotocol.io/docs/draft/tutorials/security/local-server-security

**Implication for us:** Attack 02 (MCP SSH exfil) maps cleanly to OWASP language. In copy/demo, say the words judges recognize: *tool poisoning, rug pull, least privilege, runtime enforcement*.

### 2.3 What serious defenses look like (so we don’t reinvent naively)
Research / industry consensus:

| Principle | What it means | SwarmGuard today | Gap / next move |
|-----------|----------------|------------------|-----------------|
| **Policy Enforcement Point (PEP)** | Tool calls blocked in the *execution path*, not only in the LLM’s “judgment” | Soft: we analyze + auto-quarantine demo agents | Hard: sit as gateway/proxy between agent and tools |
| **Deterministic > alignment-only** | Don’t trust the model alone to refuse bad actions | Hybrid: heuristics + Muse + auto action | Add allow/deny rules that fire even if Muse is down |
| **Fail closed** | If unsure / scanner down → deny risky tool | Partial | Explicit fail-closed policy for secret paths / egress |
| **Audit log** | Tamper-evident incident trail | `incidents.jsonl` | Show hash/timeline in UI + export for judges |
| **Task-scoped rules** (ClawGuard-style) | Derive allowed tools/paths from user goal before tools run | Not yet | Strong differentiator if we add “mission policy” |
| **Trace-as-program** (AgentArmor-style) | Inspect agent tool graphs for unsafe flows | Not yet | Nice “Push the Frontier” narrative later |

Key papers / systems to cite in writeup (not to clone):
- ClawGuard — runtime rules at every tool-call boundary (https://arxiv.org/html/2604.11790v2)
- AgentArmor — PDG / program analysis on agent traces (https://arxiv.org/pdf/2508.01249)
- OpenClaw PRISM — defense-in-depth hooks around tool lifecycle (https://arxiv.org/html/2603.11853)
- LLM Shield / AISBD — gateway mediation, fail-closed, don’t explain denials back to the agent

**Big strategic lesson:**  
LLM-only “antivirus scoring” is impressive in a demo but **weak as a sole control**. Winning narrative = *Muse for perception & forensics* + *deterministic quarantine policy* + *audit*. We already moved to autonomous eliminate+report — keep pushing enforcement credibility.

---

## 3. Meta hackathon scoring — play to the rubric

Public waiver-style weights (community roundups of Meta docs; verify against Official Rules PDF):

| Criterion | Weight | How SwarmGuard wins it | How we lose it |
|-----------|--------|------------------------|----------------|
| **Impact** | ~30% | Everyone giving agents terminal + MCP; AV is blind; first-hand builder pain | Sound like a science-fair chatbot wrapper |
| **Use of Meta tooling** | ~25% | Spark multimodal + Wonder high reasoning + SAM 3.1 on same artifact | Single model / text-only classification |
| **Demo quality** | ~25% | Autonomous loop with sound + visible chain + before/after SAM | Flaky Tk widget, silent failures, slideware |
| **Technical execution** | ~20% | Clean repo, reliable happy path, honest safety model | Broken imports, empty HUD, API truncations |

Indie lens: **creativity, ambition, and whether it works.**

Official pages:
- https://dev.meta.ai/events/global-hackathon
- https://cerebralvalley.ai/e/meta-ai-developer-hackathon

Partner credits (claim if useful): Fireworks / Modal / Baseten (~$100 each per live event page). Primary path remains **Meta Model API**.

### Tooling score tips (do)
- Name models on screen and in narration: `muse-spark-1.3`, `muse-wonder-1.0`, `sam-3.1`
- Show **unexpected** combo: vision reads camouflaged text → Wonder quotes it → SAM boxes it → swarm auto-quarantines
- Prefer Model API Standard mode (non-contributor) for privacy narrative unless credits force otherwise

### Tooling score tips (don’t)
- Don’t demo Fireworks-only if Meta API works — judges want Meta stack
- Don’t spend days on Muse Image unless it tells the security story
- Don’t let Muse burn all tokens on reasoning with empty JSON (keep completion headroom)

---

## 4. Positioning — what to say vs what not to claim

### Say (accurate + strong)
- “Runtime defense for coding/browser agents against indirect prompt injection and MCP abuse.”
- “Autonomous: detect, freeze, quarantine, report — no approval click in the hot path.”
- “Meta Muse sees the poisoned artifact; SAM isolates it; Wonder writes the forensics.”
- “Traditional AV doesn’t understand agent tool calls.”

### Don’t claim (will get destroyed in Q&A)
- “We replace CrowdStrike / stop all malware.”
- “We safely kill arbitrary OS processes by default.” (We deliberately don’t.)
- “Prompt injection is solved.” (Industry: assume injection eventually succeeds → contain blast radius.)
- “Production MCP gateway for enterprise” unless we actually proxy tool calls.

### Honest safety sentence for submission
> SwarmGuard’s auto-quarantine targets *simulated / instrumented agent threats* in the demo harness. Host process inspection is read-only. Real SIGKILL of user processes is out of scope for safety.

---

## 5. Competitive landscape (know the field)

Adjacent categories (not 1:1 competitors, but judges may compare):
- **Prompt shields / content classifiers** (e.g. Microsoft Prompt Shields) — filter text before the model; we focus on **local agent consequences** (files, egress, UI traps)
- **MCP security guides / sandboxes** — preventative config; we are **runtime response**
- **Runtime agent frameworks** (ClawGuard, PRISM, AgentArmor) — academic/infra; we are a **visible product HUD** with Meta multimodal story

**Our wedge:** consumer-visible **antivirus metaphor** + **multimodal Meta stack** + **autonomous eliminate+report** UX. Don’t try to out-paper ClawGuard in 7 days — out-demo them.

---

## 6. DO moving forward (prioritized)

### P0 — must before submission
1. **One flawless happy path:** Inject 01 → sounds → chain → SAM before/after → auto-quarantine report. Record it twice.
2. **Demo video ≤ 2 minutes**, real product only (no slides). Judges may never run the repo.
3. **Spoken Meta model names** + on-screen chips.
4. **GitHub repo** with work clearly in Oct 26–Nov 4 window; disclose any boilerplate.
5. **Written description** maps to Impact / Tooling / Demo / Execution explicitly.
6. Confirm Official Rules acceptance + claim partner credits if needed.

### P1 — high leverage if time
1. **Deterministic policy layer** alongside Muse: block `.env` / `~/.ssh` / webhook domains even if API fails (fail-closed).
2. **Richer concealment corpus** for Overwatch/SAM: opacity-0, font-size 0, off-screen, zero-width (Unit 42 list).
3. **Mission policy banner:** “User goal: refactor UI only → deny secret reads / egress” (ClawGuard-inspired, UI-visible).
4. **Incident export** (JSON/Markdown) for the submission zip / judges.
5. Optional: Muse Image to *generate* poisoned pages for the demo corpus (tooling depth) — only if stable.

### P2 — nice / post-hackathon
1. Real PEP proxy in front of MCP/stdio tools
2. Cross-platform packaged app
3. Tamper-evident log hashing
4. Windows/Linux parity

---

## 7. DON’T moving forward

1. **Don’t revive the Tk widget as the demo hero** — macOS system Tk painted blank / ate clicks; War Room is the product.
2. **Don’t require a Kill click** in the primary story — autonomy is the insight that “makes sense.”
3. **Don’t auto-SIGKILL real processes** — unsafe, demos badly if it bricks the machine, wrong threat model for a hackathon laptop.
4. **Don’t expand to 10 attack types** — three tight stories (README / MCP / webpage) beat a zoo of half-broken ones (JetBrains judging advice: one clear flow).
5. **Don’t leave Muse on `minimal` forever for Wonder** — forensics should look deep; guards can stay cheaper.
6. **Don’t burn credits on continuous auto-fire patrol** during recording unless intentional — toggle warns about API cost.
7. **Don’t hide failures** — if SAM falls back, say so; show one handled failure calmly (builds trust).
8. **Don’t use contributor/training mode models** in the privacy-sensitive security narrative if avoidable.

---

## 8. Demo script (autonomous — ~90–110 seconds)

Record War Room only (full browser). Enable sound before recording.

| Time | Visual | Narration |
|------|--------|-----------|
| 0:00–0:15 | Title / ARMED HUD | “Agents now have terminals and MCP tools. Traditional antivirus can’t see a prompt injection. SwarmGuard is autonomous antivirus for that world.” |
| 0:15–0:30 | Model chips Spark / Wonder / SAM | “Meta Muse Spark reads the artifact, Wonder writes forensics, SAM isolates the trap.” |
| 0:30–0:50 | Inject event 01 | “I only inject a poisoned README onto the wire — I don’t approve anything.” |
| 0:50–1:15 | Live chain + sounds + SAM before/after | “Overwatch sees the white-on-white instruction. Wonder quotes it. SAM boxes it.” |
| 1:15–1:35 | AUTO-QUARANTINED report | “No kill click. The swarm freezes the rogue agent, quarantines, and reports what it did.” |
| 1:35–1:45 | Incident log | “Every action is logged. Indie track — SwarmGuard Zero.” |

**Backup take:** pre-run once; if API flakes, keep a screen recording of a known-good run as emergency backup (still prefer live).

---

## 9. Architecture (target narrative for writeup)

```
[ Agent / MCP / poisoned artifact ]
              │
              ▼
     SwarmGuard sensor bus
      (telemetry + images)
              │
     ┌────────┴────────┐
     │  Muse Spark     │  specialist guards (multimodal Overwatch)
     │  Muse Wonder    │  chief forensics
     │  SAM 3.1        │  visual isolation
     └────────┬────────┘
              │
     Policy + auto-quarantine  ← keep strengthening (deterministic)
              │
     War Room HUD + sounds + incidents.jsonl
```

Env (Meta Model API):
```env
MODEL_API_KEY=...
META_BASE_URL=https://api.meta.ai/v1
META_GUARD_MODEL=muse-spark-1.3
META_FORENSIC_MODEL=muse-wonder-1.0
META_SAM_MODEL=sam-3.1
META_REASONING_EFFORT=low
META_FORENSIC_REASONING_EFFORT=high
```

---

## 10. Source library (bookmark)

### Threat intel
- Unit 42 IDPI in the wild: https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/
- HiddenLayer coding-assistant injections: https://www.hiddenlayer.com/research/how-hidden-prompt-injections-can-hijack-ai-code-assistants-like-cursor
- Invisible font injection paper: https://arxiv.org/html/2505.16957
- Microsoft prompt injection controls: https://learn.microsoft.com/en-us/security/zero-trust/catalog-ai-attack-techniques/prompt-injection
- Microsoft MCP indirect injection: https://developer.microsoft.com/blog/protecting-against-indirect-injection-attacks-mcp/

### MCP / standards
- OWASP MCP Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html
- MCP local server security: https://modelcontextprotocol.io/docs/draft/tutorials/security/local-server-security
- OWASP GenAI MCP third-party guide (PDF via genai.owasp.org)

### Runtime defense research
- ClawGuard: https://arxiv.org/html/2604.11790v2
- AgentArmor: https://arxiv.org/pdf/2508.01249
- OpenClaw PRISM: https://arxiv.org/html/2603.11853

### Hackathon
- Meta event: https://dev.meta.ai/events/global-hackathon
- Cerebral Valley: https://cerebralvalley.ai/e/meta-ai-developer-hackathon
- Roundup w/ scoring commentary: https://reconscribe.com/meta-global-ai-developer-hackathon-2026/
- Judging craft (general): https://blog.jetbrains.com/ai/2026/06/how-to-win-a-hackathon-notes-from-the-judging-table/

### Meta models
- **Internal expert guide (read this):** `meta_model_api_muse_code_expert_guide.md`
- Docs overview: https://dev.meta.ai/docs/overview
- Models overview: https://dev.meta.ai/docs/models
- Image understanding: https://dev.meta.ai/docs/image-understanding
- SAM / media segmentation: https://dev.meta.ai/docs/media-segmentation

---

## 11. Immediate next checklist

- [ ] Record autonomous Attack 01 demo (two takes) with sound
- [ ] Push clean GitHub repo + README that matches this blueprint
- [ ] Draft submission text using Impact / Tooling / Demo / Execution headings
- [ ] Add fail-closed path rules (P1) if >1 day remains
- [ ] Re-read Official Rules PDF day before submit
- [ ] Submit ≥3 hours early (Nov 4 9pm ET hard cutoff)

---

*This file is the working strategy doc. Prefer updating it when the product or research landscape shifts — not the outdated Tk-first instructions from the first draft.*
