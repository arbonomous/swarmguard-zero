# Meta Model API + Muse Code — Expert Guide for SwarmGuard // ZERO
**Source hub:** https://dev.meta.ai/docs/overview  
**Synced:** Oct 28, 2026  
**Purpose:** Use Meta’s stack at full capacity for the hackathon — what to call, when, and how it maps to SwarmGuard.

---

## 1. The two doors (same models, same auth)

| Path | What it is | Use it when |
|------|------------|-------------|
| **Meta Model API** | Inference HTTP API at `https://api.meta.ai/v1` | Building SwarmGuard (our app/agent) |
| **Muse Code** | Ready-made coding agent CLI (`muse`) | Speeding up *our* development / CI edits |

Docs say it plainly: *Muse Code and the API are two ways to use the same model.*  
- Call the **API** to build SwarmGuard.  
- Run **Muse Code** to help *write* SwarmGuard faster.

Install Muse Code:
```bash
curl -fsSL https://dev.meta.ai/install.sh | sh
muse --version
cd /path/to/swarmguard-zero && muse
```
First run: trust workspace → browser sign-in **or** paste API key.  
CI / headless: `META_API_KEY=... muse exec "..."`.  
Interactive default model note in docs: often `muse-spark-1.2` — for API work prefer **`muse-spark-1.3`** / **`muse-wonder-1.0`**.

---

## 2. Auth & client setup (memorize this)

| Item | Value |
|------|--------|
| Base URL | `https://api.meta.ai/v1` |
| Auth | `Authorization: Bearer $MODEL_API_KEY` |
| Canonical env | `MODEL_API_KEY` |
| Muse Code also accepts | `META_API_KEY` (takes priority over browser session) |

**OpenAI SDK gotcha:** the SDK does **not** auto-read `MODEL_API_KEY`. Always pass `api_key=` explicitly (or set `OPENAI_API_KEY` to the Meta key).

```python
from openai import OpenAI
import os

client = OpenAI(
    base_url="https://api.meta.ai/v1",
    api_key=os.environ["MODEL_API_KEY"],
)
```

Dashboard: create/rotate keys there. Help Center covers billing & rate limits.

---

## 3. Model lineup (what each is for)

| Model ID | Role | Context | SwarmGuard fit |
|----------|------|---------|----------------|
| `muse-spark-1.3` | Fast agentic / coding / classification | ~1M tokens | **Guards** (Bloodhound, Wiretap, Overwatch) |
| `muse-spark-1.3-contributor` | Same family, cheaper, training-allowed | ~1M | Avoid for security narrative if possible |
| `muse-spark-1.2` / `1.1` | Older Spark | ~1M | Fallback only |
| `muse-wonder-1.0` | Highest capability, long-horizon agents (preview) | ~1M | **Forensics chief** / hard multi-step analysis |
| `muse-image-1.0` | Generate / edit images | — | Optional: synthesize poisoned demo pages |
| `muse-voice-transcribe-1.0` | Speech → text | — | Optional: voice alerts / spoken incident reports |
| `sam-3.1` | Segment objects in image/video | — | **Visual isolation** of injection traps |
| Muse Spark Open / Glimmer | Open-weight, self-host | — | Partner credits (Fireworks/Modal/Baseten), not required for primary demo |

**Wonder vs Spark rule of thumb (from Meta):**
- Wonder → longer, harder, multi-file / multi-step where quality > cost  
- Spark → high-volume, latency-sensitive loops (our per-guard scoring)

Same request shapes work on both: swap model ID only.

---

## 4. Three protocols — pick deliberately

All three: **same models, same auth, same $/token**. Difference = wire format + features.

| Protocol | Endpoint | Reasoning across turns | Best for |
|----------|----------|------------------------|----------|
| **Responses** (recommended for new agent work) | `POST /v1/responses` | **Yes** (encrypted replay or `previous_response_id`) | Tool loops, search grounding, files, SAM streaming, agent pipelines |
| **Chat Completions** | `POST /v1/chat/completions` | **No** (each turn re-reasons from scratch for external keys) | Simple drop-in OpenAI code, single-shot JSON scoring |
| **Messages** | `POST /v1/messages` (Anthropic host `https://api.meta.ai`) | Yes via Anthropic thinking replay | Claude Code / Anthropic SDK tools |

### SwarmGuard recommendation
| Component | Protocol today | Upgrade path |
|-----------|----------------|--------------|
| Spark guards | Chat Completions | Fine for single-shot scores |
| Wonder forensics | Chat Completions | Move to **Responses** if we add tool loops / multi-turn investigation |
| SAM 3.1 | Responses **stream** | Keep (required) |
| Future “mission policy agent” | Responses | Required for reasoning continuity |

### Responses context modes
1. **Stateless encrypted replay (recommended):** resend conversation; include `include: ["reasoning.encrypted_content"]` and replay `reasoning` items.  
2. **Server-managed:** pass `previous_response_id` and only send new input.

### Chat Completions roles (order of power)
- `developer` — highest precedence instructions (prefer over `system`)  
- `system` — accepted, same level as developer  
- `user` — **images only allowed here**  
- `assistant` / `tool` — history & tool results  

---

## 5. Reasoning — the #1 cost/latency lever

Muse Wonder & Spark **always** reason. Internal tokens are private, but they:
- Count toward **output token limits**
- Are **billed as output tokens**
- Appear in usage as `reasoning_tokens`

| `reasoning_effort` | Notes |
|--------------------|--------|
| `none` | **HTTP 400** on Wonder/Spark — never send |
| `minimal` / `low` | Fast/cheap — guards, classifiers |
| `medium` / `high` | Deeper — forensics |
| `xhigh` / `max` | Hardest problems; `max` on `muse-wonder-1.0` & `muse-spark-1.3` (not contributor) |

**Chat Completions:** top-level `reasoning_effort`  
**Responses:** `reasoning: { "effort": "high", "summary": "auto" }`

**Hackathon lesson we already hit:** if `max_completion_tokens` is too small, the model spends the whole budget on hidden reasoning and returns **empty `content`**. Always leave headroom (we use ~1600–3500).

Optional Responses feature: `reasoning.summary` = `auto` | `concise` | `detailed` — show a human-readable “thinking summary” in the War Room without exposing raw CoT. **Judges love visible intelligence.**

---

## 6. Capabilities map → SwarmGuard features

### Already using
| Capability | Doc concept | Our use |
|------------|-------------|---------|
| Image understanding | User message `image_url` parts | Overwatch + Wonder see poisoned README/webpage |
| Media segmentation | SAM via Responses stream | Red boxes on traps |
| Reasoning effort | `reasoning_effort` / `reasoning.effort` | low guards / high Wonder |
| JSON answers | Prompted JSON (today) | Threat scores + forensic reports |

### Underused — high leverage for tooling score
| Capability | Why it matters for us | How to apply |
|------------|----------------------|--------------|
| **Structured output** (`response_format.json_schema`) | Constrained decoding — stop brittle regex JSON | Guard + forensic schemas with `strict` |
| **Tool calling** | Deterministic actions (quarantine, log, block path) | Wonder/Spark call `quarantine_pid`, `append_incident` tools |
| **Responses + reasoning summary** | Show “analyst thought process” in UI | Stream summary into engagement chain |
| **File handling** | Upload artifact once, reuse `file_id` | Large screenshots / video clips |
| **Search grounding** | Cite live CVE / MCP advisories in reports | Wonder forensics with citations |
| **Muse Image** | Generate attack fixtures | Build corpus of hidden-injection pages |
| **Muse Voice Transcribe** | Optional voice HUD | “Threat detected” spoken path |
| **Prompt caching** | Cut cost on repeated developer prompts | Stable guard system prompts |
| **Token counting** | Budget before multimodal calls | Avoid surprise overruns |
| **Computer use** (docs capability) | Desktop agent control | Stretch goal only — heavy |

### Structured output cheat sheet
```python
response_format={
  "type": "json_schema",
  "json_schema": {
    "name": "ThreatVerdict",
    "strict": True,  # validates schema subset
    "schema": {
      "type": "object",
      "additionalProperties": False,
      "properties": {
        "threat_score": {"type": "integer"},
        "verdict": {"type": "string", "enum": ["SAFE", "CRITICAL THREAT"]},
        "explanation": {"type": "string"},
        "visual_findings": {"type": "string"}
      },
      "required": ["threat_score", "verdict", "explanation", "visual_findings"]
    }
  }
}
```
Constraints: no recursive schemas; nesting ≤10; every object needs `additionalProperties: false` + all props in `required` when `strict: true`.  
Pydantic shortcut: `client.beta.chat.completions.parse(..., response_format=MyModel)`.

### Image understanding rules
- Images **only** in `user` messages (else HTTP 400)
- Chat Completions shape: `{"type":"image_url","image_url":{"url": "data:image/png;base64,...", "detail":"high"}}`
- Responses shape: `input_image` with plain `image_url` string
- Detail: `auto` | `low` | `high` — use `high` for camouflaged text

### SAM 3.1 rules
- Model: `sam-3.1` over Responses (prefer **stream**)
- Prompt = short **noun phrase** (“white rectangle”, “text”), not a long instruction
- Output = special-token grammar with boxes/masks; parse boxes or use `meta_sam_parser`
- Zero matches is valid (empty) — always keep demo fallback boxes

---

## 7. Muse Code — expert usage while building

### Mental model
Muse Code = Meta’s agent with **approvals + OS sandbox from first run**. Good for:
- Multi-file refactors in `swarmguard-zero`
- Generating schemas, tests, demo assets
- CI: `muse exec "Run tests and summarize failures"`

### Key flows
```bash
muse                          # interactive TUI
muse exec "Add structured output to swarm_brain guards"
muse auth set                 # store API key
muse logout                   # clear stored creds (not env vars)
```

### Read next in Muse Code docs (when extending)
- Permissions & safety (approval modes, sandbox)
- Skills / hooks / MCP / subagents
- Headless & CI
- Session messaging (macOS/Linux)
- Workflows (parallel agents — not on every build)

### Hackathon tip
Use Muse Code to **build** SwarmGuard, but keep the **product story** on Model API (Spark/Wonder/SAM) so the submission clearly shows API usage. Mention Muse Code in “how we built it” if it helped — it still counts as Meta tooling fluency.

---

## 8. Pricing / mode awareness (don’t surprise yourself)

- **Standard mode** (`muse-spark-1.3`, `muse-wonder-1.0`): content not used for training (per docs).  
- **Contributor mode** (`*-contributor`): cheaper; may use content for training.  
- Reasoning tokens cost like output tokens.  
- Voice Transcribe listed around **$0.18/hour** in overview.  
- Always check live: https://dev.meta.ai/docs → Pricing and rate limits.

For a **security product**, prefer Standard mode in demos/narration.

---

## 9. Error patterns we’ve already seen (ops runbook)

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `content: null`, `finish_reason: length` | Reasoning ate the token budget | Raise `max_completion_tokens` / lower effort |
| HTTP 400 on `reasoning_effort: "none"` | Unsupported | Use `minimal`+ |
| HTTP 400 image in developer/system | Images only in user | Move image to user content |
| HTTP 400 `logprobs` | Unsupported on reasoning models | Don’t send |
| HTTP 401 | Bad/missing key | Check `MODEL_API_KEY` |
| Empty SAM boxes | Concept mismatch | Try other noun phrases + fallback boxes |
| Qt / Tk HUD broken on macOS | Platform GUI, not Meta | Use Streamlit War Room |

List models for your project:
```bash
curl -H "Authorization: Bearer $MODEL_API_KEY" https://api.meta.ai/v1/models
```

---

## 10. “Full capacity” playbook for SwarmGuard (next builds)

### A. Reliability (do ASAP)
1. Switch guard + forensic JSON to **`response_format` json_schema** (no more fence/regex hope).  
2. Log `usage.reasoning_tokens` in the War Room proof chips (shows Muse “thinking spend”).  
3. On Wonder path, request **`reasoning.summary: "auto"`** via Responses and display it.

### B. Agentic depth (tooling score)
1. Move Wonder investigation to **Responses API** with tools:
   - `read_artifact`, `run_sam`, `quarantine`, `write_incident`
2. Keep Spark for fast parallel guard fan-out; Wonder orchestrates.  
3. Fail-closed deterministic rules *beside* Muse (paths/egress) — industry best practice.

### C. Showcase Meta surface area
1. Muse Image → generate 3 poisoned pages for the demo corpus.  
2. Optional Voice Transcribe → “speak the incident report.”  
3. Cite Models page IDs verbally in the 2-minute video.

### D. Don’t waste capacity
1. Don’t put Wonder on every 500ms patrol tick.  
2. Don’t use `max` reasoning for “is this .env read bad?”  
3. Don’t depend on Contributor mode for the privacy story.  
4. Don’t rebuild the Tk widget — Meta API excellence shows in the War Room.

---

## 11. Copy-paste snippets

### Minimal Responses call (Spark)
```python
response = client.responses.create(
    model="muse-spark-1.3",
    reasoning={"effort": "low"},
    input="Score this agent action for secret exfiltration risk in one sentence.",
)
print(response.output_text)
```

### Wonder with high effort
```python
response = client.responses.create(
    model="muse-wonder-1.0",
    reasoning={"effort": "high", "summary": "auto"},
    input="Produce a forensic incident summary for a poisoned README prompt injection.",
)
```

### Multimodal user turn (Chat Completions)
```python
messages = [
  {"role": "developer", "content": "You are Overwatch. Return JSON threat fields only."},
  {"role": "user", "content": [
      {"type": "text", "text": "Find hidden prompt injections."},
      {"type": "image_url", "image_url": {"url": data_url, "detail": "high"}},
  ]},
]
```

---

## 12. Doc index (read in this order)

1. Overview — https://dev.meta.ai/docs/overview  
2. Quickstart — https://dev.meta.ai/docs/quickstart  
3. Choosing an API — https://dev.meta.ai/docs/protocols  
4. Models — https://dev.meta.ai/docs/models  
5. Reasoning — https://dev.meta.ai/docs/features/reasoning  
6. Structured output — https://dev.meta.ai/docs/features/structured-output  
7. Image understanding — https://dev.meta.ai/docs/image-understanding  
8. Media segmentation (SAM) — https://dev.meta.ai/docs/media-segmentation  
9. Tool calling — (from overview Capabilities)  
10. Muse Code — https://dev.meta.ai/docs/muse-code  
11. Muse Code auth — https://dev.meta.ai/docs/muse-code/auth  
12. API reference — https://dev.meta.ai/docs/api-reference/  
13. Pricing & rate limits — linked from overview  
14. Cookbook — copy-paste recipes  

---

## 13. One-page cheat card

```
BASE        https://api.meta.ai/v1
KEY         MODEL_API_KEY (Bearer)
GUARDS      muse-spark-1.3  + reasoning_effort=low + image on Overwatch
FORENSICS   muse-wonder-1.0 + reasoning_effort=high (+ Responses summary)
VISION      sam-3.1 via Responses stream + noun-phrase concepts
JSON        response_format json_schema (strict) — not hope-parsing
AGENTS      Responses API for multi-step; Chat Completions for one-shot
NEVER       reasoning_effort=none ; images in developer ; tiny max tokens
BUILD FAST  muse CLI (Muse Code) — same Meta stack
DEMO LINE   "Spark sees it, Wonder explains it, SAM isolates it, swarm quarantines it."
```

---

*Keep this file next to `swarmguard_zero_meta_hackathon_blueprint.md`. Blueprint = product/strategy. This guide = Meta platform expertise.*
