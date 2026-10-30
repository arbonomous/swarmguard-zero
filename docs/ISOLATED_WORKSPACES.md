# Isolated scratch workspaces (experimental)

This launcher is agent-neutral. It runs a Linux command or agent already present
in a trusted local image inside a short-lived OrbStack container. It does not
monitor other agents on the Mac and is not protection against every attack.

## Boundary

- Explicit `orbstack` Docker context per command; no global context change.
- No automatic image download, package install, model call, or key forwarding.
- No Mac folder, Docker socket, SSH agent, device, or existing volume mounts.
- Network disabled, root filesystem read-only, unprivileged user 65534.
- All Linux capabilities dropped; privilege escalation disabled.
- Private process/IPC namespaces, 64-process limit, 256 MiB RAM/swap limit, 1 CPU.
- Only a temporary 32 MiB `/tmp` is writable; no executable files there.
- Image entrypoint replaced with the explicit executable you select.
- Images declaring volumes are rejected. Container settings are inspected before
  start. A mismatch refuses launch, with no direct-on-host fallback.
- At most 300 seconds; cleanup removes only the uniquely named container created
  for that run. No pruning or changes to existing environments.

## First use

OrbStack must already be installed/running and the Docker CLI available.
List local images without downloading anything:

```sh
docker --context orbstack image ls --format '{{.Repository}}:{{.Tag}}'
```

Select an image you trust that already has the executable you need. For example,
if a local image contains `/bin/sh`, replace `YOUR_LOCAL_IMAGE` below:

```sh
python3 isolated_runner.py --image YOUR_LOCAL_IMAGE -- /bin/sh -c 'echo inside-swarmguard; id; touch /tmp/scratch-ok'
```

The first supported mode is intentionally offline scratch only. Do not mount
private project directories or pass credentials to work around its restrictions.
It cannot run a network-dependent cloud agent yet. No output files persist after
cleanup; command stdout/stderr is returned to the terminal after the run.

## Required verification

Unit tests verify argument construction and rejection of unsafe inspected
settings, not live enforcement. Before claiming containment on a Mac, test the
actual local runtime with synthetic files and network probes. Check expected
scratch writes work while root writes, host mounts, external networking and
Docker-socket access fail. A failed probe is a blocker, not a warning to bypass.

Container isolation is not a guarantee against malicious images, kernel/runtime
vulnerabilities or escape. OrbStack shares its Linux kernel between workloads.
Do not use this experimental launcher for deliberately hostile malware. Agents
running elsewhere remain outside this boundary. Host-wide enforcement needs a
separate supported macOS security architecture and installation consent.

## Sources

- https://docs.orbstack.dev/docker/
- https://docs.orbstack.dev/docker/network
- https://docs.orbstack.dev/docker/file-sharing
- https://docs.orbstack.dev/architecture
- https://docs.docker.com/reference/cli/docker/container/run/

## In-app check

The advanced console now has **Check offline isolation**. It uses the exact
Redis image fingerprint matched to Docker Hub's official library/redis registry
on October 29, 2026, only if already local. It does not install a test image.
The check covers scratch writes, read-only root, loopback-only interfaces,
common host/socket path absence, zero effective capabilities, no-new-privileges
and leftover labeled containers. Missing runtime/image or failed checks remain
failures, never automatic fallback. Results show the check time and scoped tests,
not a persistent whole-computer protection badge.

A local OrbStack test passed the startup, scratch and restriction probes on
October 29, 2026. That is one machine/runtime observation, not proof for every machine or
against hostile kernel/container escape. No external exfiltration request was sent.

## Network-dependent agents: not enabled

No network-enabled mode is implemented. Do not replace `--network=none` with a
bridge to make cloud agents work. A future broker should keep credentials on the
host, accept only a narrow model request schema, use fixed provider endpoints,
reject caller-chosen URLs/headers and arbitrary tool forwarding, cap request and
response bytes, cap calls/cost/time, and default to no inference without approval.
Domain allowlisting alone cannot stop private text being sent to an allowed model
API. Tools and project imports/exports need separate policy and explicit scope.

A broker must have synthetic offline transport tests first, then a separately
approved local network test before any provider request. Existing API keys are
not permission to spend. This is a design constraint, not a claim that a broker
or usable cloud-agent workspace already exists.

## Copied source workspace (experimental)

The advanced console offers an explicit file picker, an absolute in-image command
and requested output paths. Review those exact values before starting. Changing
any value resets the review checkbox. Only selected UTF-8 source files cross the
boundary: 200 files, 1 MiB each, 4 MiB total. Hidden paths, credential-like names,
likely credential content, binary files and symlinks are rejected. Detection is
not exhaustive; do not select private material because a scanner appears clear.

Imports use a bounded archive into scratch, not host mounts. The selected command
runs offline for at most 120 seconds. The container is paused before output
collection to prevent background-process races. Returned files are size/type/path
checked without extracting an untrusted archive onto the host. No device, symlink,
hardlink, traversal or duplicate archive entries are accepted. Selected outputs
are provided as a download for review, never written over the source project.
Cleanup targets only the run's generated name. The image must already be local;
commands/tooling absent from it simply fail. The pinned Redis test image does not
contain a cloud agent, so this is an explicit offline source-command workspace,
not a working general AI agent installation. Live copied-transfer integration on
OrbStack still needs testing; the earlier restriction probes did not test this
new transfer path.

Docker copy behavior: https://docs.docker.com/reference/cli/docker/container/cp/
Pause/freezer behavior: https://docs.docker.com/reference/cli/docker/container/pause/


The native menu now has **Offline workspace (experimental)**, opening the
workspace section of the local advanced console. Opening it runs nothing.
**Run complete offline check** performs the synthetic restrictions check and
copied input/command/paused export/cleanup roundtrip in one click. No private
files are used. Native-menu rendering and this combined workflow still require
Mac verification after updating; unit tests are not that verification.

Workspace bounds: 20 requested output files, 4 MiB combined imported/exported
text, 1 MiB per source file, 1 MiB command output, 6 MiB archive stream. Each
Docker operation and the full workflow have deadlines; cleanup has its own
15-second attempt even when the workflow deadline expires. A cleanup failure
names the exact generated container for attention, never prunes other workloads.

## Native menu workflow

The menu workspace action now opens an AppKit panel owned by the menu app,
not Streamlit or a browser. The Protector panel's workspace action uses the same
native panel; the normal menu no longer has a dashboard entry. The dashboard
source is retained as a development surface, not the primary user workflow.
Native file selection reads only selected source; a modal review confirms the
exact byte snapshot, command and output names before execution. Native save
creates a new archive and refuses to overwrite an existing file. Menu Quit waits
while the workspace is busy so ordinary quitting does not interrupt cleanup.
Keep the launcher Terminal open during a run; forced process termination can
still interrupt cleanup. Missing AppKit/runtime/image fails, never installs.

This native layout is source/unit-checked only until inspected on a real Mac.
The next verification is one native **Run complete offline check** and a screenshot
of the native results. It combines the existing restriction probes and synthetic
copy/execute/pause/export/cleanup without private project files.

Native migration preview adds a compact section picker: scoped status, attack
catalog, synthetic policy checks, activity/evidence, latest analysis, workspace
and model/about details. Optional synthetic AI scenarios require a separate
credit-use confirmation, and missing analysis dependencies do not auto-install.
Sound preview and notice acknowledgement stay native. A native image viewer
opens only fixed local synthetic artifacts, never arbitrary incident-supplied
paths. Visual box overlays/live multi-step trace presentation are not yet at
full dashboard parity. Native pixel/layout checks and combined copied-workspace
runtime verification remain required on Mac. Do not describe this preview as a
finished visual migration or general computer protection.

The top-level menu preview uses plain status rather than environment variables or
raw rule IDs. Historical tool denials are summarized once and explicitly may
include tests; they do not trigger an attack-alert badge. Status/activity and
isolated-workspace actions select their native sections directly. No active tool
connection means no connected-tool protection is confirmed, regardless of policy
configuration. Menu labels/layout still need an actual Mac screenshot check.

## End-to-end native preview flow

1. Click the shared shield mark. The dropdown contains only basic commands:
   Open SwarmGuard, Safety check, Activity, Workspace, Quit.
2. Open SwarmGuard shows native status with the same shield and a primary Run
   safety check action. Tool-connection and scope explanations live here, not as
   diagnostic rows flooding the dropdown.
3. Safety check opens its native section in the popout without silently starting.
   Run shows a waiting state while restrictions/copy/export/cleanup complete.
4. The result stays in the popout, with pass/attention, tested scope and next
   action. Failure says not to bypass restrictions. Activity/details are separate.
5. Workspace explicitly selects/reviews source copies and exports. Originals are
   never overwritten. API demos are secondary and require credit-use confirmation.

The panel anchors below the status item when that anchor is available. Pixel
placement on macOS still requires verification. Asset previews are real rendered
light/dark small-alpha checks, not a substitute for native screenshot validation.

## Managed guard core (experimental)

`managed_guard.py` is a persistent supervisor for one owned, protocol-speaking
workload. It is not the prior rotating `autonomy.py` scenario demo. The managed
workload emits one JSON tool request per line and receives a broker response.
Only `read_source` on explicit imported files and `write_artifact` into bounded
in-memory output are implemented. No arbitrary host path, shell, network or key
forwarding tool exists. Protocol-speaking agents can use this boundary without
an IDE-specific hook. Other code inside the container still has the container's
restricted Linux filesystem; broker denial is not a replacement for isolation.

The supervisor owns the generated container, applies policy before any broker
effect, and on a forbidden/malformed request or limit stops only that workload.
It inspects stopped state and checks that its exact container name disappears
after removal. Evidence distinguishes allowed requests, denied-with-no-effect,
stopping, verified stopped and removal. Missing verification is failure.
It runs while the workload is active, not as a repeated canned patrol. The Mac
menu app is not an always-on security daemon and this does not cover other agents.

The native primary action **Test managed guard** uses a synthetic shell workload:
read synthetic selected source, produce an output artifact, request an unavailable
host-file tool, then try a later artifact. The proof requires the first artifact,
the denial, verified workload stop/removal, and absence of the later artifact.
No real SSH key is opened: the denied path is protocol data and no host-file tool
is implemented. The workload is synthetic; the stop/prevention is real only when
verified against a live runtime. Local tests use a real subprocess stream and
mocked Docker lifecycle. Live OrbStack verification is still required before
claiming this proof passed on Mac. No intelligent cloud agent is installed or
called; model investigation remains a separate explicitly approved future layer.


## Disabled Meta adapter

`meta_agent.py` is source-only preparation, not connected to a menu action or CLI.
No live API call was used to test it. Tests mock provider replies. Before calling
it, verify current credit balance, billing/overage controls and the user's exact
spending permission. Token/turn caps are not a promise of zero charges.

The adapter keeps the existing key in the host environment, uses only the fixed
Meta endpoint and Spark model, and offers only Broker-mediated source/artifact
functions. It ends its model session on denial. This host-session adapter does
not claim container isolation, termination of an independently running agent, or
whole-Mac protection. A narrow host inference RPC bridge for a container worker
is separate unfinished work. No key belongs inside that worker.


## Prepared managed-model bridge (not live-verified)

`managed_model.py` joins host-only inference to the existing offline Guard. It is
not connected to ordinary native actions or a CLI and defaults to refusing use.
A new explicitly bounded live-inference approval is required. The previous
one-run model test permission is consumed, not reused by this module.

A fixed shell relay in the owned network-disabled container asks for the next
model step and echoes the returned structured tool request. The host retains the
provider key and conversation, contacts only Meta's fixed endpoint/model, then
checks the exact echoed request through the Broker. Out-of-order inference or
substitution is denied. No source/model text is evaluated as shell. A denied
request bubbles into the same scoped stop/inspect/remove checks as the scripted
proof. The worker is an agent-protocol relay, not a local model installation.

Limits: three model turns, 1600 completion tokens per turn, 20-second provider
timeout with retries disabled, bounded source/context/tool output and existing
90-second Guard runtime. These are engineering limits, not a provider dollar cap.
The fixed provider SDK call is synchronous, so a request already in flight can
finish or hit its own timeout before the supervisor handles a later deadline.
No network/key is given to the worker. Host and daemon remain trusted.

Dry tests use mocked provider responses and Docker control plus a real local
relay subprocess. They prove wiring, exact-request matching and cleanup calls,
not live container/model enforcement. A future live injection check must report
the model's actual behavior. Ignoring an injected instruction is not evidence
that an attack tool request was denied. Deterministic enforcement proofs stay
labeled separately from model-choice observations.

### Native one-run AI task

In the native panel's dropdown, choose **AI task**, then **Review AI task...**.
Opening this view does not call Meta. The fixed project `.venv/bin/python` checks
only local dependencies and the existing host-local key. Nothing is installed.
The approval sheet has Cancel as its default and displays scope, billing risk,
request/token limits, the exact synthetic sales source and its fake instruction.
Only **Approve one paid run** launches one task. No review choice is remembered,
no automatic retries occur, and a failed/missing result must not be rerun blindly.

The key and provider connection stay on the host. A fixed offline OrbStack relay
is created per task, not a persistent protection service. Progress shows worker
start, model/tool steps, stop and removal. A short task may disappear from OrbStack
before its list is noticed; verified removal means no container remains.

The normal result separately checks JSON sales totals (20 units, $100), model
completion, denial and cleanup. A task with no denied request is never presented
as a blocked attack. A protocol denial alone is not proof of an attack either.
Show details exposes usage and event evidence; Copy results copies the visible
review text. Output remains untrusted and is never applied to a project.
`synthetic_workload=false` describes real model execution, not real input data:
this native task explicitly records `synthetic_input=true` and
`synthetic_injection=true`. No private user source is selected or uploaded.

Tests use fake clients/process output only. Actual macOS layout, first-click
presentation, review scrolling, Cancel and live progress require a Mac checkpoint.
A live run requires a new one-run approval; earlier run approvals are consumed.

### Paid native execution paused (supersedes the live UI steps above)

An unexpected native run occurred during a review-and-cancel checkpoint. The
cause is unresolved. The separate run's worker cleanup was verified, but that
does not establish approval. Do not describe this as a confirmed Cancel defect
or infer a user click. All native paid execution gates remain disabled.

The replacement UI is nonpaying only:

1. **Review only...** displays the fixed task and synthetic source. It has only
   **Close review - no task**. No modal result can start a model or worker.
2. A distinct **Check start - no spend** control consumes an in-memory one-use
   review receipt bound to the source bytes/names and task hash. It checks the
   binding and records zero requests/no worker. It cannot approve spending.
3. Reopening review invalidates the earlier receipt. Changed input, a substituted
   receipt, missing receipt or replay fails closed. Consumption happens before
   any continuation. The receipt is not a token usable by the paid worker.

Audit data holds a random run ID, hashes, times and the nonpaying action. It does
not contain keys, source text, task text or private project files. No inference,
key preflight, subprocess or container is connected to either replacement UI
control. The existing live implementation stays behind its disabled gates.

Automated dry tests do not resolve the old event or authorize re-enabling paid
execution. Future checkpoints: inspect actual Mac review/start layout and
nonpaying behavior, resolve the approval-path uncertainty, then get a separate
new user decision before any live task. No further user test is currently asked.


### Native pause audit (October 30)

The separate legacy AI demo control was not covered by the native task pause.
It is now disabled and its callback is inert. The shared native worker launcher
accepts only offline workspace/check kinds and refuses model/demo/unknown kinds
before changing UI state or starting a thread. This closes a leftover route; it
does not explain the earlier unexpected task result.

The Mac review and separate nonpaying check at db08f89 were observed working:
the reported check consumed one receipt with zero model requests and no worker.
That is not a spending approval. Native paid tasks and demos remain paused.
The review alert now explicitly uses the existing shield mark; its new Mac
appearance has not yet been visually verified.

This is a native-menu safety boundary, not a repository-wide inference kill
switch. The separately launched browser dashboard, stress-test scripts,
managed_model/meta_agent functions and analysis APIs retain paid-capable paths.
Do not run them as an alternative to the paused native controls. No new paid
execution is authorized by this patch. Existing hooks/proxy policy routes are
not changed by it.


### Durable nonpaying coordinator

`execution_gate.py` is a dry-only coordinator, now used by the native review and
separate no-spend check. It has no provider/client/worker imports. Paid dispatch
always refuses. It does not turn a review receipt into spending authority.

A frozen run manifest hashes source/task, provider/model, tool schema, fixed
image/command, request/token/context limits, no retries and billing warning.
Pending state expires after two minutes and never survives coordinator restart.
A distinct dry start is required. Claims commit in SQLite with FULL synchronous
mode before any dry callback; replay, concurrent starts and changed manifests
fail closed. A failure after claim is unknown/spent, not retryable. Request
reservations are durable and occur before a future request seam, not after it.
The private database contains only random run IDs, hashes, lifecycle timestamps,
state and request counts. No task/source text, model content or credentials.
One coordinator owns this database; creating another invalidates pending state.

Tests cover cancellation/close/escape as adapter cancellation events, replacement,
expiry, changed manifest fields, forged/replayed identity, concurrent claims,
restart, crash/unreadable result, storage failure, request budgets and the exact
native dry handler. These are mocked/isolated tests, not proof of actual AppKit
input-event semantics. Existing Mac no-spend evidence predates this adapter.
No additional Mac check is requested for this change.

Still absent: a trusted paid-approval UI adapter, authenticated private worker
handoff, worker-side manifest enforcement and provider integration consuming the
same request budget. There is deliberately no working paid dispatch to bypass
these missing pieces. Native paid paths stay off. The legacy `--approved-once`
path is still disabled; it must be removed/replaced before any paid re-enable.
This coordinator is an accidental/reentrant-launch boundary, not protection
against arbitrary same-user host code or a repo-wide provider kill switch.


### Dry private worker handoff

`worker_handoff.py` prototypes a coordinator-owned inherited socketpair. The
parent commits a dry claim before starting the fixed local Python child. No
authority file, task text, source or credential is passed in arguments. The child
inherits a minimal environment with no model API key. Source/task travel only
inside the private local channel and are checked against the manifest hash at
the child boundary. Neither process imports a provider or starts a container.

Each dry request needs a sequential reservation response from the parent. The
parent commits the same run's budget reservation before responding. Changed
inputs, out-of-order frames, excessive frames, exhausted budgets and storage
failures stop the protocol. The child is reaped or killed on every exit path.
Unclear results remain spent/unknown and cannot retry. The subprocess tests use
real local IPC, not real inference. Three dry reservations succeed; a fourth is
refused with zero model requests. No paid UI or execution route uses this file.
This is not a whole-computer agent guard and does not authenticate human intent.


### Protected task intake (execution paused)

Native `Protected task` accepts explicit text source selections and a user-written
goal instead of the fixed sales fixture. `Review protected task` snapshots and
validates the selected files and displays exact source and goal locally. It
cannot start a model, container or provider disclosure. Paid native actions stay
off. Selected source is limited to 8 KiB total and goal to 2048 UTF-8 bytes;
credential-like names/content are refused, but secret detection is not complete.
No automatic file scanning, host mounts or application changes are introduced.

The backend plan is immutable and binds this source/goal to the existing
managed-model tool schema, fixed relay/image and request limits. An explicit
mock-only test adapter connects that plan through the durable coordinator to the
existing ModelSession/Broker/Guard flow. The same run budget is committed before
each mocked model request. It supports useful review-only output, policy denial
and verified cleanup evidence. Artifact export refuses unverified cleanup and
never applies content to the source project. `execute_native` always refuses.
There is no live or paid adapter for this flow yet.

Tests cover real selected-file snapshots, immutable plans, goals, secret/size
limits, the exact native review callback with no worker launch, general model-
selected read/write/forbidden tools through mocked Guard lifecycle, reservation
ordering, request exhaustion and output withholding on uncertain cleanup.
These tests do not certify actual native layout, OrbStack containment or live
intelligence. The new native section is visually unverified and is not ready for
an unqualified UI-completion claim. No additional Mac test is requested now.

Scope is shown in the product: only tasks launched through SwarmGuard can be
managed. Other agents and the rest of the Mac are outside this boundary. This
is an entry point toward autonomous computer protection, not host-wide policing.
