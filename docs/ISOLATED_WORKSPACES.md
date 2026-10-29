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
