"""Plain-language native dashboard detail model. No browser imports or model calls."""
from __future__ import annotations
import json
from policy import enforce_enabled, probe_catalog_enforcement
from threat_bus import read_gate_status, read_incidents, read_state
from threat_model import coverage_rows, summary_counts


def section_text(section: str) -> str:
    gate = read_gate_status()
    if section == 'Status':
        try:
            from swarm_brain import api_status
            api = api_status()
            ai = 'Set, not live-verified' if api.get('configured') else 'Missing'
        except ImportError:
            ai = 'Analysis dependencies unavailable'
        return ('CONNECTED TOOLS ONLY\nPolicy configuration: ' + ('On' if enforce_enabled() else 'Off') +
                '\nMCP gate: ' + ('Wrapping tools' if gate.get('wrapping') else 'Idle') +
                '\nAI key: ' + ai + '\nLogged activity: ' + str(len(read_incidents(100))) +
                '\n\nHooks and MCP only enforce actions routed through them. Offline workspaces isolate commands launched inside them. Other Mac processes are outside these boundaries.\n\n' +
                str(gate.get('note') or 'No active MCP connection confirmed.'))
    if section == 'Attack catalog':
        counts = summary_counts()
        rows = coverage_rows()
        return ('CATALOG, NOT A PREVENTION RATE\n' + json.dumps(counts, indent=2) +
                '\n\nRules require connected hooks/tools. Analysis is not a host block.\n\n' +
                '\n\n'.join('\n'.join(f'{k}: {v}' for k,v in row.items()) for row in rows))
    if section == 'Policy checks':
        probes = probe_catalog_enforcement()
        return ('SYNTHETIC INPUTS ONLY\nNo actual host attack was attempted.\n\n' +
                '\n'.join(('PASS' if row['ok'] else 'FAIL') + ': ' + str(row['threat_id']) + ' | ' + str(row['rule']) for row in probes))
    if section == 'Activity and evidence':
        rows = read_incidents(100)
        return ('RECENT ACTIVITY AND EVIDENCE\nSimulated quarantine never means a real process was stopped.\n\n' +
                ('\n\n'.join(_activity(row) for row in rows) if rows else 'No logged incidents.'))
    if section == 'Latest analysis':
        return ('LATEST LOCAL STATE\nEvidence, forensic details and any visual-box coordinates are data, not proof of host enforcement.\n\n' +
                json.dumps(read_state(), indent=2, ensure_ascii=False))
    return ('HOW PROTECTION WORKS\n\n1. Connected IDE hooks and MCP tools apply the policy before routed actions.\n2. The attack catalog documents rules, analysis paths and planned gaps.\n3. Optional AI demos inspect synthetic scenarios and can use API credits; they never force-quit real apps.\n4. Offline copied workspaces have no network or host folder mounts.\n\nNo always-on whole-Mac process enforcement is provided. Cloud-agent workspace networking is not enabled.\n\nModel settings are configuration, not verified readiness.\n' + _model_settings())


def _activity(row: dict) -> str:
    title = str(row.get('headline') or row.get('title') or 'Logged activity')
    summary = str(row.get('action_detail') or row.get('executive_summary') or '')
    detail = json.dumps({k:v for k,v in row.items() if k not in ('headline','title','action_detail','executive_summary')}, indent=2, ensure_ascii=False)
    return title + '\n' + summary + '\nDetails:\n' + detail


def _model_settings() -> str:
    try:
        from swarm_brain import api_status
        data=api_status()
        return '\n'.join(key + ': ' + str(data.get(key) or 'unset') for key in ('guard_model','forensic_model','sam_model'))
    except ImportError:
        return 'Analysis dependencies unavailable in this Python environment.'
