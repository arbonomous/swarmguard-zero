"""Real-file protected task intake. Native execution stays paused.

Only explicit selected source copies enter a plan. Mock execution is a test seam,
not permission to disclose source to a provider or spend credits.
"""
from dataclasses import dataclass
import json
from pathlib import Path
from types import MappingProxyType
from workspace_files import selected_files,validate_files,make_archive,SECRET_CONTENT
from execution_gate import Manifest
from isolation_check import VERIFIED_IMAGE
from meta_agent import BASE_URL,MODEL,TOOLS
from managed_model import ModelSession,RELAY

WARNING='Paid execution paused. Future Meta use discloses these exact copies and goal; credits can spill to card. No approval is granted by review.'
SCOPE='Only tasks launched through SwarmGuard. Outside agents and the rest of your Mac are not protected.'

@dataclass(frozen=True)
class Plan:
    source: object
    goal: str
    manifest: Manifest

    def preview(self):
        return ('PROTECTED TASK PLAN - NOTHING STARTED\n'+SCOPE+'\n\nGoal:\n'+self.goal+
                '\n\nExact selected copies:\n'+ '\n\n'.join(name+'\n'+data.decode() for name,data in self.source.items())+
                '\n\nTools: read selected copies; write review-only artifacts. No host files, shell or worker network.\n'+WARNING+
                '\nSecret detection is limited. Do not include private documents or credentials.\n\nManifest SHA256: '+self.manifest.fingerprint())


def plan_files(paths,goal):
    files={}
    for value in paths:
        path=Path(value)
        if path.name in files:raise ValueError('Selected files must have distinct names')
        files.update(selected_files(path.parent,[path.name]))
    return plan_source(files,goal)


def plan_source(source,goal):
    source=validate_files(dict(source))
    if sum(map(len,source.values()))>8192:raise ValueError('Protected task copies must total at most 8 KiB')
    if not isinstance(goal,str) or not goal.strip() or len(goal.encode())>2048:
        raise ValueError('Write a goal from 1 to 2048 UTF-8 bytes')
    if '\x00' in goal or SECRET_CONTENT.search(goal):raise ValueError('Possible credential in goal; remove it')
    manifest=Manifest.build(source,goal,endpoint=BASE_URL,model=MODEL,tools=TOOLS,image=VERIFIED_IMAGE,command=RELAY,all_role_requests=12,warning=WARNING)
    return Plan(MappingProxyType(source),goal,manifest)


def execute_native(*args,**kwargs):
    raise PermissionError('Protected task execution is paused. Review cannot authorize provider disclosure or spending.')


def run_mock(plan,coordinator,ticket,*,client,reviewers=None):
    """Explicit local mock client only. No production provider adapter is accepted."""
    from unittest.mock import Mock
    if not isinstance(client,Mock):raise PermissionError('Only a local mock client is supported while execution is paused')
    from managed_guard import Guard
    checked=plan_source(plan.source,plan.goal)
    if checked.manifest!=plan.manifest:raise PermissionError('Changed protected task plan')
    def operation(claim):
        class BudgetSession(ModelSession):
            def request(self,request,broker):
                if isinstance(request,dict) and request.get('tool')=='model_next':
                    coordinator.reserve_dry_request(claim,plan.manifest,context_bytes=len(json.dumps(self.messages).encode()))
                return super().request(request,broker)
        council=None
        if reviewers is not None:
            from defense_council import DefenseCouncil
            council=DefenseCouncil(plan.goal,reviewers,reserve=lambda role,size: coordinator.reserve_dry_request(claim,plan.manifest,context_bytes=size,role=role))
        session=BudgetSession(plan.goal,list(plan.source),authorized=True,client=client)
        result=Guard(plan.manifest.image).run(dict(plan.source),list(plan.manifest.command),seconds=90,model_session=session,defense_council=council)
        result.update(defense_reviews=council.events if council else [],model_finished=session.finished,model_requests=session.turns,mocked_model=True,paid_authority=False)
        return result
    return coordinator.dispatch_dry(ticket,plan.manifest,operation)


def result_view(result):
    clean=result.get('stopped') is True and result.get('removed') is True
    lines=['Protected task stopped by policy.' if result.get('denied') else 'Protected task finished.' if clean and result.get('model_finished') and not result.get('failure') else 'Protected task needs attention.',SCOPE,
        'Outputs are untrusted review copies. Nothing applied to your project.',
        'Worker stopped: '+('Yes' if result.get('stopped') is True else 'UNVERIFIED'),
        'Worker removed: '+('Yes' if result.get('removed') is True else 'UNVERIFIED')]
    if result.get('mocked_model'):lines.append('Test-only model responses. No real intelligent task or provider request.')
    for name,data in result.get('artifacts',{}).items():lines.extend(['\nReview output '+name+':',data.decode()])
    return '\n'.join(lines)


def export_review(result):
    if result.get('export_permitted') is False or result.get('stopped') is not True or result.get('removed') is not True:
        raise PermissionError('Cleanup unverified; output export is withheld')
    return make_archive(result.get('artifacts',{}))


def run_prepared_mock(plan,coordinator,ticket,*,client):
    """Whole cooperating path using production-shaped adapters and mock transport."""
    from provider_bridge import ProviderBridge
    from defense_council import DefenseCouncil,ROLES
    from managed_guard import Guard
    checked=plan_source(plan.source,plan.goal)
    if checked.manifest!=plan.manifest:raise PermissionError('Changed protected task plan')
    def operation(claim):
        bridge=ProviderBridge(coordinator,claim,plan.manifest,client=client,mock_only=True)
        # Adapter reserves after full defender prompt is built, not twice here.
        council=DefenseCouncil(plan.goal,{r:bridge.defender(r) for r in ROLES},reserve=lambda role,size:None,timeout=12)
        session=ModelSession(plan.goal,list(plan.source),authorized=True,client=bridge.task_client())
        result=Guard(plan.manifest.image).run(dict(plan.source),list(plan.manifest.command),seconds=90,model_session=session,defense_council=council)
        result.update(defense_reviews=council.events,model_finished=session.finished,model_requests=session.turns,
                      mocked_model=True,paid_authority=False,all_role_usage=bridge.usage,provider_diagnostics=bridge.diagnostics)
        return result
    return coordinator.dispatch_dry(ticket,plan.manifest,operation)
