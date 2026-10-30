"""Mock-only defense wiring on actual Broker proposals, never a live AI swarm.

No defender can grant tools. Hard policy is checked by Broker before this seam.
No provider imports, effect permissions or user confirmation callbacks.
"""
import json
import queue
import threading
from execution_gate import digest

ROLES=('goal_integrity','data_safety')

class DefenseCouncil:
    def __init__(self, goal, reviewers, *, reserve, timeout=1):
        from unittest.mock import Mock
        if set(reviewers)!=set(ROLES) or not all(isinstance(v,Mock) for v in reviewers.values()):
            raise PermissionError('Only explicit local mock defenders are supported')
        if not 0<timeout<=5:raise ValueError('Bounded review timeout required')
        self.goal=goal;self.reviewers=dict(reviewers);self.reserve=reserve;self.timeout=timeout
        self.events=[];self.stopped=False

    def review(self,request,source):
        if self.stopped:raise PermissionError('Defense session already stopped')
        proposal=json.loads(json.dumps(request));action_hash=digest(proposal)
        context={'goal':self.goal,'source':{k:v.decode() for k,v in source.items()},'proposed_action':proposal,'action_hash':action_hash}
        encoded=json.dumps(context,sort_keys=True)
        if len(encoded.encode())>32768:
            self.stopped=True;raise PermissionError('Defense context limit exceeded')
        try:
            for role in ROLES:
                self.reserve(role,len(encoded.encode())) # commit BEFORE any reviewer call
                result=queue.Queue(maxsize=1)
                def run(reviewer=self.reviewers[role],payload=json.loads(encoded),out=result):
                    try:out.put((True,reviewer(payload)))
                    except BaseException:out.put((False,None))
                # Mock callbacks have no effect/provider capability. Timed-out daemon
                # results are discarded; no further callback runs for this council.
                threading.Thread(target=run,daemon=True).start()
                try:ok,report=result.get(timeout=self.timeout)
                except queue.Empty:raise PermissionError('Defender timed out') from None
                if not ok:raise PermissionError('Defender failed')
                if (not isinstance(report,dict) or set(report)!={'role','action_hash','decision','reason','evidence'} or
                    report['role']!=role or report['action_hash']!=action_hash or
                    report['decision'] not in ('allow','deny','uncertain') or
                    not isinstance(report['reason'],str) or not 1<=len(report['reason'])<=240 or
                    not isinstance(report['evidence'],str) or not report['evidence'] or report['evidence'] not in encoded):
                    raise PermissionError('Invalid or ungrounded defender report')
                self.events.append({'role':role,'action_hash':action_hash,'decision':report['decision']})
                if report['decision']!='allow':raise PermissionError('Defender veto: '+role)
        except BaseException:
            self.stopped=True
            self.events.append({'action_hash':action_hash,'decision':'stopped_before_effect'})
            raise
        return True
