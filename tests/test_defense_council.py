import json,os,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace as S
from unittest.mock import Mock,patch
from execution_gate import Coordinator,Manifest
from defense_council import DefenseCouncil,ROLES
from managed_guard import Broker,Guard


def reviewer(role,decision='allow'):
    return Mock(side_effect=lambda c:{'role':role,'action_hash':c['action_hash'],'decision':decision,'reason':'Grounded action review','evidence':c['goal']})

class CouncilTests(unittest.TestCase):
    def council(self,decision='allow',**kwargs):
        return DefenseCouncil('goal',{r:reviewer(r,decision) for r in ROLES},reserve=Mock(),**kwargs)
    def test_safe_effect_waits_for_both_roles(self):
        c=self.council();b=Broker({'input.txt':b'notes'},defense_council=c)
        def check(context):
            self.assertFalse(b.artifacts)
            return {'role':'data_safety','action_hash':context['action_hash'],'decision':'allow','reason':'Grounded','evidence':'goal'}
        c.reviewers['data_safety'].side_effect=check
        b.request({'id':1,'tool':'write_artifact','arguments':{'path':'out.txt','text':'useful'}})
        self.assertEqual(b.artifacts,{'out.txt':b'useful'});self.assertEqual(len(c.events),2)
    def test_hard_policy_before_council_and_veto_never_widens(self):
        c=self.council();b=Broker({'input.txt':b'notes'},defense_council=c)
        with self.assertRaises(PermissionError):b.request({'id':1,'tool':'read_host_file','arguments':{'path':'synthetic'}})
        for r in c.reviewers.values():r.assert_not_called()
        c=self.council('deny');b=Broker({'input.txt':b'notes'},defense_council=c)
        with self.assertRaises(PermissionError):b.request({'id':1,'tool':'write_artifact','arguments':{'path':'out.txt','text':'candidate'}})
        self.assertFalse(b.artifacts);self.assertTrue(c.stopped)
        with self.assertRaises(PermissionError):b.request({'id':2,'tool':'read_source','arguments':{'path':'input.txt'}})
    def test_uncertain_error_malformed_ungrounded_substitution_fail_closed(self):
        for change in ('uncertain','error','malformed','ungrounded','substitution'):
            c=self.council();r=c.reviewers['goal_integrity']
            if change=='uncertain':r.side_effect=reviewer('goal_integrity','uncertain').side_effect
            elif change=='error':r.side_effect=ValueError('untrusted provider detail')
            elif change=='malformed':r.side_effect=None;r.return_value={}
            else:
                def bad(context):
                    return {'role':'goal_integrity','action_hash':'wrong' if change=='substitution' else context['action_hash'],'decision':'allow','reason':'test','evidence':'invented absent text'}
                r.side_effect=bad
            b=Broker({'input.txt':b'notes'},defense_council=c)
            with self.assertRaises(PermissionError):b.request({'id':1,'tool':'write_artifact','arguments':{'path':'out.txt','text':'candidate'}})
            self.assertFalse(b.artifacts)
    def test_timeout_no_effect_or_next_role(self):
        c=self.council(timeout=.01)
        c.reviewers['goal_integrity'].side_effect=lambda c:time.sleep(.05)
        b=Broker({'input.txt':b'notes'},defense_council=c)
        with self.assertRaises(PermissionError):b.request({'id':1,'tool':'read_source','arguments':{'path':'input.txt'}})
        c.reviewers['data_safety'].assert_not_called();self.assertTrue(c.stopped)
    def test_independent_payloads_mutation_cannot_replace_effect(self):
        c=self.council();b=Broker({'input.txt':b'notes'},defense_council=c)
        original=c.reviewers['goal_integrity'].side_effect
        def mutate(context):
            report=original(context);context['proposed_action']['arguments']['text']='substituted';return report
        c.reviewers['goal_integrity'].side_effect=mutate
        b.request({'id':1,'tool':'write_artifact','arguments':{'path':'out.txt','text':'original'}})
        self.assertEqual(b.artifacts['out.txt'],b'original')
    def test_all_roles_share_durable_budget_before_callbacks(self):
        with tempfile.TemporaryDirectory() as tmp:
            c=Coordinator(Path(tmp)/'dry.db');m=Manifest.build({'input.txt':b'notes'},'goal',endpoint='https://invalid.test',model='mock',tools=[],image='sha256:test',command=['mock'],all_role_requests=3,warning='warning')
            t=c.review(m);c.decide_dry(t,m,explicit_start=True);claim=c.claim_dry(t,m)
            c.reserve_dry_request(claim,m,context_bytes=1,role='task')
            council=DefenseCouncil('goal',{r:reviewer(r) for r in ROLES},reserve=lambda role,size:c.reserve_dry_request(claim,m,context_bytes=size,role=role))
            b=Broker({'input.txt':b'notes'},defense_council=council)
            b.request({'id':1,'tool':'read_source','arguments':{'path':'input.txt'}})
            with self.assertRaises(PermissionError):b.request({'id':2,'tool':'write_artifact','arguments':{'path':'out.txt','text':'later'}})
            self.assertFalse(b.artifacts);self.assertEqual(c.audit()[-1]['requests'],3)
    def test_real_local_protocol_veto_stops_and_cleanup_attempts(self):
        from test_isolation import IMAGE,configuration
        calls=[]
        def docker(*args,**kwargs):
            calls.append(args)
            if args[0]=='inspect':
                data=configuration();data['Name']='/'+args[1];data['State']={'Running':False};return S(stdout=json.dumps([data]))
            return S(stdout='',stderr='')
        with tempfile.TemporaryDirectory() as tmp:
            exe=Path(tmp)/'docker';exe.write_text('#!/bin/sh\nprintf \'%s\\n\' \'{"id":1,"tool":"write_artifact","arguments":{"path":"out.txt","text":"candidate"}}\'\nexec sleep 30\n');exe.chmod(0o700)
            with patch.dict(os.environ,{'PATH':tmp+os.pathsep+os.environ['PATH']}),patch('managed_guard.runner.local_image',return_value=IMAGE),patch('managed_guard.runner.docker',side_effect=docker):
                result=Guard('mock-image').run({'input.txt':b'notes'},['/bin/sh'],seconds=3,defense_council=self.council('deny'))
        self.assertTrue(result['denied']);self.assertTrue(result['stopped']);self.assertTrue(result['removed']);self.assertFalse(result['artifacts'])
        self.assertTrue(any(c[0]=='stop' for c in calls));self.assertTrue(any(c[:2]==('rm','--force') for c in calls))
