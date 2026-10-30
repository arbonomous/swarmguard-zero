import json,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace as S
from unittest.mock import Mock,patch
from execution_gate import Coordinator
from protected_task import plan_source,run_prepared_mock
from provider_bridge import ProviderBridge,disclosure_plan

class ProviderBridgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.gate=Coordinator(Path(self.tmp.name)/'dry.db')
        self.plan=plan_source({'notes.txt':b'project notes'},'Make checklist')
    def claim(self):
        t=self.gate.review(self.plan.manifest);self.gate.decide_dry(t,self.plan.manifest,explicit_start=True)
        return self.gate.claim_dry(t,self.plan.manifest)
    def test_live_disabled_before_client_or_key(self):
        with patch('openai.OpenAI') as api,patch.dict('os.environ',{},clear=True):
            with self.assertRaises(PermissionError):ProviderBridge(None,None,None)
            api.assert_not_called()
        import provider_bridge
        with patch.object(provider_bridge,'LIVE_PROVIDER_ENABLED',True),self.assertRaises(PermissionError):ProviderBridge(None,None,None)
    def test_prepared_cooperation_uses_same_budget_and_vetoes_before_effect(self):
        client=Mock();calls=[]
        def transport(**kw):
            calls.append(kw)
            self.assertEqual(self.gate.audit()[-1]['requests'],len(calls))
            self.assertEqual(kw['timeout'],10)
            if 'tools' in kw:
                message=S(content='',tool_calls=[S(id='action',function=S(name='write_artifact',arguments=json.dumps({'path':'out.md','text':'candidate'})))])
                return S(usage=None,choices=[S(message=message,finish_reason='tool_calls')])
            payload=json.loads(kw['messages'][1]['content']);context=payload['untrusted_context'];role=payload['reviewer_role']
            self.assertEqual(kw['max_completion_tokens'],400);self.assertNotIn('tools',kw)
            report={'role':role,'action_hash':context['action_hash'],'decision':'deny' if role=='data_safety' else 'allow','reason':'Grounded candidate review','evidence':'candidate'}
            return S(usage=None,choices=[S(message=S(content=json.dumps(report),tool_calls=[]),finish_reason='stop')])
        client.chat.completions.create.side_effect=transport
        def guard(_self,source,command,**kw):
            from managed_guard import Broker
            broker=Broker(source,defense_council=kw['defense_council']);session=kw['model_session']
            action=session.request({'id':0,'tool':'model_next','arguments':{}},broker)
            with self.assertRaises(PermissionError):session.request(action,broker)
            return dict(denied=True,stopped=True,removed=True,artifacts=broker.artifacts,failure='policy stop')
        t=self.gate.review(self.plan.manifest);self.gate.decide_dry(t,self.plan.manifest,explicit_start=True)
        with patch('managed_guard.Guard.run',new=guard):result=run_prepared_mock(self.plan,self.gate,t,client=client)
        self.assertFalse(result['artifacts']);self.assertTrue(result['denied']);self.assertEqual(len(calls),3)
        self.assertEqual([e['decision'] for e in result['defense_reviews']],['allow','deny','stopped_before_effect'])
    def test_transport_error_never_retried(self):
        client=Mock();client.chat.completions.create.side_effect=TimeoutError('synthetic')
        bridge=ProviderBridge(self.gate,self.claim(),self.plan.manifest,client=client,mock_only=True)
        for _ in range(2):
            with self.assertRaises((TimeoutError,PermissionError)):bridge.request('goal_integrity',[{'role':'user','content':'bounded'}])
        self.assertEqual(client.chat.completions.create.call_count,1);self.assertEqual(self.gate.audit()[-1]['requests'],1)
    def test_changed_tools_and_context_refused_before_call(self):
        client=Mock();bridge=ProviderBridge(self.gate,self.claim(),self.plan.manifest,client=client,mock_only=True)
        with self.assertRaises(PermissionError):bridge.request('task',[],tools=[])
        client.chat.completions.create.assert_not_called()
    def test_disclosure_plan_all_roles_and_no_false_cap(self):
        p=disclosure_plan(self.plan.manifest)
        self.assertEqual(p['max_requests_total'],12);self.assertEqual(p['analyst_requests'],0)
        self.assertEqual(p['max_completion_tokens_total'],8000)
        self.assertEqual(p['max_context_bytes_per_request'],32768)
        self.assertIn('not a dollar cap',p['billing']);self.assertFalse(p['live_enabled'])
