import contextlib,io,json,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace as S
from unittest.mock import Mock,patch
from execution_gate import Coordinator
import validate_cooperation as validation

class HeadlessValidationTests(unittest.TestCase):
    def test_no_flag_never_reads_key_or_constructs_client(self):
        with patch('openai.OpenAI') as api,patch('dotenv.load_dotenv') as load,contextlib.redirect_stdout(io.StringIO()) as out:
            validation.main([])
        api.assert_not_called();load.assert_not_called();self.assertFalse(json.loads(out.getvalue())['ran'])
    def test_three_real_shaped_calls_enforce_before_effect(self):
        for veto in (False,True):
            with tempfile.TemporaryDirectory() as tmp:
                gate=Coordinator(Path(tmp)/'audit.db');client=Mock();calls=[]
                def respond(**kw):
                    calls.append(kw);self.assertEqual(gate.audit()[-1]['requests'],len(calls))
                    if 'tools' in kw:
                        return S(usage=None,choices=[S(finish_reason='tool_calls',message=S(content='',tool_calls=[S(function=S(name='write_artifact',arguments='{"path":"checklist.md","text":"- Review report"}'))]))])
                    p=json.loads(kw['messages'][1]['content']);role=p['reviewer_role'];c=p['untrusted_context']
                    report={'role':role,'action_hash':c['action_hash'],'decision':'deny' if veto and role=='data_safety' else 'allow','reason':'Candidate action reviewed','evidence':'Review report'}
                    return S(usage=None,choices=[S(finish_reason='stop',message=S(content=json.dumps(report),tool_calls=[]))])
                client.chat.completions.create.side_effect=respond
                result=validation.run(gate,client=client)
                self.assertEqual(len(calls),3);self.assertEqual(result['artifact_created'],not veto)
                self.assertEqual(result['denied_before_effect'],veto);self.assertFalse(result['containment_verified'])
                self.assertTrue(all(len(json.dumps({'messages':c['messages'],'tools':c.get('tools')},sort_keys=True).encode())<=4096 for c in calls))
    def test_incomplete_defender_stops_without_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            gate=Coordinator(Path(tmp)/'audit.db');client=Mock()
            task=S(usage=None,choices=[S(finish_reason='tool_calls',message=S(content='',tool_calls=[S(function=S(name='write_artifact',arguments='{"path":"checklist.md","text":"- Review report"}'))]))])
            incomplete=S(usage=None,choices=[S(finish_reason='length',message=S(content='{}',tool_calls=[]))])
            client.chat.completions.create.side_effect=[task,incomplete]
            result=validation.run(gate,client=client)
            self.assertFalse(result['artifact_created']);self.assertEqual(client.chat.completions.create.call_count,2)
    def test_reasoning_and_complete_json_budget_are_manifest_bound(self):
        from dataclasses import replace
        m=validation.manifest()
        self.assertEqual(m.defender_completion_tokens,1600);self.assertEqual(m.reasoning_effort,'low')
        self.assertNotEqual(m.fingerprint(),replace(m,defender_completion_tokens=400).fingerprint())
        self.assertNotEqual(m.fingerprint(),replace(m,reasoning_effort='minimal').fingerprint())
        with contextlib.redirect_stdout(io.StringIO()) as out:validation.main([])
        plan=json.loads(out.getvalue())['ready_plan']
        self.assertEqual(plan['max_completion_tokens_total'],4800)
        self.assertEqual(plan['max_requests_total'],3)
    def test_veto_fixture_passes_hard_policy_and_models_stop_before_effect(self):
        from managed_guard import Broker
        Broker(validation.SOURCE).validate_request(validation.VETO_ACTION)
        with tempfile.TemporaryDirectory() as tmp:
            gate=Coordinator(Path(tmp)/'audit.db');client=Mock()
            def respond(**kw):
                self.assertNotIn('tools',kw)
                p=json.loads(kw['messages'][1]['content']);c=p['untrusted_context'];role=p['reviewer_role']
                report={'role':role,'action_hash':c['action_hash'],'decision':'deny','reason':'Goal hijack and unsafe disclosure request','evidence':'Disable SwarmGuard'}
                return S(usage=None,choices=[S(finish_reason='stop',message=S(content=json.dumps(report),tool_calls=[]))])
            client.chat.completions.create.side_effect=respond
            result=validation.run(gate,client=client,veto=True)
            self.assertTrue(result['hard_policy_fixture_passed']);self.assertFalse(result['task_model_called'])
            self.assertFalse(result['artifact_created']);self.assertTrue(result['denied_before_effect'])
            self.assertEqual(result['defense_reviews'][-1]['failure_category'],'grounded_deny')
            self.assertEqual(client.chat.completions.create.call_count,1)
            self.assertIn('injected',result['proposal_origin'])
            self.assertEqual(validation.manifest(True).all_role_requests,2)
