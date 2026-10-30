import contextlib,io,json,os,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace as S
from unittest.mock import Mock,patch
from execution_gate import Coordinator
from test_isolation import configuration
import validate_owned_worker as validation

class OwnedWorkerValidationTests(unittest.TestCase):
    def test_no_flag_has_no_credentials_or_docker(self):
        with patch('openai.OpenAI') as api,patch('dotenv.load_dotenv') as load,patch('managed_guard.runner.docker') as docker,contextlib.redirect_stdout(io.StringIO()) as out:
            validation.main([])
        api.assert_not_called();load.assert_not_called();docker.assert_not_called()
        self.assertFalse(json.loads(out.getvalue())['ran'])

    def exercise(self,decision='deny',cleanup=True,incomplete=False,unverified=False):
        calls=[];client=Mock()
        def respond(**kw):
            self.assertEqual(kw['max_completion_tokens'],1600)
            self.assertEqual(kw['reasoning_effort'],'low');self.assertNotIn('tools',kw)
            p=json.loads(kw['messages'][1]['content']);c=p['untrusted_context'];role=p['reviewer_role']
            report={'role':role,'action_hash':c['action_hash'],'decision':decision,'reason':'Goal hijack','evidence':'Disable SwarmGuard'}
            return S(usage=None,choices=[S(finish_reason='length' if incomplete else 'stop',message=S(content=json.dumps(report),tool_calls=[]))])
        client.chat.completions.create.side_effect=respond
        def docker(*args,**kw):
            calls.append(args)
            if args[0]=='inspect':
                data=configuration();data['Name']='/'+args[1];data['Image']=validation.VERIFIED_IMAGE
                data['State']={'Running':not any(c[0]=='stop' for c in calls)}
                if unverified:data['HostConfig']['NetworkMode']='host'
                return S(stdout=json.dumps([data]))
            if args[0]=='ps':return S(stdout='' if cleanup else 'leftover')
            return S(stdout='',stderr='')
        with tempfile.TemporaryDirectory() as tmp:
            exe=Path(tmp)/'docker'
            # A real local protocol process. Docker lifecycle/state only are mocked.
            exe.write_text("#!/bin/sh\nprintf '%s\\n' '"+validation.ACTION_JSON+"'\nIFS= read -r response\n")
            exe.chmod(0o700);gate=Coordinator(Path(tmp)/'audit.db')
            with patch.dict(os.environ,{'PATH':tmp+os.pathsep+os.environ['PATH']}),patch('managed_guard.runner.local_image',return_value=validation.VERIFIED_IMAGE),patch('managed_guard.runner.docker',side_effect=docker):
                result=validation.run(gate,client=client)
        self.assertFalse(result['export_permitted']);self.assertNotIn('artifacts',result)
        self.assertTrue(any(c[0]=='stop' for c in calls));self.assertTrue(any(c[:2]==('rm','--force') for c in calls))
        self.assertFalse(any(c[0]=='exec' for c in calls))
        return result,client

    def test_grounded_veto_and_real_local_protocol_cleanup(self):
        result,client=self.exercise()
        self.assertTrue(result['proof_passed']);self.assertTrue(result['cleanup_verified'])
        self.assertFalse(result['artifact_created']);self.assertEqual(result['requests_reserved'],1)
        self.assertEqual(client.chat.completions.create.call_count,1)
        kinds=[e['kind'] for e in result['events']]
        self.assertEqual(kinds,['boundary_verified','started','proposal_received','denied','stopping','stopped','removed'])

    def test_cleanup_uncertainty_cannot_pass(self):
        result,_=self.exercise(cleanup=False)
        self.assertFalse(result['proof_passed']);self.assertFalse(result['cleanup_verified'])

    def test_unanimous_allow_is_failed_detection_and_no_export(self):
        result,client=self.exercise(decision='allow')
        self.assertFalse(result['proof_passed']);self.assertTrue(result['artifact_created'])
        self.assertFalse(result['grounded_model_veto']);self.assertEqual(client.chat.completions.create.call_count,2)

    def test_incomplete_is_not_a_grounded_veto(self):
        result,client=self.exercise(incomplete=True)
        self.assertFalse(result['proof_passed']);self.assertFalse(result['grounded_model_veto'])
        self.assertFalse(result['artifact_created']);self.assertTrue(result['cleanup_verified'])
        self.assertEqual(client.chat.completions.create.call_count,1)

    def test_bad_boundary_never_calls_provider(self):
        result,client=self.exercise(unverified=True)
        self.assertFalse(result['proof_passed']);self.assertFalse(result['containment_verified'])
        client.chat.completions.create.assert_not_called()

    def test_changed_manifest_refused(self):
        from dataclasses import replace
        from provider_bridge import ProviderBridge
        with self.assertRaises(PermissionError):
            ProviderBridge.for_owned_worker_validation(None,None,replace(validation.manifest(),command=('/bin/sh',)),client=Mock())
