import unittest
from types import SimpleNamespace as S
from unittest.mock import Mock
import meta_agent

def call(name,args):return S(id='test-call',function=S(name=name,arguments=args))
def response(*calls):return S(usage=None,choices=[S(message=S(content='',tool_calls=list(calls)))])

class MetaAgentTests(unittest.TestCase):
    def test_disabled_before_client_or_source(self):
        client=Mock()
        with self.assertRaises(PermissionError):meta_agent.run({},'task',client=client)
        client.chat.completions.create.assert_not_called()
    def test_model_chosen_safe_artifact(self):
        client=Mock();client.chat.completions.create.side_effect=[response(call('read_source','{"path":"input.txt"}')),response(call('write_artifact','{"path":"summary.txt","text":"Model result"}')),response()]
        result=meta_agent.run({'input.txt':b'public synthetic'},'Summarize',authorized=True,client=client)
        self.assertEqual(result['artifacts']['summary.txt'],b'Model result')
        self.assertFalse(result['denied'])
        self.assertEqual(client.chat.completions.create.call_count,3)
        self.assertTrue(all(c.kwargs['model']==meta_agent.MODEL for c in client.chat.completions.create.call_args_list))
    def test_denial_stops_later_effects_and_inference(self):
        client=Mock();client.chat.completions.create.return_value=response(call('read_host_file','{"path":"~/.ssh/id_ed25519"}'),call('write_artifact','{"path":"later.txt","text":"bad"}'))
        result=meta_agent.run({'input.txt':b'synthetic'},'Summarize',authorized=True,client=client)
        self.assertTrue(result['denied']);self.assertFalse(result['artifacts'])
        self.assertEqual(client.chat.completions.create.call_count,1)
        self.assertFalse(result['events'][0]['effect_executed'])
    def test_malformed_arguments_fail_closed(self):
        client=Mock();client.chat.completions.create.return_value=response(call('read_source','[]'))
        self.assertTrue(meta_agent.run({'input.txt':b'synthetic'},'Summarize',authorized=True,client=client)['denied'])
    def test_no_live_client_in_tests(self):
        self.assertEqual(meta_agent.BASE_URL,'https://api.meta.ai/v1')
        self.assertEqual({t['function']['name'] for t in meta_agent.TOOLS},{'read_source','write_artifact'})
