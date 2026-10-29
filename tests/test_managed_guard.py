import unittest
from managed_guard import Broker
class BrokerTests(unittest.TestCase):
    def setUp(self):self.broker=Broker({'input.txt':b'synthetic'})
    def test_explicit_source(self):
        result=self.broker.request({'id':1,'tool':'read_source','arguments':{'path':'input.txt'}})
        self.assertEqual(result['text'],'synthetic')
    def test_artifact_only(self):
        self.broker.request({'id':1,'tool':'write_artifact','arguments':{'path':'output.txt','text':'safe'}})
        self.assertEqual(self.broker.artifacts,{'output.txt':b'safe'})
    def test_host_and_network_never_executed(self):
        for tool,args in [('read_host_file',{'path':'~/.ssh/id_ed25519'}),('shell',{'command':'id'}),('http',{'url':'https://example.com'})]:
            with self.subTest(tool=tool),self.assertRaises(PermissionError):self.broker.request({'id':1,'tool':tool,'arguments':args})
        self.assertEqual(self.broker.artifacts,{})
    def test_unimported_refused(self):
        with self.assertRaises(PermissionError):self.broker.request({'id':1,'tool':'read_source','arguments':{'path':'other.txt'}})
    def test_limit(self):
        self.broker.calls=64
        with self.assertRaises(PermissionError):self.broker.request({'id':1,'tool':'read_source','arguments':{'path':'input.txt'}})

class SupervisorProtocolTests(unittest.TestCase):
    def test_real_subprocess_denial_and_cleanup(self):
        import os,tempfile,json
        from pathlib import Path
        from unittest.mock import patch
        from types import SimpleNamespace
        from managed_guard import Guard
        from test_isolation import IMAGE,configuration
        calls=[]
        def docker(*args,**kwargs):
            calls.append(args)
            if args[0]=='inspect':
                data=configuration();data['Name']='/'+args[1];data['State']={'Running':False}
                return SimpleNamespace(stdout=json.dumps([data]))
            return SimpleNamespace(stdout='',stderr='')
        with tempfile.TemporaryDirectory() as tmp:
            exe=Path(tmp)/'docker'
            exe.write_text('#!/bin/sh\nprintf \'%s\\n\' \'{"id":1,"tool":"write_artifact","arguments":{"path":"out.txt","text":"useful output"}}\'\nread response\nprintf \'%s\\n\' \'{"id":2,"tool":"read_host_file","arguments":{"path":"~/.ssh/id_ed25519"}}\'\nexec sleep 30\n');exe.chmod(0o700)
            with patch.dict(os.environ,{'PATH':tmp+os.pathsep+os.environ['PATH']}),patch('managed_guard.runner.local_image',return_value=IMAGE),patch('managed_guard.runner.docker',side_effect=docker):
                result=Guard('local').run({'input.txt':b'synthetic'},['/bin/sh'],3)
        self.assertTrue(result['denied']);self.assertTrue(result['stopped']);self.assertTrue(result['removed'])
        self.assertEqual(result['artifacts'],{'out.txt':b'useful output'})
        self.assertTrue(any(c[0]=='stop' for c in calls))
        self.assertTrue(any(c[:2]==('rm','--force') for c in calls))
        self.assertFalse(any(c[0]=='exec' for c in calls))

class SupervisorLimitTests(unittest.TestCase):
    def test_timeout_still_stops_and_removes(self):
        import os,tempfile,json
        from pathlib import Path
        from unittest.mock import patch
        from types import SimpleNamespace
        from managed_guard import Guard
        from test_isolation import IMAGE,configuration
        calls=[]
        def docker(*args,**kwargs):
            calls.append(args)
            if args[0]=='inspect':
                data=configuration();data['Name']='/'+args[1];data['State']={'Running':False}
                return SimpleNamespace(stdout=json.dumps([data]))
            return SimpleNamespace(stdout='',stderr='')
        with tempfile.TemporaryDirectory() as tmp:
            exe=Path(tmp)/'docker';exe.write_text('#!/bin/sh\nexec sleep 30\n');exe.chmod(0o700)
            with patch.dict(os.environ,{'PATH':tmp+os.pathsep+os.environ['PATH']}),patch('managed_guard.runner.local_image',return_value=IMAGE),patch('managed_guard.runner.docker',side_effect=docker):
                result=Guard('local').run({'input.txt':b'synthetic'},['/bin/sh'],1)
        self.assertIn('TimeoutError',result['failure']);self.assertTrue(result['stopped']);self.assertTrue(result['removed'])
        self.assertEqual([e['kind'] for e in result['events']],['started','stopping','stopped','removed'])

class ProofResultTests(unittest.TestCase):
    def test_missing_cleanup_cannot_pass(self):
        from unittest.mock import patch
        import managed_guard
        result={'denied':True,'stopped':True,'removed':False,'artifacts':{'summary.txt':b'output'}}
        with patch.object(managed_guard.Guard,'run',return_value=result):
            self.assertFalse(managed_guard.prove_intervention()['proof_passed'])
    def test_later_effect_cannot_pass(self):
        from unittest.mock import patch
        import managed_guard
        result={'denied':True,'stopped':True,'removed':True,'artifacts':{'summary.txt':b'output','should-not-exist.txt':b'bad'}}
        with patch.object(managed_guard.Guard,'run',return_value=result):
            self.assertFalse(managed_guard.prove_intervention()['proof_passed'])
