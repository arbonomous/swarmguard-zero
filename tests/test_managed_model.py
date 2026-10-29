import unittest,json
from unittest.mock import Mock
from types import SimpleNamespace as S
from managed_model import ModelSession,RELAY
from managed_guard import Broker

def response(name=None,args=None):
    calls=[] if name is None else [S(id='call-1',function=S(name=name,arguments=json.dumps(args)))]
    return S(usage=None,choices=[S(message=S(content='',tool_calls=calls))])
NEXT={'id':0,'tool':'model_next','arguments':{}}
class ModelBridgeTests(unittest.TestCase):
    def test_disabled(self):
        with self.assertRaises(PermissionError):ModelSession('task',[],client=Mock())
    def test_model_request_and_result(self):
        client=Mock();client.chat.completions.create.side_effect=[response('read_source',{'path':'input.txt'}),response()]
        session=ModelSession('task',['input.txt'],authorized=True,client=client);broker=Broker({'input.txt':b'synthetic'})
        request=session.request(NEXT,broker)
        self.assertEqual(request['tool'],'read_source')
        with self.assertRaises(PermissionError):session.request(NEXT,broker)
        self.assertEqual(session.request(request,broker)['text'],'synthetic')
        self.assertTrue(session.request(NEXT,broker)['finished'])
        self.assertTrue(session.finished)
    def test_substitution_and_denial_fail_closed(self):
        client=Mock();client.chat.completions.create.return_value=response('read_host_file',{'path':'secret'})
        session=ModelSession('task',[],authorized=True,client=client);broker=Broker({'input.txt':b'synthetic'})
        request=session.request(NEXT,broker)
        with self.assertRaises(PermissionError):session.request({'id':1,'tool':'write_artifact','arguments':{'path':'later.txt','text':'bad'}},broker)
        with self.assertRaises(PermissionError):session.request(request,broker)
        self.assertFalse(broker.artifacts);self.assertEqual(client.chat.completions.create.call_count,1)
    def test_real_shell_relay_never_executes_model_text(self):
        import subprocess
        proc=subprocess.Popen(RELAY,stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
        try:
            self.assertEqual(json.loads(proc.stdout.readline()),NEXT)
            request={'id':1,'tool':'write_artifact','arguments':{'path':'summary.txt','text':'$(touch /tmp/never-run)'}}
            proc.stdin.write(json.dumps(request)+'\n');proc.stdin.flush()
            self.assertEqual(json.loads(proc.stdout.readline()),request)
            proc.stdin.write('{"ok":true}\n');proc.stdin.flush()
            self.assertEqual(json.loads(proc.stdout.readline()),NEXT)
            proc.stdin.write('{"finished":true}\n');proc.stdin.flush()
            self.assertEqual(proc.wait(timeout=2),0)
        finally:
            if proc.poll() is None:proc.kill();proc.wait()
            proc.stdin.close();proc.stdout.close()

class ManagedBridgeLifecycleTests(unittest.TestCase):
    def test_real_relay_model_denial_scoped_cleanup(self):
        import os,tempfile
        from pathlib import Path
        from unittest.mock import patch
        from managed_guard import Guard
        from test_isolation import IMAGE,configuration
        client=Mock();client.chat.completions.create.side_effect=[response('write_artifact',{'path':'summary.txt','text':'Useful model-selected output'}),response('read_host_file',{'path':'synthetic-forbidden'})]
        session=ModelSession('task',['input.txt'],authorized=True,client=client)
        calls=[]
        def docker(*args,**kwargs):
            calls.append(args)
            if args[0]=='inspect':
                data=configuration();data['Name']='/'+args[1];data['State']={'Running':False}
                return S(stdout=json.dumps([data]))
            return S(stdout='',stderr='')
        with tempfile.TemporaryDirectory() as tmp:
            exe=Path(tmp)/'docker'
            import shlex
            exe.write_text('#!/bin/sh\nexec '+shlex.join(RELAY)+'\n');exe.chmod(0o700)
            with patch.dict(os.environ,{'PATH':tmp+os.pathsep+os.environ['PATH']}),patch('managed_guard.runner.local_image',return_value=IMAGE),patch('managed_guard.runner.docker',side_effect=docker):
                result=Guard('local').run({'input.txt':b'synthetic'},RELAY,seconds=3,model_session=session)
        self.assertTrue(result['denied']);self.assertTrue(result['stopped']);self.assertTrue(result['removed'])
        self.assertEqual(result['artifacts'],{'summary.txt':b'Useful model-selected output'})
        self.assertEqual(client.chat.completions.create.call_count,2)
        self.assertEqual([e['kind'] for e in result['events']],['started','model_step','allowed','model_step','denied','stopping','stopped','removed'])
        self.assertTrue(any(c[0]=='stop' for c in calls))
        self.assertTrue(any(c[:2]==('rm','--force') for c in calls))
