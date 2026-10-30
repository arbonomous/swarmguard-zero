import json,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace as S
from unittest.mock import Mock,patch
from execution_gate import Coordinator
from protected_task import plan_files,plan_source,execute_native,run_mock,result_view,export_review

def response(name=None,args=None):
    calls=[] if name is None else [S(id='call',function=S(name=name,arguments=json.dumps(args)))]
    return S(usage=None,choices=[S(message=S(content='',tool_calls=calls))])

class ProtectedTaskTests(unittest.TestCase):
    def test_real_selected_source_snapshot_and_arbitrary_goal(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'notes.txt';path.write_text('A useful real-file note')
            plan=plan_files([str(path)],'Turn these notes into a checklist')
            path.write_text('changed after selection')
            self.assertEqual(plan.source['notes.txt'],b'A useful real-file note')
            self.assertIn('checklist',plan.preview());self.assertIn('Outside agents',plan.preview())
            with self.assertRaises(TypeError):plan.source['notes.txt']=b'changed'
    def test_input_and_secret_limits(self):
        for source,goal in (({},'task'),({'x.txt':b'x'*8193},'task'),({'x.txt':b'x'},''),({'x.txt':b'x'},'x'*2049),({'x.txt':b'api_key=abcdefghijklmnop'},'task')):
            with self.assertRaises(ValueError):plan_source(source,goal)
    def test_native_and_nonmock_client_refused_before_provider(self):
        with self.assertRaises(PermissionError):execute_native()
        client=S(chat=Mock())
        with self.assertRaises(PermissionError):run_mock(None,None,None,client=client)
        client.chat.assert_not_called()
    def test_general_task_uses_guard_and_reserves_before_each_mock_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            gate=Coordinator(Path(tmp)/'dry.db');plan=plan_source({'notes.txt':b'project notes'},'Create a checklist')
            ticket=gate.review(plan.manifest);gate.decide_dry(ticket,plan.manifest,explicit_start=True)
            client=Mock()
            responses=[response('read_source',{'path':'notes.txt'}),response('write_artifact',{'path':'checklist.md','text':'- review notes'}),response('read_host_file',{'path':'synthetic-forbidden'})]
            def infer(**kwargs):
                self.assertEqual(gate.audit()[-1]['requests'],client.chat.completions.create.call_count)
                return responses.pop(0)
            client.chat.completions.create.side_effect=infer
            def guard(_self,source,command,**kw):
                from managed_guard import Broker
                broker=Broker(source);session=kw['model_session'];denied=False
                for _ in range(3):
                    request=session.request({'id':0,'tool':'model_next','arguments':{}},broker)
                    try:session.request(request,broker)
                    except PermissionError:denied=True;break
                return dict(denied=denied,stopped=True,removed=True,artifacts=broker.artifacts,failure=None)
            with patch('managed_guard.Guard.run',new=guard):result=run_mock(plan,gate,ticket,client=client)
            self.assertTrue(result['denied']);self.assertEqual(result['model_requests'],3)
            self.assertEqual(result['artifacts'],{'checklist.md':b'- review notes'})
            self.assertIn('stopped by policy',result_view(result));self.assertIn('Test-only',result_view(result))
            self.assertTrue(export_review(result));self.assertEqual(gate.audit()[-1]['state'],'succeeded')
    def test_export_withheld_without_cleanup(self):
        with self.assertRaises(PermissionError):export_review({'stopped':True,'removed':False,'artifacts':{'x.txt':b'out'}})

    def test_exact_native_review_handler_never_launches(self):
        import ast,native_workspace
        tree=ast.parse(Path(native_workspace.__file__).read_text())
        node=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='runClicked_')
        scope={};exec(compile(ast.Module(body=[node],type_ignores=[]),'<protected review handler>','exec'),scope)
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'notes.txt';path.write_text('Useful project note')
            controller=Mock();controller.busy=False;controller.mode='Protected task';controller.paths=[str(path)]
            controller.command.stringValue.return_value='Make a checklist'
            scope['runClicked_'](controller,None)
            controller.showError_.assert_not_called();controller.startWorker_.assert_not_called()
            self.assertIn('Make a checklist',controller.results.setString_.call_args.args[0])
            self.assertIn('NOTHING STARTED',controller.results.setString_.call_args.args[0])
    def test_mock_budget_exhaustion_precedes_additional_client_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            gate=Coordinator(Path(tmp)/'dry.db');plan=plan_source({'notes.txt':b'notes'},'Read notes')
            ticket=gate.review(plan.manifest);gate.decide_dry(ticket,plan.manifest,explicit_start=True)
            client=Mock();client.chat.completions.create.return_value=response('read_source',{'path':'notes.txt'})
            def guard(_self,source,command,**kw):
                from managed_guard import Broker
                broker=Broker(source);session=kw['model_session']
                for _ in range(4):
                    request=session.request({'id':0,'tool':'model_next','arguments':{}},broker)
                    session.request(request,broker)
            with patch('managed_guard.Guard.run',new=guard),self.assertRaises(PermissionError):run_mock(plan,gate,ticket,client=client)
            self.assertEqual(client.chat.completions.create.call_count,3)
            self.assertEqual(gate.audit()[-1]['state'],'unknown')
