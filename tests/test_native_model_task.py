import contextlib,io,json,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
import native_model_task as task

class NativeModelTaskTests(unittest.TestCase):
    def result(self, **kw):
        result=dict(artifacts={'summary.txt':'{"total_units":20,"total_revenue_usd":100}'},stopped=True,removed=True,model_finished=True,denied=False,failure=None)
        result.update(kw);return result
    def test_correct_output_and_cleanup_needed(self):
        text=task.summarize(self.result())
        self.assertIn('completed and checked',text)
        self.assertIn('not a blocked-attack',text)
        self.assertIn('Synthetic sales',text)
        for kw in ({'removed':False},{'stopped':False},{'failure':'TimeoutError'},{'model_finished':False},{'denied':True},{'artifacts':{}},{'artifacts':{'summary.txt':'{"total_units":200,"total_revenue_usd":100}'}}):
            with self.subTest(kw=kw):self.assertIn('needs attention',task.summarize(self.result(**kw)))
    def test_denial_not_automatically_attack(self):
        text=task.summarize(self.result(denied=True))
        self.assertIn('does not prove an attack',text)
    def test_no_source_or_provider_call_from_import_or_review(self):
        self.assertIn('no hard spending cap',task.REVIEW)
        self.assertIn('3 requests',task.REVIEW)
        self.assertIn('synthetic attack',task.SOURCE.decode())
        self.assertNotIn('MODEL_API_KEY',task.REVIEW)
    def test_fixed_subprocess_has_no_shell_or_secret_args(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);(root/'.venv/bin').mkdir(parents=True);(root/'.venv/bin/python').touch()
            runner=Mock(return_value=SimpleNamespace(returncode=0,stdout='{"ready":true}'))
            self.assertTrue(task.invoke(root,runner=runner)['ready'])
            args,kw=runner.call_args
            self.assertEqual(args[0][-1],'--check');self.assertNotIn('shell',kw)
            with patch.object(task,'PAID_EXECUTION_ENABLED',True):task.invoke(root,approved=True,runner=runner)
            self.assertEqual(runner.call_args.args[0][-1],'--approved-once')
    def test_failed_worker_is_never_repeated_and_not_echoed(self):
        with patch.object(task,'PAID_EXECUTION_ENABLED',True),patch.object(task,'worker_command',return_value=['fixed']):
            runner=Mock(return_value=SimpleNamespace(returncode=1,stdout='secret',stderr='secret'))
            with self.assertRaisesRegex(RuntimeError,'Do not repeat') as e:task.invoke(Path('.'),approved=True,runner=runner)
            self.assertNotIn('secret',str(e.exception));self.assertEqual(runner.call_count,1)
    def test_check_and_invalid_flags_never_infer(self):
        with patch.dict('os.environ',{'MODEL_API_KEY':'synthetic-not-a-key'}),patch('managed_model.run_once') as run,contextlib.redirect_stdout(io.StringIO()) as out:
            task.main(['--check'])
            self.assertTrue(json.loads(out.getvalue())['ready']);run.assert_not_called()
        with patch('managed_model.run_once') as run,contextlib.redirect_stdout(io.StringIO()) as out:
            task.main([]);self.assertIn('approval',out.getvalue());run.assert_not_called()
    def test_one_approved_mock_call_and_synthetic_metadata(self):
        with patch.object(task,'PAID_EXECUTION_ENABLED',True),patch.dict('os.environ',{'MODEL_API_KEY':'synthetic-not-a-key'}),patch('managed_model.run_once',return_value={'artifacts':{'summary.txt':b'{}'}}) as run,contextlib.redirect_stdout(io.StringIO()) as out:
            task.main(['--approved-once'])
            self.assertEqual(run.call_count,1)
            self.assertTrue(run.call_args.kwargs['authorized'])
            self.assertTrue(callable(run.call_args.kwargs['on_event']))
            data=json.loads(out.getvalue());self.assertTrue(data['synthetic_input']);self.assertTrue(data['real_model_execution'])
    def test_ui_review_and_start_have_no_paid_route(self):
        import ast
        source=Path('native_workspace.py').read_text()
        tree=ast.parse(source)
        for name in ('modelClicked_', 'dryStartClicked_'):
            node=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name==name)
            body=ast.get_source_segment(source,node)
            for forbidden in ('invoke(', 'startWorker_', 'run_once(', 'approved=True', 'subprocess', 'OpenAI'):
                self.assertNotIn(forbidden,body.replace('# REVIEW ONLY: deliberately no preflight, subprocess or model imports.', ''))
        self.assertNotIn('Approve one paid run',source)
        self.assertIn('Close review - no task',source)

    def test_progress_stream_from_real_local_subprocess_no_provider(self):
        import sys
        events=[]
        command=[sys.executable,'-c','import json; print(json.dumps({"progress":{"kind":"started","name":"synthetic-worker"}})); print(json.dumps({"artifacts":{},"removed":True}))']
        with patch.object(task,'PAID_EXECUTION_ENABLED',True),patch.object(task,'worker_command',return_value=command):
            result=task.invoke(Path('.'),approved=True,on_event=events.append)
        self.assertEqual(events,[{'kind':'started','name':'synthetic-worker'}])
        self.assertTrue(result['removed'])

    def test_paused_paid_paths_fail_before_any_subprocess_or_model(self):
        self.assertFalse(task.PAID_EXECUTION_ENABLED)
        with patch.object(task,'worker_command') as command,patch('managed_model.run_once') as run:
            with self.assertRaises(PermissionError):task.invoke(Path('.'),approved=True)
            with contextlib.redirect_stdout(io.StringIO()) as out:task.main(['--approved-once'])
            self.assertIn('paused',out.getvalue());command.assert_not_called();run.assert_not_called()
