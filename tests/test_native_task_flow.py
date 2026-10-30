import json,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace as S
from unittest.mock import Mock,patch
from execution_gate import Coordinator
from native_task_flow import StartFlow,prepare,SingleArtifactSession

class NativeTaskFlowTests(unittest.TestCase):
    def gate(self,tmp):return Coordinator(Path(tmp)/'audit.db')
    def test_review_close_changed_replay_never_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            flow=StartFlow(self.gate(tmp));client=Mock()
            with patch('native_task_flow.execute') as run:
                text=flow.review({'x.txt':b'public notes'},'Checklist')
                self.assertIn('NOTHING STARTED',text);run.assert_not_called()
                with self.assertRaises(PermissionError):flow.start({'x.txt':b'public notes'},'Changed',explicit_start=True,client=client)
                run.assert_not_called()
                flow.review({'x.txt':b'public notes'},'Checklist');flow.invalidate()
                with self.assertRaises(PermissionError):flow.start({'x.txt':b'public notes'},'Checklist',explicit_start=True,client=client)
                flow.review({'x.txt':b'public notes'},'Checklist')
                flow.start({'x.txt':b'public notes'},'Checklist',explicit_start=True,client=client)
                run.assert_called_once()
                with self.assertRaises(PermissionError):flow.start({'x.txt':b'public notes'},'Checklist',explicit_start=True,client=client)
                self.assertEqual(run.call_count,1)
    def test_live_release_refused_before_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            flow=StartFlow(self.gate(tmp));flow.review({'x.txt':b'public'},'Checklist')
            with patch('native_task_flow.execute') as run,self.assertRaises(PermissionError):flow.start({'x.txt':b'public'},'Checklist',explicit_start=True)
            run.assert_not_called()
    def test_actual_task_proposal_both_defenders_then_finish(self):
        from native_task_flow import execute
        from managed_guard import Broker
        with tempfile.TemporaryDirectory() as tmp:
            gate=self.gate(tmp);flow=StartFlow(gate);source={'x.txt':b'public notes'};goal='Make a checklist'
            flow.review(source,goal);client=Mock()
            def respond(**kw):
                if 'tools' in kw:return S(usage=None,choices=[S(finish_reason='tool_calls',message=S(tool_calls=[S(function=S(name='write_artifact',arguments='{"path":"checklist.md","text":"- Review notes"}'))]))])
                p=json.loads(kw['messages'][1]['content']);c=p['untrusted_context']
                return S(usage=None,choices=[S(finish_reason='stop',message=S(tool_calls=[],content=json.dumps({'role':p['reviewer_role'],'action_hash':c['action_hash'],'decision':'allow','reason':'Matches goal','evidence':'Review notes'})))])
            client.chat.completions.create.side_effect=respond
            def guard(_self,source,command,**kw):
                broker=Broker(source,defense_council=kw['defense_council']);session=kw['model_session']
                action=session.request({'id':0,'tool':'model_next','arguments':{}},broker)
                self.assertEqual(broker.artifacts,{})
                session.request(action,broker)
                self.assertEqual(client.chat.completions.create.call_count,3)
                self.assertEqual(session.request({'id':0,'tool':'model_next','arguments':{}},broker),{'finished':True})
                return dict(artifacts=broker.artifacts,denied=False,stopped=True,removed=True,failure=None)
            with patch('managed_guard.Guard.run',new=guard):result=flow.start(source,goal,explicit_start=True,client=client)
            self.assertTrue(result['export_permitted']);self.assertEqual(gate.audit()[-1]['requests'],3)
            self.assertTrue(result['artifacts']);self.assertFalse(result['native_paid_enabled'])
    def test_bounds_and_denied_export(self):
        from protected_task import export_review
        self.assertEqual(prepare({'x.txt':b'public'},'Goal').manifest.all_role_requests,3)
        with self.assertRaises(ValueError):prepare({'x.txt':b'x'*1025},'Goal')
        with self.assertRaises(PermissionError):export_review(dict(export_permitted=False,stopped=True,removed=True,artifacts={'x.txt':b'no'}))

class ScopedTransportTests(unittest.TestCase):
    def test_unreleased_transport_refuses_changed_or_general_entry(self):
        from provider_bridge import ProviderBridge
        plan=prepare({'x.txt':b'public'},'Checklist')
        with self.assertRaises(PermissionError):ProviderBridge.for_native_task(None,None,plan,client=Mock())
    def test_lazy_transport_no_key_before_guard_requests(self):
        from native_task_flow import execute
        with tempfile.TemporaryDirectory() as tmp:
            gate=Coordinator(Path(tmp)/'audit.db');plan=prepare({'x.txt':b'public'},'Checklist')
            ticket=gate.review(plan.manifest);gate.decide_dry(ticket,plan.manifest,explicit_start=True)
            def guard(*args,**kwargs):
                return dict(artifacts={},stopped=True,removed=True,denied=False,failure='Boundary refused')
            with patch('native_task_flow.NATIVE_LIVE_RELEASED',True),patch('managed_guard.Guard.run',side_effect=guard),patch('dotenv.load_dotenv') as load,patch('openai.OpenAI') as api:
                result=execute(plan,gate,ticket)
            load.assert_not_called();api.assert_not_called();self.assertFalse(result['export_permitted'])
    def test_native_start_unreleased_and_changed_inputs_never_threads(self):
        import ast,native_workspace
        node=next(n for n in ast.walk(ast.parse(Path(native_workspace.__file__).read_text())) if isinstance(n,ast.FunctionDef) and n.name=='protectedStartClicked_')
        scope={};exec(compile(ast.Module(body=[node],type_ignores=[]),'<native Start>','exec'),scope)
        controller=Mock();controller.busy=False
        scope['protectedStartClicked_'](controller,None)
        controller.setBusy_.assert_not_called();controller.showError_.assert_called_once()
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'notes.txt';p.write_text('public')
            controller=Mock();controller.busy=False;controller.paths=[str(p)]
            controller.command.stringValue.return_value='Goal';controller.protected_flow=None
            with patch('native_task_flow.NATIVE_LIVE_RELEASED',True):scope['protectedStartClicked_'](controller,None)
            controller.setBusy_.assert_not_called();controller.showError_.assert_called_once()

class ProtectedLayoutTests(unittest.TestCase):
    def test_dedicated_rectangles_do_not_overlap(self):
        from native_workspace import protected_layout
        frames=protected_layout()
        for a,(x,y,w,h) in frames.items():
            self.assertGreaterEqual(x,18);self.assertGreaterEqual(y,48)
            self.assertLessEqual(x+w,572);self.assertLessEqual(y+h,524)
            for b,(xx,yy,ww,hh) in frames.items():
                if a>=b:continue
                self.assertFalse(x<xx+ww and xx<x+w and y<yy+hh and yy<y+h,(a,b))
    def test_display_limits_share_execution_constants(self):
        import native_task_flow as task
        self.assertIn(str(task.MAX_GOAL_BYTES),task.limits_text())
        self.assertIn(str(task.MAX_SOURCE_BYTES//1024)+' KiB',task.limits_text())
        with patch.object(task,'MAX_SOURCE_BYTES',3),self.assertRaises(ValueError):task.prepare({'x.txt':b'four'},'Goal')
    def test_actual_section_handler_hides_legacy_controls(self):
        import ast,native_workspace
        node=next(n for n in ast.walk(ast.parse(Path(native_workspace.__file__).read_text())) if isinstance(n,ast.FunctionDef) and n.name=='sectionChanged_')
        scope={'NSMakeRect':lambda *v:v,'protected_layout':native_workspace.protected_layout}
        exec(compile(ast.Module(body=[node],type_ignores=[]),'<native section>','exec'),scope)
        c=Mock();c.busy=False;c.protected_flow=None;c.base_frames=[]
        c.sections.titleOfSelectedItem.return_value='Protected task'
        c.workspace_views=[c.workspace_scope,c.pick_button,c.selection,c.command_label,c.command,c.exports_label,c.exports,c.workspace_limits,c.run_button,c.save_button,c.protected_start,c.check_button]
        c.top_views=[Mock() for _ in range(7)]
        c.command.stringValue.return_value=''
        scope['sectionChanged_'](c,None)
        for view in c.top_views:self.assertEqual(view.setHidden_.call_args.args,(True,))
        for view in [c.home_button,c.details_button,c.check_button,c.exports_label,c.exports,c.save_button]:self.assertEqual(view.setHidden_.call_args.args,(True,))
        self.assertEqual(c.protected_start.setEnabled_.call_args.args,(False,))
        self.assertEqual(c.workspace_limits.setStringValue_.call_args.args[0],__import__('native_task_flow').limits_text())
        for name,rect in native_workspace.protected_layout().items():self.assertEqual(getattr(c,name).setFrame_.call_args.args,(rect,))
