import json,tempfile,unittest
from pathlib import Path
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock,patch
from execution_gate import Coordinator,Manifest

class ExecutionGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'approval.sqlite3';self.now=1000
        self.c=Coordinator(self.path,clock=lambda:self.now)
        self.m=Manifest.build({'source.txt':b'private source'},'private task',endpoint='https://provider.invalid/v1',model='synthetic-model',tools=[{'tool':'synthetic'}],image='sha256:synthetic',command=['/bin/synthetic'],warning='credits may spill to card')
    def ready(self):
        t=self.c.review(self.m);self.c.decide_dry(t,self.m,explicit_start=True);return t
    def test_review_close_cancel_escape_never_approve(self):
        for _ in ('close','escape','cancel','replace'):
            t=self.c.review(self.m);self.c.cancel()
            with self.assertRaises(PermissionError):self.c.claim_dry(t,self.m)
        t=self.c.review(self.m)
        with self.assertRaises(PermissionError):self.c.decide_dry(t,self.m)
    def test_claim_is_committed_before_callback_and_double_start_refused(self):
        t=self.ready()
        def callback(claim):
            self.assertEqual(self.c.audit()[-1]['state'],'claimed')
            with self.assertRaises(PermissionError):self.c.dispatch_dry(t,self.m,Mock())
            return 'dry'
        self.assertEqual(self.c.dispatch_dry(t,self.m,callback),'dry')
        self.assertEqual(self.c.audit()[-1]['state'],'succeeded')
    def test_concurrent_claim_only_one_wins(self):
        t=self.ready()
        def claim(_):
            try:self.c.claim_dry(t,self.m);return 1
            except PermissionError:return 0
        with ThreadPoolExecutor(max_workers=8) as pool:self.assertEqual(sum(pool.map(claim,range(8))),1)
    def test_every_manifest_change_refused(self):
        for field,value in [('input_hash','changed'),('endpoint','changed'),('model','changed'),('tools_hash','changed'),('image','changed'),('command',('changed',)),('requests',2),('completion_tokens',20),('context_bytes',20),('warning_hash','changed')]:
            t=self.ready()
            with self.assertRaises(PermissionError):self.c.claim_dry(t,replace(self.m,**{field:value}))
            self.assertEqual(self.c.audit()[-1]['state'],'refused')
    def test_expired_and_forged_consumed(self):
        t=self.ready();self.now+=301
        with self.assertRaises(PermissionError):self.c.claim_dry(t,self.m)
        t=self.ready()
        with self.assertRaises(PermissionError):self.c.claim_dry(replace(t),self.m)
        with self.assertRaises(PermissionError):self.c.claim_dry(t,self.m)
    def test_restart_invalidates_pending_and_cannot_recover_claim(self):
        t=self.ready();other=Coordinator(self.path,clock=lambda:self.now)
        with self.assertRaises(PermissionError):self.c.claim_dry(t,self.m)
        t=self.ready();claim=self.c.claim_dry(t,self.m)
        other=Coordinator(self.path,clock=lambda:self.now)
        with self.assertRaises(PermissionError):other.reserve_dry_request(claim,self.m,context_bytes=10)
        with self.assertRaises(PermissionError):other.claim_dry(t,self.m)
    def test_crash_unreadable_failure_stays_spent(self):
        for error in (RuntimeError('unreadable'),SystemExit()):
            t=self.ready()
            with self.assertRaises(type(error)):self.c.dispatch_dry(t,self.m,Mock(side_effect=error))
            self.assertEqual(self.c.audit()[-1]['state'],'unknown')
            with self.assertRaises(PermissionError):self.c.claim_dry(t,self.m)
    def test_persistence_failure_never_dispatches(self):
        t=self.ready();callback=Mock()
        with patch.object(self.c,'db',side_effect=OSError('disk')):
            with self.assertRaises(OSError):self.c.dispatch_dry(t,self.m,callback)
        callback.assert_not_called()
        with self.assertRaises(PermissionError):self.c.claim_dry(t,self.m)
    def test_request_limits_manifest_and_identity(self):
        t=self.ready();claim=self.c.claim_dry(t,self.m)
        with self.assertRaises(PermissionError):self.c.reserve_dry_request(replace(claim),self.m,context_bytes=1)
        with self.assertRaises(PermissionError):self.c.reserve_dry_request(claim,replace(self.m,model='other'),context_bytes=1)
        with self.assertRaises(PermissionError):self.c.reserve_dry_request(claim,self.m,context_bytes=40000)
        for _ in range(3):self.c.reserve_dry_request(claim,self.m,context_bytes=20)
        with self.assertRaises(PermissionError):self.c.reserve_dry_request(claim,self.m,context_bytes=20)
        self.assertEqual(self.c.audit()[-1]['requests'],3)
    def test_paid_dispatch_impossible_and_no_private_audit(self):
        callback=Mock();t=self.ready()
        with self.assertRaises(PermissionError):self.c.dispatch_paid(t,self.m,callback)
        callback.assert_not_called();text=json.dumps(self.c.audit())
        for value in ('private source','private task','synthetic-model','credits may spill','provider.invalid'):self.assertNotIn(value,text)
        self.assertTrue(all(r['paid_authority'] is False for r in self.c.audit()))
        self.assertEqual(self.path.stat().st_mode & 0o777,0o600)

    def test_invalid_manifest_and_limits_not_accepted(self):
        for kw in ({'requests':4},{'requests':True},{'completion_tokens':1601},{'context_bytes':32769},{'retries':1},{'command':['mutable']}):
            with self.assertRaises(ValueError):self.c.review(replace(self.m,**kw))
    def test_review_replacement_invalidates_old_and_start_with_changed_manifest(self):
        old=self.ready();new=self.c.review(self.m)
        with self.assertRaises(PermissionError):self.c.decide_dry(old,self.m,explicit_start=True)
        with self.assertRaises(PermissionError):self.c.claim_dry(new,self.m)
        t=self.c.review(self.m)
        with self.assertRaises(PermissionError):self.c.decide_dry(t,replace(self.m,model='changed'),explicit_start=True)
    def test_request_expiry_and_terminal_claim_refused(self):
        t=self.ready();claim=self.c.claim_dry(t,self.m);self.now+=301
        with self.assertRaises(PermissionError):self.c.reserve_dry_request(claim,self.m,context_bytes=1)
        self.c.finish(claim,'unknown')
        with self.assertRaises(PermissionError):self.c.reserve_dry_request(claim,self.m,context_bytes=1)

class NativeCoordinatorAdapterTests(unittest.TestCase):
    def test_exact_dry_handler_consumes_durable_claim_before_local_receipt(self):
        import ast,native_workspace
        from task_review import ReviewFlow
        tree=ast.parse(Path(native_workspace.__file__).read_text())
        node=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='dryStartClicked_')
        with tempfile.TemporaryDirectory() as tmp:
            controller=Mock();controller.busy=False
            controller.execution_gate=Coordinator(Path(tmp)/'gate.db')
            manifest=native_workspace.dry_manifest()
            controller.execution_ticket=controller.execution_gate.review(manifest)
            from native_model_task import SOURCE,TASK
            controller.review_flow=ReviewFlow()
            controller.review_receipt=controller.review_flow.reviewed({'sales.txt':SOURCE},TASK)
            original=controller.review_flow.consume_dry
            def consume(*args):
                self.assertEqual(controller.execution_gate.audit()[-1]['state'],'claimed')
                return original(*args)
            scope={'dry_manifest':native_workspace.dry_manifest,'check_summary':native_workspace.check_summary,'json':json}
            exec(compile(ast.Module(body=[node],type_ignores=[]),'<native dry handler>','exec'),scope)
            with patch.object(controller.review_flow,'consume_dry',side_effect=consume):scope['dryStartClicked_'](controller,None)
            controller.showError_.assert_not_called()
            self.assertEqual(controller.execution_gate.audit()[-1]['state'],'succeeded')
            self.assertIsNone(controller.review_receipt);self.assertIsNone(controller.execution_ticket)
            controller.startWorker_.assert_not_called();controller.dry_button.setEnabled_.assert_called_with(False)
            scope['dryStartClicked_'](controller,None)
            controller.showError_.assert_called_once()
