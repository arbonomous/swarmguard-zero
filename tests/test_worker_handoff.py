import base64,json,socket,tempfile,threading,unittest
from dataclasses import asdict
from pathlib import Path
from unittest.mock import Mock,patch
from execution_gate import Coordinator,Manifest,digest
from worker_handoff import launch_dry,send,receive,child_main,MAX_FRAME

class WorkerHandoffTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.c=Coordinator(Path(self.tmp.name)/'gate.db')
        self.source={'data.txt':b'synthetic'};self.task='dry synthetic task'
        self.m=Manifest.build(self.source,self.task,endpoint='https://invalid.test',model='none',tools=[],image='sha256:synthetic',command=['dry'],warning='billing warning')
    def ready(self):
        ticket=self.c.review(self.m);self.c.decide_dry(ticket,self.m,explicit_start=True);return ticket
    def test_actual_local_child_private_handoff_and_reservations(self):
        ticket=self.ready()
        import worker_handoff
        real=worker_handoff.subprocess.Popen
        def spawn(*args,**kwargs):
            self.assertEqual(self.c.audit()[-1]['state'],'claimed')
            self.assertEqual(kwargs['env'],{'PYTHONNOUSERSITE':'1'})
            self.assertNotIn(self.task,' '.join(args[0]));self.assertEqual(len(kwargs['pass_fds']),1)
            return real(*args,**kwargs)
        with patch.object(worker_handoff.subprocess,'Popen',side_effect=spawn):
            result=launch_dry(self.c,ticket,self.m,self.source,self.task,rounds=3)
        self.assertEqual(result['model_requests'],0);self.assertEqual(result['reservations'],3)
        self.assertEqual(self.c.audit()[-1]['state'],'succeeded');self.assertEqual(self.c.audit()[-1]['requests'],3)
        with self.assertRaises(PermissionError):launch_dry(self.c,ticket,self.m,self.source,self.task)
    def test_fourth_reservation_denied_and_child_cleaned(self):
        with self.assertRaises(PermissionError):launch_dry(self.c,self.ready(),self.m,self.source,self.task,rounds=4)
        self.assertEqual(self.c.audit()[-1]['state'],'unknown');self.assertEqual(self.c.audit()[-1]['requests'],3)
    def test_input_substitution_refused_before_spawn(self):
        with patch('worker_handoff.subprocess.Popen') as spawn:
            with self.assertRaises(PermissionError):launch_dry(self.c,self.ready(),self.m,{'data.txt':b'changed'},self.task)
            spawn.assert_not_called()
    def test_spawn_failure_is_spent_not_retryable(self):
        ticket=self.ready()
        with patch('worker_handoff.subprocess.Popen',side_effect=OSError('synthetic')):
            with self.assertRaises(OSError):launch_dry(self.c,ticket,self.m,self.source,self.task)
        self.assertEqual(self.c.audit()[-1]['state'],'unknown')
    def test_worker_rejects_changed_source_and_manifest(self):
        for change in ('source','manifest'):
            parent,child=socket.socketpair();errors=[]
            fd=child.detach()
            def run():
                try:child_main(fd)
                except Exception as exc:errors.append(exc)
            thread=threading.Thread(target=run);thread.start()
            with parent,parent.makefile('rwb') as stream:
                payload={'kind':'dry_manifest','run_id':'synthetic','manifest':asdict(self.m),'manifest_hash':self.m.fingerprint(),'source':{'data.txt':base64.b64encode(b'synthetic').decode()},'task':self.task,'rounds':1}
                if change=='source':payload['source']['data.txt']=base64.b64encode(b'changed').decode()
                else:payload['manifest']['model']='changed'
                send(stream,payload)
            thread.join(timeout=2);self.assertFalse(thread.is_alive());self.assertIsInstance(errors[0],PermissionError)
    def test_frame_limits_and_no_standalone_paid_entry(self):
        import io
        for data in (b'',b'{}',b'[]\n',b'x'*(MAX_FRAME+1)):
            with self.assertRaises((PermissionError,ValueError)):receive(io.BytesIO(data))
        with self.assertRaises(PermissionError):send(io.BytesIO(),{'large':'x'*MAX_FRAME})

    def test_reservation_storage_failure_stops_child_without_retry(self):
        ticket=self.ready()
        with patch.object(self.c,'reserve_dry_request',side_effect=OSError('disk full')) as reserve:
            with self.assertRaises(OSError):launch_dry(self.c,ticket,self.m,self.source,self.task,rounds=2)
            self.assertEqual(reserve.call_count,1)
        self.assertEqual(self.c.audit()[-1]['state'],'unknown')
        self.assertEqual(self.c.audit()[-1]['requests'],0)
