import json,unittest
from dataclasses import replace
from task_review import ReviewFlow,binding

SOURCE={'sales.txt':b'made-up'}
TASK='synthetic task'
class ReviewFlowTests(unittest.TestCase):
    def test_no_receipt_refused(self):
        with self.assertRaises(PermissionError):ReviewFlow().consume_dry(None,SOURCE,TASK)
    def test_exact_one_use_consumed_before_continuation(self):
        flow=ReviewFlow();receipt=flow.reviewed(SOURCE,TASK)
        event=flow.consume_dry(receipt,SOURCE,TASK)
        self.assertIsNone(flow.pending);self.assertFalse(event['paid_authority'])
        self.assertFalse(event['worker_started']);self.assertEqual(event['model_requests'],0)
        with self.assertRaises(PermissionError):flow.consume_dry(receipt,SOURCE,TASK)
    def test_source_task_and_forged_receipt_refused_consumed(self):
        for source,task,forge in (({'sales.txt':b'changed'},TASK,False),(SOURCE,'changed',False),(SOURCE,TASK,True)):
            flow=ReviewFlow();receipt=flow.reviewed(SOURCE,TASK)
            if forge:receipt=replace(receipt)
            with self.assertRaises(PermissionError):flow.consume_dry(receipt,source,task)
            self.assertIsNone(flow.pending)
    def test_replacement_and_cancel_invalidate_old(self):
        flow=ReviewFlow();old=flow.reviewed(SOURCE,TASK);flow.begin_review()
        with self.assertRaises(PermissionError):flow.consume_dry(old,SOURCE,TASK)
        new=flow.reviewed(SOURCE,TASK)
        self.assertNotEqual(old.run_id,new.run_id)
    def test_audit_contains_no_source_or_task_text_or_authority(self):
        flow=ReviewFlow();r=flow.reviewed(SOURCE,TASK);flow.consume_dry(r,SOURCE,TASK)
        audit=json.dumps(flow.audit)
        self.assertNotIn('made-up',audit);self.assertNotIn(TASK,audit)
        self.assertTrue(all(e['paid_authority'] is False for e in flow.audit))
        self.assertEqual(binding(SOURCE,TASK),r.binding)
