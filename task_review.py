"""In-memory, one-use review binding. Never grants paid execution.

A review receipt records presentation, not user spending authority. The dry-start
receipt records only a nonpaying check. No keys, source text or task text in audit.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import secrets


def binding(source: dict[str, bytes], task: str) -> str:
    canonical = {'sources': [{'name': name, 'bytes': len(data),
                             'sha256': hashlib.sha256(data).hexdigest()}
                            for name, data in sorted(source.items())],
                 'task_sha256': hashlib.sha256(task.encode('utf-8')).hexdigest()}
    return hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest()


def now():
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class ReviewReceipt:
    run_id: str
    binding: str
    reviewed_at: str


class ReviewFlow:
    def __init__(self):
        self.pending = None
        self.audit = []

    def invalidate(self, reason='review replaced'):
        if self.pending is not None:
            self.audit.append({'event': 'review_invalidated', 'run_id': self.pending.run_id,
                               'reason': reason, 'at': now(), 'paid_authority': False})
        self.pending = None

    def begin_review(self):
        # An interrupted/canceled replacement cannot leave an older start active.
        self.invalidate()

    def reviewed(self, source, task):
        self.invalidate()
        self.pending = ReviewReceipt(secrets.token_hex(16), binding(source, task), now())
        self.audit.append({'event': 'review_presented', 'run_id': self.pending.run_id,
                           'binding_sha256': self.pending.binding,
                           'at': self.pending.reviewed_at, 'paid_authority': False})
        return self.pending

    def consume_dry(self, receipt, source, task):
        pending, self.pending = self.pending, None  # consume BEFORE any continuation
        if pending is None or receipt is not pending:
            raise PermissionError('No current one-use review. Nothing started.')
        if pending.binding != binding(source, task):
            self.audit.append({'event': 'binding_refused', 'run_id': pending.run_id,
                               'at': now(), 'paid_authority': False})
            raise PermissionError('Source or task changed. Review again; nothing started.')
        event = {'event': 'dry_start_consumed', 'run_id': pending.run_id,
                 'binding_sha256': pending.binding, 'at': now(),
                 'user_action': 'Check start - no spend', 'paid_authority': False,
                 'model_requests': 0, 'worker_started': False}
        self.audit.append(event)
        return event.copy()
