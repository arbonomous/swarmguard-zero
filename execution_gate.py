"""Durable dry-only execution coordinator. No UI or provider imports.

A recorded decision is not proof of user authority. A future trusted UI adapter
must verify that authority independently. This module cannot dispatch paid work.
Same-user arbitrary code execution is outside this accidental-launch boundary.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import threading
import time
from task_review import binding


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


@dataclass(frozen=True)
class Manifest:
    input_hash: str
    endpoint: str
    model: str
    tools_hash: str
    image: str
    command: tuple
    requests: int
    completion_tokens: int
    context_bytes: int
    warning_hash: str
    retries: int = 0

    @classmethod
    def build(cls, source, task, *, endpoint, model, tools, image, command,
              requests=3, completion_tokens=1600, context_bytes=32768, warning):
        if (type(requests) is not int or not 1 <= requests <= 3 or
            type(completion_tokens) is not int or not 1 <= completion_tokens <= 1600 or
            type(context_bytes) is not int or not 1 <= context_bytes <= 32768):
            raise ValueError('Run limits exceeded')
        if not all(isinstance(v,str) and v for v in (endpoint,model,image,warning)):
            raise ValueError('Complete manifest required')
        if not command or not all(isinstance(v,str) for v in command):
            raise ValueError('Fixed worker command required')
        return cls(binding(source,task),endpoint,model,digest(tools),image,tuple(command),
                   requests,completion_tokens,context_bytes,digest(warning))

    def fingerprint(self):
        if (type(self.requests) is not int or not 1 <= self.requests <= 3 or
            type(self.completion_tokens) is not int or not 1 <= self.completion_tokens <= 1600 or
            type(self.context_bytes) is not int or not 1 <= self.context_bytes <= 32768 or
            self.retries != 0 or type(self.command) is not tuple):
            raise ValueError('Invalid manifest limits or command')
        return digest(self.__dict__)


@dataclass(frozen=True)
class Ticket:
    run_id: str
    manifest_hash: str


class Coordinator:
    def __init__(self, path, *, clock=time.time):
        self.path=Path(path);self.clock=clock;self.lock=threading.RLock()
        self.pending=None;self.claims={}
        self.path.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(self.path,os.O_CREAT | os.O_APPEND | os.O_WRONLY,0o600)
        os.close(fd)
        self.path.chmod(0o600)
        with self.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, manifest TEXT NOT NULL, state TEXT NOT NULL, created REAL NOT NULL, expires REAL NOT NULL, updated REAL NOT NULL, requests INTEGER NOT NULL DEFAULT 0)')
            # Pending permission never survives restart; claimed work never retries.
            db.execute("UPDATE runs SET state='invalidated',updated=? WHERE state IN ('reviewed','approved')",(clock(),))
        self.path.chmod(0o600)

    @contextmanager
    def db(self):
        db=sqlite3.connect(self.path,timeout=5)
        try:
            db.execute('PRAGMA synchronous=FULL')
            with db:
                yield db
        finally:
            db.close()

    def cancel(self):
        with self.lock:
            ticket,self.pending=self.pending,None
            if ticket:
                with self.db() as db:
                    db.execute("UPDATE runs SET state='invalidated',updated=? WHERE id=? AND state IN ('reviewed','approved')",(self.clock(),ticket.run_id))

    def review(self, manifest, *, ttl=120):
        if not isinstance(manifest,Manifest) or not 0 < ttl <= 300:
            raise ValueError('Bounded manifest/expiry required')
        with self.lock:
            self.cancel()
            ticket=Ticket(secrets.token_hex(16),manifest.fingerprint());now=self.clock()
            with self.db() as db:
                db.execute('INSERT INTO runs(id,manifest,state,created,expires,updated) VALUES (?,?,?,?,?,?)',(ticket.run_id,ticket.manifest_hash,'reviewed',now,now+ttl,now))
            self.pending=ticket
            return ticket

    def decide_dry(self, ticket, manifest, *, explicit_start=False):
        """Future adapter seam only. Review-close must never call this as approval."""
        with self.lock:
            if explicit_start is not True or ticket is None or ticket is not self.pending:
                self.cancel();raise PermissionError('No distinct current start decision')
            with self.db() as db:
                changed=db.execute("UPDATE runs SET state='approved',updated=? WHERE id=? AND manifest=? AND state='reviewed' AND expires>?",(self.clock(),ticket.run_id,manifest.fingerprint(),self.clock())).rowcount
            if changed!=1:
                self.cancel();raise PermissionError('Changed, expired or invalid review')

    def claim_dry(self, ticket, manifest):
        with self.lock:
            pending,self.pending=self.pending,None
            if pending is None or ticket is not pending:
                if pending:
                    with self.db() as db:db.execute("UPDATE runs SET state='refused',updated=? WHERE id=? AND state IN ('reviewed','approved')",(self.clock(),pending.run_id))
                raise PermissionError('No current one-use decision')
            # Consume durably even for a mismatched manifest; never leave retryable.
            with self.db() as db:
                db.execute('BEGIN IMMEDIATE')
                row=db.execute('SELECT manifest,state,expires FROM runs WHERE id=?',(ticket.run_id,)).fetchone()
                valid=row is not None and row[0]==manifest.fingerprint() and row[1]=='approved' and row[2]>self.clock()
                db.execute("UPDATE runs SET state=?,updated=? WHERE id=? AND state IN ('reviewed','approved')",('claimed' if valid else 'refused',self.clock(),ticket.run_id))
            if not valid:raise PermissionError('Decision refused; nothing started')
            claim=Ticket(ticket.run_id,ticket.manifest_hash)
            self.claims[claim.run_id]=claim
            return claim

    def reserve_dry_request(self, claim, manifest, *, context_bytes):
        with self.lock:
            if self.claims.get(claim.run_id) is not claim:raise PermissionError('Unknown claim')
            if type(context_bytes) is not int or not 0 <= context_bytes <= manifest.context_bytes:
                raise PermissionError('Context limit exceeded')
            with self.db() as db:
                changed=db.execute("UPDATE runs SET requests=requests+1,updated=? WHERE id=? AND manifest=? AND state='claimed' AND expires>? AND requests<?",(self.clock(),claim.run_id,manifest.fingerprint(),self.clock(),manifest.requests)).rowcount
            if changed!=1:raise PermissionError('Run expired, exhausted or changed')

    def dispatch_dry(self, ticket, manifest, callback):
        claim=self.claim_dry(ticket,manifest) # committed before any callback
        try:
            result=callback(claim)
        except BaseException:
            self.finish(claim,'unknown');raise
        self.finish(claim,'succeeded')
        return result

    def finish(self, claim, outcome):
        if outcome not in ('succeeded','failed','unknown'):raise ValueError('Invalid outcome')
        with self.lock:
            if self.claims.get(claim.run_id) is not claim:raise PermissionError('Unknown claim')
            # If persistence fails, claim stays spent and cannot be dispatched again.
            with self.db() as db:db.execute("UPDATE runs SET state=?,updated=? WHERE id=? AND state='claimed'",(outcome,self.clock(),claim.run_id))
            self.claims.pop(claim.run_id,None)

    def dispatch_paid(self, *args, **kwargs):
        raise PermissionError('Paid dispatch is not implemented or enabled')

    def audit(self):
        with self.db() as db:
            rows=db.execute('SELECT id,manifest,state,created,expires,updated,requests FROM runs ORDER BY rowid').fetchall()
        return [dict(zip(('run_id','manifest_hash','state','created','expires','updated','requests'),row),paid_authority=False) for row in rows]
