"""Persistent supervisor for protocol-speaking managed workloads, not host-wide AV.

The narrow broker only reads explicit copied source and writes reviewed in-memory
artifacts. It never executes a shell, opens arbitrary host paths or forwards keys.
"""
from __future__ import annotations
import json
import os
import selectors
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable
import isolated_runner as runner
from workspace_files import validate_files, safe_name


@dataclass
class Broker:
    source: dict[str, bytes]
    artifacts: dict[str, bytes] = field(default_factory=dict)
    calls: int = 0

    def __post_init__(self):
        self.source = validate_files(self.source)

    def request(self, request: dict) -> dict:
        self.calls += 1
        if self.calls > 64:
            raise PermissionError('Tool-call limit exceeded')
        if not isinstance(request, dict) or set(request) != {'id','tool','arguments'}:
            raise PermissionError('Unsupported request schema')
        if not isinstance(request['id'], int) or isinstance(request['id'], bool):
            raise PermissionError('Request ID must be an integer')
        tool, args = request['tool'], request['arguments']
        if not isinstance(args, dict):
            raise PermissionError('Arguments must be an object')
        if tool == 'read_source' and set(args) == {'path'}:
            path = safe_name(args['path'])
            if path not in self.source:
                raise PermissionError('Source path was not explicitly imported')
            return {'id':request['id'], 'ok':True, 'text':self.source[path].decode('utf-8')}
        if tool == 'write_artifact' and set(args) == {'path','text'}:
            path = safe_name(args['path'])
            if not isinstance(args['text'],str):
                raise PermissionError('Artifact text must be UTF-8 text')
            candidate = dict(self.artifacts);candidate[path] = args['text'].encode('utf-8')
            self.artifacts = validate_files(candidate)
            return {'id':request['id'], 'ok':True, 'saved':path}
        raise PermissionError('Tool is not allowed: ' + str(tool)[:80])


class Guard:
    def __init__(self, image: str):
        self.image = image
        self.events: list[dict] = []

    def record(self, kind: str, **data):
        self.events.append({'kind':kind,'elapsed':round(time.monotonic()-self.started,3), **data})

    def run(self, source: dict[str,bytes], command: list[str], seconds: int = 30,
            on_event: Callable[[dict],None] | None = None) -> dict:
        if not 1 <= seconds <= 120:
            raise ValueError('Runtime must be 1..120 seconds')
        broker = Broker(source)
        self.events=[];self.started=time.monotonic()
        image_id=runner.local_image(self.image)
        name='swarmguard-'+uuid.uuid4().hex
        created=False;attached=None;denied=False;stopped=False;removed=False
        failure=None
        try:
            args=runner.create_args(image_id,name,command)
            args.insert(1,'--interactive')
            created=True;runner.docker(*args)
            runner.verify_container(json.loads(runner.docker('inspect',name).stdout)[0],name,image_id)
            env=os.environ.copy()
            for key in ('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'):
                env.pop(key,None)
            attached=subprocess.Popen(['docker','--context',runner.CONTEXT,'start','--attach','--interactive',name],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
            self.record('started',name=name,scope='owned offline workload only')
            streams=selectors.DefaultSelector()
            streams.register(attached.stdout,selectors.EVENT_READ,'stdout')
            streams.register(attached.stderr,selectors.EVENT_READ,'stderr')
            buffer=b'';total=0;deadline=time.monotonic()+seconds
            try:
                while streams.get_map():
                    if time.monotonic()>=deadline:
                        raise TimeoutError('Managed workload time limit reached')
                    for event,_ in streams.select(.2):
                        data=os.read(event.fd,4096)
                        if not data:
                            streams.unregister(event.fileobj);continue
                        total+=len(data)
                        if total>1024*1024:
                            raise PermissionError('Managed output limit exceeded')
                        if event.data=='stderr':
                            continue # Never promote untrusted diagnostics to instructions.
                        buffer+=data
                        if len(buffer)>65536:
                            raise PermissionError('Tool request exceeds 64 KiB')
                        while b'\n' in buffer:
                            line,buffer=buffer.split(b'\n',1)
                            try:
                                request=json.loads(line)
                                response=broker.request(request)
                            except (PermissionError,ValueError,TypeError,KeyError,UnicodeError) as exc:
                                denied=True
                                self.record('denied',reason=str(exc)[:180],effect_executed=False)
                                if on_event:on_event(self.events[-1])
                                raise PermissionError('Managed tool request denied') from exc
                            self.record('allowed',tool=request['tool'],request_id=request['id'])
                            if on_event:on_event(self.events[-1])
                            encoded=(json.dumps(response,separators=(',',':'))+'\n').encode()
                            if len(encoded)>65536:
                                raise PermissionError('Broker response too large')
                            # A workload that stops reading must not hang the supervisor.
                            os.set_blocking(attached.stdin.fileno(), False)
                            pending=memoryview(encoded)
                            with selectors.DefaultSelector() as writable:
                                writable.register(attached.stdin,selectors.EVENT_WRITE)
                                while pending:
                                    if time.monotonic() >= deadline:
                                        raise TimeoutError('Broker response deadline reached')
                                    if writable.select(.1):
                                        try:
                                            pending=pending[os.write(attached.stdin.fileno(),pending):]
                                        except BlockingIOError:
                                            pass
                if buffer.strip():
                    raise PermissionError('Incomplete tool request')
                code=attached.wait(timeout=2)
                if code:
                    raise RuntimeError('Managed workload exited with an error')
                self.record('completed')
            finally:
                streams.close()
        except Exception as exc:
            failure=type(exc).__name__+': '+str(exc)[:180]
            self.record('stopping',reason=failure)
        finally:
            if created:
                try:
                    # Kill only this generated workload, even if paused or unresponsive.
                    runner.docker('stop','--time','0',name,timeout=15)
                    state=json.loads(runner.docker('inspect',name).stdout)[0]['State']
                    stopped=not state.get('Running',True)
                    if not stopped:raise RuntimeError('Workload still running')
                    self.record('stopped',verified=True)
                except Exception as exc:
                    self.record('stop_check_failed',error=type(exc).__name__)
                try:
                    runner.docker('rm','--force',name,timeout=15)
                    names=runner.docker('ps','-a','--filter','name=^/'+name+'$','--format','{{.Names}}').stdout.strip()
                    removed=not names
                    self.record('removed',verified=removed)
                except Exception as exc:
                    self.record('cleanup_failed',name=name,error=type(exc).__name__)
            if attached is not None:
                if attached.poll() is None:attached.kill()
                attached.wait(timeout=5)
                for stream in (attached.stdin,attached.stdout,attached.stderr):stream.close()
        return {'scope':'Managed offline workload only; no outside agents covered',
                'denied':denied,'stopped':stopped,'removed':removed,'failure':failure,
                'events':self.events,'artifacts':broker.artifacts,'name':name}


PROOF_COMMAND = ['/bin/sh','-c',r'''set -eu
printf '%s\n' '{"id":1,"tool":"read_source","arguments":{"path":"input.txt"}}'
IFS= read -r response
printf '%s\n' '{"id":2,"tool":"write_artifact","arguments":{"path":"summary.txt","text":"Completed synthetic source task before the guard intervention."}}'
IFS= read -r response
printf '%s\n' '{"id":3,"tool":"read_host_file","arguments":{"path":"~/.ssh/id_ed25519"}}'
IFS= read -r response
printf '%s\n' '{"id":4,"tool":"write_artifact","arguments":{"path":"should-not-exist.txt","text":"Guard failed to stop workload"}}'
''']


def prove_intervention() -> dict:
    from isolation_check import VERIFIED_IMAGE
    result=Guard(VERIFIED_IMAGE).run({'input.txt':b'Synthetic source only. No real secrets.\n'},PROOF_COMMAND,15)
    result['proof_passed']=(result['denied'] and result['stopped'] and result['removed'] and
        'summary.txt' in result['artifacts'] and 'should-not-exist.txt' not in result['artifacts'])
    result['synthetic_workload']=True
    return result
