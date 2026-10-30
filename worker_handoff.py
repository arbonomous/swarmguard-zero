"""Private local dry worker handoff. No provider, key lookup, Docker or network.

Uses an inherited socketpair, not an approval file or command-line grant. This
is a dry protocol prototype, not a paid-capable worker or host security boundary.
"""
from dataclasses import asdict
import base64
import json
from pathlib import Path
import socket
import subprocess
import sys
from execution_gate import digest
from task_review import binding

MAX_FRAME=65536


def send(stream, value):
    data=json.dumps(value,separators=(',',':')).encode()+b'\n'
    if len(data)>MAX_FRAME:raise PermissionError('IPC frame too large')
    stream.write(data);stream.flush()


def receive(stream):
    data=stream.readline(MAX_FRAME+1)
    if not data or len(data)>MAX_FRAME or not data.endswith(b'\n'):
        raise PermissionError('Invalid or interrupted IPC frame')
    value=json.loads(data)
    if not isinstance(value,dict):raise PermissionError('Invalid IPC message')
    return value


def launch_dry(coordinator, ticket, manifest, source, task, *, rounds=1):
    """Snapshot and verify inputs, durably claim, then launch this fixed dry child."""
    if type(rounds) is not int or not 0 <= rounds <= 4:
        raise ValueError('Dry protocol rounds exceeded')
    snapshot=dict(source)
    if not all(isinstance(k,str) and isinstance(v,bytes) for k,v in snapshot.items()):
        raise ValueError('Immutable named bytes required')
    if sum(map(len,snapshot.values()))>8192 or len(task.encode())>2048:
        raise ValueError('Dry handoff input limit exceeded')
    if binding(snapshot,task)!=manifest.input_hash:
        coordinator.cancel();raise PermissionError('Worker source/task changed')
    def operation(claim):
        parent,child=socket.socketpair()
        proc=None;stream=None
        try:
            parent.settimeout(5)
            # No host API credentials inherited or supplied on the command line.
            proc=subprocess.Popen([sys.executable,'-u',str(Path(__file__).resolve()),'--dry-child',str(child.fileno())],
                pass_fds=(child.fileno(),),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,env={'PYTHONNOUSERSITE':'1'})
            child.close();stream=parent.makefile('rwb')
            send(stream,{'kind':'dry_manifest','run_id':claim.run_id,'manifest':asdict(manifest),
                'manifest_hash':manifest.fingerprint(),'source':{k:base64.b64encode(v).decode() for k,v in snapshot.items()},
                'task':task,'rounds':rounds})
            ready=receive(stream)
            if ready!={'kind':'ready','run_id':claim.run_id,'manifest_hash':claim.manifest_hash}:
                raise PermissionError('Worker manifest acknowledgment mismatch')
            reservations=0
            for index in range(rounds):
                request=receive(stream)
                if request!={'kind':'reserve_dry','index':index,'context_bytes':len(task.encode())}:
                    raise PermissionError('Out-of-order worker request')
                # Synchronous durable reservation BEFORE permission returns to worker.
                coordinator.reserve_dry_request(claim,manifest,context_bytes=request['context_bytes'])
                reservations+=1
                send(stream,{'kind':'reserved_dry','index':index})
            result=receive(stream)
            expected={'kind':'done','reservations':reservations,'model_requests':0,'paid_authority':False}
            if result!=expected:raise PermissionError('Unverified worker result')
            if proc.wait(timeout=5)!=0:raise PermissionError('Worker failed after claim')
            return result
        finally:
            try:
                if stream:stream.close()
            finally:
                parent.close();child.close()
                if proc is not None and proc.poll() is None:
                    proc.kill();proc.wait(timeout=5)
    return coordinator.dispatch_dry(ticket,manifest,operation)


def child_main(fd):
    sock=socket.socket(fileno=fd);sock.settimeout(5)
    with sock, sock.makefile('rwb') as stream:
        message=receive(stream)
        if set(message)!={'kind','run_id','manifest','manifest_hash','source','task','rounds'} or message['kind']!='dry_manifest':
            raise PermissionError('No dry manifest')
        manifest=message['manifest']
        if digest(manifest)!=message['manifest_hash'] or manifest.get('retries')!=0:
            raise PermissionError('Changed manifest')
        source={k:base64.b64decode(v,validate=True) for k,v in message['source'].items()}
        if binding(source,message['task'])!=manifest['input_hash']:
            raise PermissionError('Changed source/task at worker boundary')
        if (type(message['rounds']) is not int or not 0<=message['rounds']<=4 or
            type(manifest['requests']) is not int or not 1<=manifest['requests']<=3 or
            type(manifest['completion_tokens']) is not int or not 1<=manifest['completion_tokens']<=1600 or
            type(manifest['context_bytes']) is not int or not len(message['task'].encode())<=manifest['context_bytes']<=32768 or
            sum(map(len,source.values()))>8192):
            raise PermissionError('Invalid dry budget')
        send(stream,{'kind':'ready','run_id':message['run_id'],'manifest_hash':message['manifest_hash']})
        for index in range(message['rounds']):
            send(stream,{'kind':'reserve_dry','index':index,'context_bytes':len(message['task'].encode())})
            if receive(stream)!={'kind':'reserved_dry','index':index}:
                raise PermissionError('No matching reservation')
        send(stream,{'kind':'done','reservations':message['rounds'],'model_requests':0,'paid_authority':False})


if __name__=='__main__':
    if len(sys.argv)!=3 or sys.argv[1]!='--dry-child':
        raise SystemExit('Only inherited dry IPC is supported. Paid execution is unavailable.')
    child_main(int(sys.argv[2]))
