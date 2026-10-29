"""Explicit-copy, offline source workspace. No mounts, pulls, keys or model calls."""
from __future__ import annotations
import json
import uuid
import time
import isolated_runner as runner
from workspace_files import validate_files, safe_name, make_archive, read_archive


def run(files: dict[str, bytes], command: list[str], export_names: list[str], *,
        image: str, seconds: int = 30) -> dict:
    """Return selected text outputs for review, never overwrite the source project.

    Caller must show exact imports, command and requested exports before launch.
    Image/command must be trusted. This is not a malware detonation service.
    """
    files = validate_files(files)
    if not command or not command[0].startswith('/') or not 1 <= seconds <= 120:
        raise ValueError('Use an absolute in-image executable and 1..120 seconds')
    if not export_names or len(export_names) > 20:
        raise ValueError('Select 1..20 output filenames')
    export_names = [safe_name(name) for name in export_names]
    if len(set(export_names)) != len(export_names):
        raise ValueError('Select distinct output filenames')
    image_id = runner.local_image(image)
    deadline = time.monotonic() + seconds + 45
    def call(*args, **kwargs):
        remaining = int(deadline - time.monotonic())
        if remaining < 1:
            raise TimeoutError('Total workspace deadline reached')
        kwargs['timeout'] = min(kwargs.get('timeout', 15), remaining)
        return runner.docker(*args, **kwargs)
    name = 'swarmguard-' + uuid.uuid4().hex
    created = False
    try:
        args = runner.create_args(image_id, name, ['/bin/sh', '-c', 'exec sleep 180'])
        created = True
        call(*args)
        runner.verify_container(json.loads(call('inspect', name).stdout)[0], name, image_id)
        call('start', name)
        call('exec', name, '/bin/mkdir', '-p', '/tmp/project')
        call('cp', '-a', '-', name + ':/tmp/project',
                      input_data=make_archive(files))
        result = call('exec', '--workdir', '/tmp/project', name, *command, timeout=seconds)
        # Freeze all in-container processes before inspecting outputs. Pausing
        # preserves tmpfs while preventing background replacement races.
        call('pause', name)
        outputs = {}
        total = 0
        for path in export_names:
            archive = call('cp', name + ':/tmp/project/' + path, '-', raw=True).stdout
            returned = read_archive(archive)
            expected = path.rsplit('/', 1)[-1]
            if set(returned) != {expected}:
                raise ValueError('Unexpected returned archive path')
            total += len(returned[expected])
            if total > 4 * 1024 * 1024:
                raise ValueError('Total exported source exceeds 4 MiB')
            outputs[path] = returned[expected]
        return {'files': validate_files(outputs), 'stdout': result.stdout,
                'stderr': result.stderr, 'scope': 'Offline copied workspace only; exports require review.'}
    finally:
        if created:
            try:
                runner.docker('rm', '--force', name, timeout=15)
            except Exception as exc:
                raise RuntimeError('Cleanup failed for scratch container ' + name + '; no other containers were changed') from exc
