"""Local synthetic isolation check. No pulls, network calls, keys or host mounts."""
from __future__ import annotations
import contextlib
import io
from datetime import datetime, timezone
import isolated_runner as runner

# Matched against Docker Hub library/redis on 2026-10-29; never auto-download.
VERIFIED_IMAGE = 'sha256:978f0e01593e65eed801f2402944efcd936d43b5027e4908a7897baf88ed6241'
CHECKS = ('scratch-write', 'readonly-root', 'loopback-only',
          'common-host-paths-and-sockets-absent', 'no-capabilities-no-new-privileges')
PROBE = r'''set -eu
test "$(id -u)" = 65534
touch /tmp/scratch-ok; test -f /tmp/scratch-ok; echo PASS-scratch-write
ro=no
while read -r dev path fs opts rest; do
  if [ "$path" = / ]; then case ",$opts," in *,ro,*) ro=yes;; esac; fi
done < /proc/mounts
test "$ro" = yes
if touch /swarmguard-root-probe 2>/dev/null; then echo FAIL-root-write; exit 1; fi
echo PASS-readonly-root
for p in /sys/class/net/*; do test "${p##*/}" = lo; done
echo PASS-loopback-only
for p in /Users /host /mnt/host /run/host /var/run/docker.sock /run/docker.sock; do test ! -e "$p"; done
echo PASS-common-host-paths-and-sockets-absent
caps=no; nnp=no
while read -r key value rest; do
  case "$key" in
    CapEff:) test "$value" = 0000000000000000; caps=yes;;
    NoNewPrivs:) test "$value" = 1; nnp=yes;;
  esac
done < /proc/self/status
test "$caps" = yes; test "$nnp" = yes
echo PASS-no-capabilities-no-new-privileges
'''


def check() -> dict:
    """Run only the pinned, source-verified image if it is already local."""
    out, err = io.StringIO(), io.StringIO()
    result = {'checked_at': datetime.now(timezone.utc).isoformat(),
              'image': VERIFIED_IMAGE, 'passed': False, 'checks': {},
              'scope': 'Offline scratch only. Agents outside this launcher are not covered.'}
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = runner.run(VERIFIED_IMAGE, ['/bin/sh', '-c', PROBE], 15)
        names = runner.docker('ps', '-a', '--filter', f'label={runner.LABEL}=1',
                              '--format', '{{.Names}}').stdout.strip()
        lines = set(out.getvalue().splitlines())
        result['checks'] = {name: 'PASS-' + name in lines for name in CHECKS}
        result['checks']['no-leftover-test-containers'] = not names
        result['passed'] = code == 0 and all(result['checks'].values()) and not err.getvalue()
        if names:
            result['detail'] = 'Labeled scratch containers remain. No automatic deletion of other runs.'
        elif not result['passed']:
            result['detail'] = 'A check failed or cleanup reported an error. Do not bypass the restrictions.'
    except Exception as exc:
        # Do not expose arbitrary image/environment output in the UI.
        result['detail'] = f'Check unavailable ({type(exc).__name__}). OrbStack must be running and the pinned image must already be local. Nothing is installed or downloaded.'
    return result


def check_workspace() -> dict:
    """One synthetic import/execute/freeze/export roundtrip, no private input."""
    from offline_workspace import run
    try:
        result = run({'input.txt': b'swarmguard-synthetic-only\n'},
                     ['/bin/sh', '-c', 'cat input.txt > result.txt'], ['result.txt'],
                     image=VERIFIED_IMAGE, seconds=15)
        return {'passed': result['files'] == {'result.txt': b'swarmguard-synthetic-only\n'},
                'detail': 'Synthetic import, command, frozen export and cleanup roundtrip.'}
    except Exception as exc:
        return {'passed': False, 'detail': str(exc) if isinstance(exc, RuntimeError) else
                'Copied roundtrip unavailable (' + type(exc).__name__ + '). No private source was used.'}


if __name__ == '__main__':
    import json
    result = check()
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['passed'] else 1)
