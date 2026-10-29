import json,unittest
from unittest.mock import patch
from types import SimpleNamespace
import offline_workspace as workspace
from test_isolation import configuration,IMAGE

class WorkspaceTests(unittest.TestCase):
    def test_no_mount_and_scoped_cleanup(self):
        calls=[]
        def docker(*args,**kwargs):
            calls.append(args)
            if args[0]=='inspect':
                data=configuration();data['Name']='/'+args[1]
                return SimpleNamespace(stdout=json.dumps([data]))
            if args[0]=='cp' and kwargs.get('raw'):
                from workspace_files import make_archive
                return SimpleNamespace(stdout=make_archive({'main.py':b'print(2)\n'}))
            return SimpleNamespace(stdout='',stderr='')
        with patch.object(workspace.runner,'local_image',return_value=IMAGE),patch.object(workspace.runner,'docker',side_effect=docker):
            result=workspace.run({'main.py':b'print(1)'},['/bin/sh','-c','true'],['main.py'],image='local')
        self.assertEqual(result['files']['main.py'],b'print(2)\n')
        self.assertEqual(calls[-1][:2],('rm','--force'))
        self.assertFalse(any('--volume' in c for c in calls))
        self.assertTrue(any(c[:3]==('cp','-a','-') for c in calls))
        self.assertLess(next(i for i,c in enumerate(calls) if c[0]=='pause'),
                        next(i for i,c in enumerate(calls) if c[0]=='cp' and c[-1]=='-'))
    def test_reject_before_runtime(self):
        with patch.object(workspace.runner,'docker') as docker:
            with self.assertRaises(ValueError):workspace.run({'.env':b'a'},['/bin/sh'],['x.py'],image='local')
            docker.assert_not_called()
