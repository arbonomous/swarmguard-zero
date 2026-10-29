import tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import native_workspace as native

class NativePrepTests(unittest.TestCase):
    def test_explicit_source_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'input.txt';path.write_text('synthetic')
            files,command,exports=native.prepare([str(path)],'/bin/sh -c true','result.txt')
            self.assertEqual(files,{'input.txt':b'synthetic'})
            self.assertEqual(command,['/bin/sh','-c','true'])
            self.assertEqual(exports,['result.txt'])
    def test_no_selection_fails(self):
        with self.assertRaises(ValueError):native.prepare([],'/bin/sh','result.txt')
    def test_native_route_does_not_open_browser(self):
        import menubar
        with patch.object(native,'open_workspace') as opened,patch.object(menubar.webbrowser,'open') as browser:
            menubar.open_offline_workspace();opened.assert_called_once();browser.assert_not_called()

class OverviewTests(unittest.TestCase):
    def test_native_sections_available_without_browser(self):
        import native_overview as overview
        for section in ['Status','Attack catalog','Policy checks','Activity and evidence','Latest analysis','About']:
            with self.subTest(section=section):self.assertTrue(overview.section_text(section))

class MenuLanguageTests(unittest.TestCase):
    def test_no_jargon_or_alarm_from_history(self):
        import menubar
        self.assertNotIn('SWARMGUARD',menubar._protecting_line(True))
        self.assertNotIn('MCP',menubar._gate_label({}))
        self.assertIn('may include tests',menubar._activity_summary([{'rule':'deny_real_env'}]))
        self.assertNotIn('deny_',menubar._deny_label({'rule':'deny_real_env'}))
