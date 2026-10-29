"""Synthetic-check result parsing, not live runtime evidence."""
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import isolation_check as check

class CheckTests(unittest.TestCase):
    def test_success_requires_all_markers_and_cleanup(self):
        def fake(*args):
            print('\n'.join('PASS-'+name for name in check.CHECKS));return 0
        with patch.object(check.runner,'run',side_effect=fake), patch.object(check.runner,'docker',return_value=SimpleNamespace(stdout='')):
            self.assertTrue(check.check()['passed'])
    def test_missing_marker_fails(self):
        with patch.object(check.runner,'run',return_value=0), patch.object(check.runner,'docker',return_value=SimpleNamespace(stdout='')):
            self.assertFalse(check.check()['passed'])
    def test_leftover_fails(self):
        def fake(*args):
            print('\n'.join('PASS-'+name for name in check.CHECKS));return 0
        with patch.object(check.runner,'run',side_effect=fake), patch.object(check.runner,'docker',return_value=SimpleNamespace(stdout='swarmguard-test')):
            self.assertFalse(check.check()['passed'])
    def test_unavailable_does_not_install(self):
        with patch.object(check.runner,'run',side_effect=FileNotFoundError):
            self.assertFalse(check.check()['passed'])
