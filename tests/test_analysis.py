"""Mocked provider tests. No keys, HTTP requests, or paid inference."""
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import swarm_brain as brain
import autonomy


def client_returning(data):
    content = json.dumps(data)
    client = Mock()
    client.chat.completions.create.return_value = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content), finish_reason="stop")])
    return client


GUARD = {"threat_score": 90, "verdict": "CRITICAL THREAT", "agent_triggered": "external-name",
         "explanation": "Secret read detected. Review the attempted action.", "visual_findings": "n/a"}
FORENSIC = {"headline": "Secret read", "executive_summary": "A helper requested secrets.",
            "recommended_action": "Deny the request.", "attack_chain": ["Requested .env"],
            "evidence_quotes": ["read .env"], "severity": "high", "confidence": 0.9}


class AnalysisTests(unittest.TestCase):
    def test_valid_guard_keeps_assigned_identity(self):
        with patch.object(brain, "_client", return_value=client_returning(GUARD)):
            out = brain.analyze_with_guard("Bloodhound", "read .env", "test")
        self.assertEqual(out["source"], "meta_model_api")
        self.assertEqual(out["agent_triggered"], "Bloodhound")

    def test_invalid_guard_uses_explicit_fallback(self):
        for bad in ([], {**GUARD, "threat_score": 200}, {**GUARD, "threat_score": True},
                    {**GUARD, "verdict": "all-good"}, {**GUARD, "explanation": ""}):
            with self.subTest(bad=bad), patch.object(brain, "_client", return_value=client_returning(bad)):
                out = brain.analyze_with_guard("Bloodhound", "read .env", "test")
                self.assertEqual(out["source"], "heuristic_fallback")
                self.assertNotIn("structured", out)

    def test_invalid_forensics_not_claimed_structured(self):
        for bad in ([], {**FORENSIC, "confidence": 5}, {**FORENSIC, "evidence_quotes": "not a list"},
                    {**FORENSIC, "attack_chain": [None]}, {**FORENSIC, "severity": "urgent"}):
            with self.subTest(bad=bad), patch.object(brain, "_client", return_value=client_returning(bad)):
                out = brain.synthesize_forensic_report(scenario="test", evidence="read .env", reports=[], pid=0)
                self.assertTrue(out["source"].startswith("fallback"))
                self.assertTrue(out["evidence_quotes"])
                self.assertNotIn("structured", out)

    def test_offline_forensics_has_evidence(self):
        with patch.object(brain, "_client", return_value=None):
            out = brain.synthesize_forensic_report(scenario="test", evidence="read .env", reports=[], pid=0)
        self.assertTrue(out["evidence_quotes"])

    def test_fallback_quotes_are_grounded_in_telemetry(self):
        evidence = "benign action with no quoted material"
        quotes = brain._fallback_evidence_quotes(evidence, [{"visual_findings": "Invented visual explanation"}])
        self.assertTrue(all(q in evidence for q in quotes))

    def test_entire_demo_offline(self):
        with patch.object(brain, "_client", return_value=None), patch.object(autonomy, "append_incident"), patch.object(autonomy, "raise_threat"), patch.object(autonomy, "reset_to_safe"):
            result, incident = autonomy.run_autonomous_scenario("steal_env")
        self.assertEqual(incident["action"], "AUTO_QUARANTINED")
        self.assertTrue(incident["simulation"])
        self.assertTrue(result["forensic"]["evidence_quotes"])
        self.assertEqual(result["top"]["source"], "heuristic_fallback")

    def test_valid_forensic_response(self):
        with patch.object(brain, "_client", return_value=client_returning(FORENSIC)):
            out = brain.synthesize_forensic_report(scenario="test", evidence="read .env", reports=[], pid=0)
        self.assertEqual(out["source"], "meta_model_api")
        self.assertTrue(out["structured"])

    def test_safe_analysis_never_quarantines(self):
        with patch.object(autonomy, "append_incident") as log, patch.object(autonomy, "raise_threat") as threat, patch.object(autonomy, "reset_to_safe") as reset:
            out = autonomy.auto_eliminate({"top": {"verdict": "SAFE", "threat_score": 2}})
        self.assertEqual(out["action"], "NO_THREAT")
        threat.assert_not_called(); reset.assert_not_called(); log.assert_called_once()

    def test_quarantine_labels_simulation(self):
        result = {"top": GUARD, "pid": 123, "title": "Test", "guards": {}}
        with patch.object(autonomy, "append_incident"), patch.object(autonomy, "raise_threat"), patch.object(autonomy, "reset_to_safe"):
            out = autonomy.auto_eliminate(result)
        self.assertTrue(out["simulation"])
        self.assertIn("No real process", out["action_detail"])

    def test_client_has_bounded_no_retry_calls(self):
        with patch.object(brain, "MODEL_API_KEY", "synthetic-test-only"), patch.object(brain, "OpenAI") as api:
            brain._client()
        self.assertEqual(api.call_args.kwargs["timeout"], 30.0)
        self.assertEqual(api.call_args.kwargs["max_retries"], 0)


if __name__ == "__main__":
    unittest.main()
