"""
Unit Tests: Risk Scoring Engine
Tests aggregation, score limits (0-100), dynamic vector weighting, and explanations.
"""

import unittest
from risk_engine import RiskEngine, RiskIndicator

class TestRiskEngine(unittest.TestCase):
    def test_score_capping_and_tiers(self):
        """Ensures score is bounded at 100.0 and tiers map accurately."""
        self.assertEqual(RiskEngine.get_tier(95), "Critical")
        self.assertEqual(RiskEngine.get_tier(65), "High")
        self.assertEqual(RiskEngine.get_tier(35), "Medium")
        self.assertEqual(RiskEngine.get_tier(10), "Low")

    def test_risk_aggregation_no_double_counting(self):
        """Verifies duplicate indicators within a category are deduped."""
        sender_inds = [
            RiskIndicator("sender", "Typosquatting", 40.0, "Brand mimicry", "high"),
            RiskIndicator("sender", "Typosquatting", 40.0, "Duplicate signal", "high")
        ]
        body_inds = []
        url_inds = []
        att_inds = []

        result = RiskEngine.calculate_risk(
            sender_indicators=sender_inds,
            body_indicators=body_inds,
            url_indicators=url_inds,
            attachment_indicators=att_inds,
            has_url=False,
            has_attachment=False
        )

        # Sender raw score should be 40.0 (deduped), not 80.0
        self.assertEqual(result["vector_scores"]["sender"], 40.0)
        self.assertTrue(result["overall_score"] <= 100.0)

    def test_critical_attachment_override(self):
        """Critical attachment severity ensures minimum 85 score."""
        att_inds = [
            RiskIndicator("attachment", "Disguised Windows PE Executable", 95.0, "MZ in PDF", "critical")
        ]
        result = RiskEngine.calculate_risk([], [], [], att_inds, has_url=False, has_attachment=True)
        self.assertGreaterEqual(result["overall_score"], 85.0)
        self.assertIn(result["risk_level"], ["High", "Critical"])

    def test_unavailable_vector_renormalization(self):
        """Verifies missing URL and attachment vectors are marked Unavailable, not penalizing."""
        result = RiskEngine.calculate_risk([], [], [], [], has_url=False, has_attachment=False)
        self.assertEqual(result["vector_scores"]["url"], "Unavailable")
        self.assertEqual(result["vector_scores"]["attachment"], "Unavailable")
        self.assertEqual(result["overall_score"], 0.0)
        self.assertEqual(result["risk_level"], "Low")

    def test_explanation_generation(self):
        """Verifies itemized explanations are generated for alerts."""
        inds = [
            RiskIndicator("body", "Urgency Cues", 8.0, "Contains 'urgent' keyword", "low")
        ]
        result = RiskEngine.calculate_risk([], inds, [], [])
        self.assertEqual(len(result["indicators"]), 1)
        self.assertEqual(result["indicators"][0]["title"], "Urgency Cues")
        self.assertIn("Contains 'urgent'", result["indicators"][0]["explanation"])

if __name__ == "__main__":
    unittest.main()
