"""
Unit Tests: Feedback System
Tests logging, privacy sanitization, and summary telemetry stats.
"""

import unittest
from feedback import FeedbackSystem

class TestFeedbackSystem(unittest.TestCase):
    def test_record_feedback_success(self):
        """Verifies recording feedback succeeds and returns valid stats."""
        success = FeedbackSystem.record_feedback(
            sample_id="test_sample_01",
            predicted_score=85.0,
            predicted_level="Critical",
            user_feedback="Correct",
            comment="Disguised MZ header verified"
        )
        self.assertTrue(success)

        stats = FeedbackSystem.get_summary_stats()
        self.assertGreaterEqual(stats["total_feedback_count"], 1)
        self.assertGreaterEqual(stats["counts"]["Correct"], 1)

    def test_invalid_option_sanitization(self):
        """Invalid feedback strings default safely to 'Unsure'."""
        success = FeedbackSystem.record_feedback(
            sample_id="test_sample_invalid",
            predicted_score=10.0,
            predicted_level="Low",
            user_feedback="HACK_INJECTION_PARAM",
            comment="Test comment"
        )
        self.assertTrue(success)
        records = FeedbackSystem.get_feedback_records()
        last_record = records[-1]
        self.assertEqual(last_record["user_feedback"], "Unsure")

if __name__ == "__main__":
    unittest.main()
