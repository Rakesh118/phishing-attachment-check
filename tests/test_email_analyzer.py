"""
Unit Tests: Email Analyzer
Tests sender analysis, body linguistics, password-in-email detection, and benign urgency handling.
"""

import unittest
from email_analyzer import EmailAnalyzer

class TestEmailAnalyzer(unittest.TestCase):
    def test_benign_urgency_words_low_risk(self):
        """Urgency words alone must NOT classify an email as malicious."""
        email_text = (
            "From: project-lead@internal-corp.com\n"
            "Subject: Urgent project deadline today\n\n"
            "Hi team, please submit the status report immediately before 5pm. Thanks!"
        )
        result = EmailAnalyzer.scan_full_message(email_text)
        score = result["risk_assessment"]["overall_score"]
        tier = result["risk_assessment"]["risk_level"]

        # Score must be low (less than 25)
        self.assertLess(score, 25.0)
        self.assertEqual(tier, "Low")

    def test_typosquatting_lookalike_sender(self):
        """Lookalike domain (e.g. paypa1.com) triggers sender alert."""
        meta, inds = EmailAnalyzer.analyze_sender("Support <service@paypa1-security.com>")
        titles = [i.title for i in inds]
        self.assertTrue(any("PayPal Lookalike" in t for t in titles))
        self.assertGreaterEqual(meta["risk_score"], 35.0)

    def test_password_mentioned_in_body_detection(self):
        """Detects presence of password in body without exposing/storing."""
        body = "Please open the attached archive. The zip password is: SuperSecret2026!"
        meta, inds, has_pw = EmailAnalyzer.analyze_body(body)
        self.assertTrue(has_pw)
        titles = [i.title for i in inds]
        self.assertIn("Archive Password Stated in Body", titles)

    def test_brand_freemail_spoofing(self):
        """Corporate brand name combined with free mail provider triggers alert."""
        meta, inds = EmailAnalyzer.analyze_sender("Microsoft Security Center <microsft-alerts@gmail.com>")
        titles = [i.title for i in inds]
        self.assertTrue(any("Brand Impersonation via Freemail" in t for t in titles))

if __name__ == "__main__":
    unittest.main()
