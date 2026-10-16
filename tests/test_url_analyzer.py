"""
Unit Tests: URL Analyzer
Tests URL extraction, benign long URLs, raw IP hosts, shorteners, and obfuscation.
"""

import unittest
from url_analyzer import URLAnalyzer

class TestURLAnalyzer(unittest.TestCase):
    def test_benign_long_url_tolerated(self):
        """A long URL alone must not increase the risk significantly."""
        long_url = "https://s3.amazonaws.com/company-bucket/reports/2026/financial_summary.pdf?" + "param=" + "a" * 380
        meta, inds = URLAnalyzer.analyze_single_url(long_url)
        # Score must be very low (< 10)
        self.assertLess(meta["risk_score"], 10.0)

    def test_raw_ip_address_hostname(self):
        """Raw IP address hostname triggers high-risk indicator."""
        url = "http://192.168.1.105/secure/login.php"
        meta, inds = URLAnalyzer.analyze_single_url(url)
        self.assertTrue(meta["is_ip"])
        titles = [i.title for i in inds]
        self.assertIn("Raw IP-Address Hostname", titles)
        self.assertGreaterEqual(meta["risk_score"], 40.0)

    def test_url_shortener_detection(self):
        """Known URL shorteners trigger concealment warning."""
        url = "https://bit.ly/urgent-account-reset"
        meta, inds = URLAnalyzer.analyze_single_url(url)
        self.assertTrue(meta["is_shortener"])
        titles = [i.title for i in inds]
        self.assertIn("URL Shortener Concealment", titles)

    def test_userinfo_obfuscation(self):
        """URL with @ credential symbol triggers deceptive host alert."""
        url = "https://google.com@phishing-landing-zone.com/auth"
        meta, inds = URLAnalyzer.analyze_single_url(url)
        titles = [i.title for i in inds]
        self.assertTrue(any("Userinfo (@) Host Obfuscation" in t for t in titles))

    def test_punycode_detection(self):
        """Punycode homograph domain triggers alert."""
        url = "https://xn--pypal-4ve.com/signin"
        meta, inds = URLAnalyzer.analyze_single_url(url)
        titles = [i.title for i in inds]
        self.assertTrue(any("Punycode Homograph Domain" in t for t in titles))

if __name__ == "__main__":
    unittest.main()
