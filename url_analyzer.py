"""
Static URL Risk Analyzer
Performs heuristic, zero-execution structural inspection of URLs.
Never visits or fetches remote network resources.
"""

import re
import ipaddress
from urllib.parse import urlparse, unquote
from typing import List, Dict, Any, Tuple
from risk_engine import RiskIndicator

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "buzz", "club", "work", "cam", "gq", "ml", "cf", "tk", "ga", "country", "stream"
}

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy", "rebrand.ly", "goo.gl"
}

TARGETED_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix", "wellsfargo", "chase", "bankofamerica", "dhl", "fedex"
]

CREDENTIAL_KEYWORDS = [
    "login", "signin", "verify", "verification", "account", "update", "secure", "banking", "wallet", "recover", "authenticate"
]

class URLAnalyzer:
    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """Extracts unique URLs from text or HTML."""
        if not text:
            return []
        # Pattern to capture http/https URLs and raw IP URLs
        url_pattern = r'https?://[^\s<>"\')]+'
        matches = re.findall(url_pattern, text, re.IGNORECASE)
        # Deduplicate preserving order
        seen = set()
        deduped = []
        for u in matches:
            clean = u.rstrip(".,;!?:")
            if clean and clean not in seen:
                seen.add(clean)
                deduped.append(clean)
        return deduped

    @staticmethod
    def is_ip_address(host: str) -> bool:
        """Checks if host is a raw IPv4 or IPv6 address."""
        if not host:
            return False
        # Remove brackets if ipv6
        cleaned = host.strip("[]")
        try:
            ipaddress.ip_address(cleaned)
            return True
        except ValueError:
            return False

    @staticmethod
    def analyze_single_url(url: str) -> Tuple[Dict[str, Any], List[RiskIndicator]]:
        """
        Analyzes a single URL statically.
        Returns parsed metadata and list of RiskIndicators.
        """
        indicators: List[RiskIndicator] = []
        try:
            parsed = urlparse(url)
        except Exception as e:
            return {
                "url": url,
                "error": f"Malformed URL: {str(e)}",
                "risk_score": 30.0,
                "is_ip": False,
                "is_shortener": False,
                "uses_https": False
            }, [RiskIndicator("url", "Malformed URL Structure", 30.0, "URL failed RFC structural parsing.", "medium")]

        scheme = (parsed.scheme or "").lower()
        netloc = parsed.netloc or ""
        hostname = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""

        uses_https = scheme == "https"
        if scheme == "http":
            indicators.append(RiskIndicator(
                "url", "Insecure HTTP Scheme", 12.0,
                f"URL uses unencrypted 'http://' protocol instead of HTTPS ({url[:50]}...).", "low"
            ))

        # Check for userinfo @ spoofing e.g. https://google.com@phishing.site
        has_userinfo = "@" in netloc
        if has_userinfo:
            indicators.append(RiskIndicator(
                "url", "Deceptive Userinfo (@) Host Obfuscation", 35.0,
                "URL contains '@' credential symbol used to mislead users regarding destination host.", "high"
            ))

        # IP Address check
        is_ip = URLAnalyzer.is_ip_address(hostname)
        if is_ip:
            indicators.append(RiskIndicator(
                "url", "Raw IP-Address Hostname", 40.0,
                f"Destination is a raw IP address ({hostname}) rather than a legitimate registered domain.", "high"
            ))

        # Shortener check
        is_shortener = hostname in KNOWN_SHORTENERS
        if is_shortener:
            indicators.append(RiskIndicator(
                "url", "URL Shortener Concealment", 20.0,
                f"URL uses known shortening service ({hostname}), masking the true final destination.", "medium"
            ))

        # Punycode / Internationalized Domain Name spoofing (homograph)
        is_punycode = "xn--" in hostname
        if is_punycode:
            indicators.append(RiskIndicator(
                "url", "Punycode Homograph Domain", 30.0,
                f"Domain contains punycode prefix 'xn--', commonly leveraged in lookalike spoofing attacks.", "high"
            ))

        # TLD check
        tld = hostname.split(".")[-1] if "." in hostname else ""
        if tld in SUSPICIOUS_TLDS:
            indicators.append(RiskIndicator(
                "url", f"High-Risk TLD (.{tld})", 22.0,
                f"Domain uses top-level domain '.{tld}' known for elevated malicious registrar abuse.", "medium"
            ))

        # Subdomain chaining & Brand impersonation in subdomains
        # Example: paypal.com.account-verify.xyz
        parts = hostname.split(".")
        if len(parts) > 3 and not is_ip:
            indicators.append(RiskIndicator(
                "url", "Excessive Subdomain Chaining", 15.0,
                f"Domain contains {len(parts)} levels ({hostname}), often used to mimic authentic service endpoints.", "medium"
            ))

        for brand in TARGETED_BRANDS:
            # Check if brand appears in subdomain or path while main domain is different
            registered_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
            if brand in hostname and brand not in registered_domain:
                indicators.append(RiskIndicator(
                    "url", f"Deceptive Brand Spoofing ({brand.title()})", 35.0,
                    f"Brand name '{brand}' appears in subdomain hierarchy of third-party domain '{registered_domain}'.", "high"
                ))
                break

        # Suspicious path keywords
        path_lower = (unquote(path) + " " + unquote(query)).lower()
        matched_kw = [kw for kw in CREDENTIAL_KEYWORDS if kw in path_lower]
        if matched_kw and not is_shortener:
            indicators.append(RiskIndicator(
                "url", f"Harvesting Keyword in Path ({matched_kw[0]})", 12.0,
                f"URL path or query includes security/credential-sensitive keywords: {', '.join(matched_kw[:3])}.", "low"
            ))

        # Long URL policy: "A long URL alone must not increase the risk significantly."
        # If URL is long but has NO other indicators, 0 penalty. If extremely long (>300 chars) with query, minimal +2 heuristic note.
        if len(url) > 350:
            indicators.append(RiskIndicator(
                "url", "Long URL Structure (Informational)", 2.0,
                f"URL is lengthy ({len(url)} chars). Long URLs with benign query parameters are common and carry minimal standalone penalty.", "low"
            ))

        url_score = min(100.0, sum(i.points for i in indicators))

        metadata = {
            "url": url,
            "scheme": scheme,
            "hostname": hostname,
            "is_ip": is_ip,
            "is_shortener": is_shortener,
            "uses_https": uses_https,
            "tld": tld,
            "length": len(url),
            "risk_score": url_score,
            "indicator_count": len(indicators)
        }
        return metadata, indicators

    @classmethod
    def analyze_urls(cls, urls: List[str]) -> Tuple[List[Dict[str, Any]], List[RiskIndicator]]:
        all_metadata = []
        all_indicators: List[RiskIndicator] = []
        for u in urls:
            meta, inds = cls.analyze_single_url(u)
            all_metadata.append(meta)
            all_indicators.extend(inds)
        return all_metadata, all_indicators
