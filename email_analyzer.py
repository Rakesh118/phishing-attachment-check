"""
Email Analyzer
Parses raw RFC822 messages or pasted email text and analyzes Sender, Body, URLs, and Attachments.
Adheres to strict safety guidelines: urgency words alone are a weak signal, and passwords are never exposed.
"""

import re
import email
from email import policy
from email.parser import BytesParser, Parser
from typing import Dict, List, Any, Tuple, Optional
from risk_engine import RiskIndicator, RiskEngine
from url_analyzer import URLAnalyzer
from attachment_analyzer import AttachmentAnalyzer

# Typosquatting / Lookalike brand rules
LOOKALIKE_PATTERNS = [
    (r"paypa[l1i]\b", "PayPal Lookalike (paypa1/paypai)"),
    (r"micros[o0]ft\b", "Microsoft Lookalike (micros0ft)"),
    (r"arnazon|amaz[o0]n\b", "Amazon Lookalike (arnazon/amaz0n)"),
    (r"g[o0]{2}gle\b", "Google Lookalike (g00gle)"),
    (r"app[l1i]e\b", "Apple Lookalike (app1e)"),
    (r"netf[l1i]x\b", "Netflix Lookalike (netf1ix)")
]

FREE_MAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "protonmail.com", "zoho.com", "mail.com", "yandex.com"
}

SUSPICIOUS_SENDER_TLDS = {
    "xyz", "top", "click", "buzz", "club", "work", "cam", "gq", "ml", "cf", "tk", "country", "stream"
}

BRAND_KEYWORDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix", "bank", "wells fargo", "chase", "security", "support", "billing"
]

URGENCY_KEYWORDS = [
    r"\burgen(t|cy)\b",
    r"\bimmediately\b",
    r"\baction required\b",
    r"\baccount suspended\b",
    r"\bwithin 24 hours\b",
    r"\bterminate[d]?\b",
    r"\bexpire[sd]?\b",
    r"\bdeadline\b",
    r"\bprompt attention\b"
]

CREDENTIAL_HARVEST_PHRASES = [
    r"confirm your (password|credentials|account)",
    r"verify your (identity|account|credentials|card)",
    r"update your (billing|payment|security|information)",
    r"unauthorized (access|transaction|login|activity)",
    r"suspended your (account|service|access)",
    r"wire transfer",
    r"cryptocurrency|bitcoin|gift card"
]

PASSWORD_IN_BODY_PATTERNS = [
    r"\bpass(?:word|code)\s*(?:is|:|=)\s*([^\s\r\n]+)",
    r"\b(?:zip|archive|file|attachment)\s+pass(?:word|code)\b",
    r"\bpass(?:word|code)\s+for\s+(?:the\s+)?(?:zip|archive|file)\b"
]


class EmailAnalyzer:
    @staticmethod
    def parse_email(raw_input: Any) -> Dict[str, Any]:
        """
        Parses raw text or bytes into a structured email object.
        Supports .eml raw bytes, RFC822 strings, or simple text.
        """
        sender = ""
        reply_to = ""
        subject = ""
        body = ""
        date_str = ""
        attachments: List[Dict[str, Any]] = []

        if isinstance(raw_input, bytes):
            try:
                msg = BytesParser(policy=policy.default).parsebytes(raw_input)
            except Exception:
                msg = email.message_from_bytes(raw_input)
        elif isinstance(raw_input, str):
            # If string contains typical RFC headers or just body
            try:
                msg = Parser(policy=policy.default).parsestr(raw_input)
            except Exception:
                msg = email.message_from_string(raw_input)
        else:
            msg = None

        if msg and (msg.get("From") or msg.get("Subject") or msg.is_multipart()):
            sender = str(msg.get("From", "") or "")
            reply_to = str(msg.get("Reply-To", "") or "")
            subject = str(msg.get("Subject", "") or "")
            date_str = str(msg.get("Date", "") or "")

            # Extract body and attachments
            if msg.is_multipart():
                for part in msg.walk():
                    content_disposition = str(part.get("Content-Disposition", ""))
                    content_type = part.get_content_type()
                    filename = part.get_filename()

                    if filename or "attachment" in content_disposition.lower():
                        fname = filename or "unnamed_attachment"
                        payload = part.get_payload(decode=True) or b""
                        attachments.append({
                            "filename": fname,
                            "content": payload,
                            "content_type": content_type
                        })
                    elif content_type in ["text/plain", "text/html"]:
                        try:
                            payload = part.get_payload(decode=True)
                            if payload:
                                charset = part.get_content_charset() or "utf-8"
                                text = payload.decode(charset, errors="replace")
                                if content_type == "text/plain":
                                    body += "\n" + text
                                else:
                                    # Strip basic HTML tags for text representation
                                    clean_text = re.sub(r"<[^>]+>", " ", text)
                                    body += "\n" + clean_text
                        except Exception:
                            pass
            else:
                try:
                    payload = msg.get_payload(decode=True)
                    if payload:
                        charset = msg.get_content_charset() or "utf-8"
                        body = payload.decode(charset, errors="replace")
                    else:
                        body = str(msg.get_payload() or "")
                except Exception:
                    body = str(msg.get_payload() or "")
        else:
            # Fallback for plain pasted text without full RFC headers
            text = str(raw_input)
            # Try to extract headers via simple regex if present
            from_match = re.search(r"^From:\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)
            subject_match = re.search(r"^Subject:\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)
            sender = from_match.group(1).strip() if from_match else ""
            subject = subject_match.group(1).strip() if subject_match else ""
            body = text

        return {
            "sender": sender.strip(),
            "reply_to": reply_to.strip(),
            "subject": subject.strip(),
            "date": date_str.strip(),
            "body": body.strip(),
            "attachments": attachments
        }

    @staticmethod
    def analyze_sender(sender_str: str, reply_to_str: str = "") -> Tuple[Dict[str, Any], List[RiskIndicator]]:
        indicators: List[RiskIndicator] = []
        if not sender_str:
            return {"sender": "Unavailable", "domain": "", "is_spoofed": False}, indicators

        # Extract email address and display name
        email_match = re.search(r"<([^>]+)>", sender_str)
        if email_match:
            addr = email_match.group(1).strip().lower()
            display_name = sender_str.split("<")[0].strip().strip('"').strip("'")
        elif "@" in sender_str:
            addr = sender_str.strip().lower()
            display_name = ""
        else:
            addr = ""
            display_name = sender_str.strip()

        domain = addr.split("@")[-1] if "@" in addr else ""
        tld = domain.split(".")[-1] if "." in domain else ""

        # 1. Typosquatting / Lookalike domain check
        for pattern, desc in LOOKALIKE_PATTERNS:
            if re.search(pattern, domain, re.IGNORECASE):
                indicators.append(RiskIndicator(
                    "sender", desc, 40.0,
                    f"Sender domain '{domain}' mimics legitimate brand via visual character substitution.", "high"
                ))
                break

        # 2. Free email provider impersonating corporate brand
        if domain in FREE_MAIL_PROVIDERS:
            # Check if display name mentions corporate brand
            matched_brands = [b for b in BRAND_KEYWORDS if b in display_name.lower()]
            if matched_brands:
                indicators.append(RiskIndicator(
                    "sender", f"Brand Impersonation via Freemail ({matched_brands[0].title()})", 35.0,
                    f"Sender displays corporate brand '{display_name}' but originates from free mail provider '{domain}'.", "high"
                ))

        # 3. High-risk TLD
        if tld in SUSPICIOUS_SENDER_TLDS:
            indicators.append(RiskIndicator(
                "sender", f"Suspicious Sender TLD (.{tld})", 25.0,
                f"Sender domain uses top-level domain '.{tld}' known for high malicious abuse rates.", "medium"
            ))

        # 4. Display Name vs Address mismatch / Spoofing
        if display_name and "@" in display_name:
            indicators.append(RiskIndicator(
                "sender", "Email In Display Name Obfuscation", 30.0,
                f"Display name '{display_name}' embeds a misleading email address to deceive mobile email clients.", "high"
            ))

        # 5. Inconsistent Reply-To header
        if reply_to_str and "@" in reply_to_str and domain:
            reply_domain = reply_to_str.split("@")[-1].strip(">").lower()
            if reply_domain and reply_domain != domain:
                indicators.append(RiskIndicator(
                    "sender", "Inconsistent Reply-To Header", 20.0,
                    f"Responses are redirected to '{reply_domain}', differing from sender domain '{domain}'.", "medium"
                ))

        # 6. Numeric padding / random hex in username
        username = addr.split("@")[0] if "@" in addr else ""
        if len(re.findall(r"\d", username)) > 5 and len(username) > 8:
            indicators.append(RiskIndicator(
                "sender", "Randomized / Digit-Padded Sender Username", 15.0,
                f"Username '{username}' exhibits high entropy and numeric clustering typical of automated bot generation.", "low"
            ))

        metadata = {
            "sender": sender_str,
            "address": addr,
            "display_name": display_name,
            "domain": domain,
            "risk_score": min(100.0, sum(i.points for i in indicators))
        }
        return metadata, indicators

    @staticmethod
    def analyze_body(body_text: str, subject_text: str = "") -> Tuple[Dict[str, Any], List[RiskIndicator], bool]:
        """
        Analyzes linguistics and detects passwords mentioned in email body.
        Crucial: Urgency words alone are a weak signal (+8 pts) and do not classify as phishing alone!
        """
        indicators: List[RiskIndicator] = []
        full_text = f"{subject_text}\n{body_text}".strip()
        has_password_in_body = False

        if not full_text:
            return {"urgency_count": 0, "credential_cues": 0, "password_mentioned": False}, indicators, False

        # 1. Urgency analysis (Weak signal - max 8 points)
        urgency_hits = []
        for pat in URGENCY_KEYWORDS:
            if re.search(pat, full_text, re.IGNORECASE):
                urgency_hits.append(re.findall(pat, full_text, re.IGNORECASE)[0])

        if urgency_hits:
            # Low weight so benign emails with urgency words are not penalized unfairly
            indicators.append(RiskIndicator(
                "body", "Urgency / Pressure Language (Weak Signal)", 8.0,
                f"Email uses urgency language ({', '.join(str(h) for h in urgency_hits[:2])}). Note: Urgency words alone are common in legitimate work communications and carry low weight.", "low"
            ))

        # 2. Credential harvesting / Coercive phrases
        harvest_hits = []
        for pat in CREDENTIAL_HARVEST_PHRASES:
            if re.search(pat, full_text, re.IGNORECASE):
                harvest_hits.append(pat.split("(")[0].strip())

        if harvest_hits:
            indicators.append(RiskIndicator(
                "body", "Credential / Financial Solicitation Language", 25.0,
                f"Linguistic cues prompt for credentials, account verification, or financial transfer: {', '.join(harvest_hits[:2])}.", "medium"
            ))

        # 3. Password mentioned in email body (Safe detection without saving/exposing)
        for pat in PASSWORD_IN_BODY_PATTERNS:
            match = re.search(pat, body_text, re.IGNORECASE)
            if match:
                has_password_in_body = True
                indicators.append(RiskIndicator(
                    "body", "Archive Password Stated in Body", 15.0,
                    "Body communicates an archive access password or passcode. Frequently used in coordinated evasion attacks to deliver password-protected payloads.", "medium"
                ))
                break

        # 4. Generic salutations
        if re.search(r"^(Dear (Customer|User|Client|Member|Beneficiary)|Attention Account Holder)", body_text, re.IGNORECASE | re.MULTILINE):
            indicators.append(RiskIndicator(
                "body", "Impersonal Generic Salutation", 10.0,
                "Email employs generic greeting ('Dear Customer') rather than personalized user identification.", "low"
            ))

        metadata = {
            "urgency_matches": len(urgency_hits),
            "harvesting_matches": len(harvest_hits),
            "password_mentioned": has_password_in_body,
            "risk_score": min(100.0, sum(i.points for i in indicators))
        }
        return metadata, indicators, has_password_in_body

    @classmethod
    def scan_full_message(
        cls,
        raw_email: Any,
        extra_attachments: Optional[List[Tuple[str, bytes]]] = None
    ) -> Dict[str, Any]:
        """
        End-to-end scanner orchestrating Sender, Body, URL, and Attachment vectors.
        """
        parsed = cls.parse_email(raw_email)

        # 1. Sender vector
        sender_meta, sender_inds = cls.analyze_sender(parsed["sender"], parsed["reply_to"])

        # 2. Body vector
        body_meta, body_inds, has_pw = cls.analyze_body(parsed["body"], parsed["subject"])

        # 3. URL vector
        urls = URLAnalyzer.extract_urls(f"{parsed['body']}\n{parsed.get('subject', '')}")
        url_metas, url_inds = URLAnalyzer.analyze_urls(urls)
        has_url = len(urls) > 0

        # 4. Attachment vector
        all_att_list = []
        # Attachments extracted from .eml
        for att in parsed.get("attachments", []):
            all_att_list.append((att["filename"], att["content"]))
        # Additional attachments uploaded via UI
        if extra_attachments:
            for fname, fbytes in extra_attachments:
                all_att_list.append((fname, fbytes))

        has_attachments = len(all_att_list) > 0
        att_reports = []
        att_inds: List[RiskIndicator] = []

        for fname, fcontent in all_att_list:
            report = AttachmentAnalyzer.inspect_attachment(fname, fcontent, context_has_pw=has_pw)
            att_reports.append(report)
            for ev in report.get("evidence", []):
                att_inds.append(RiskIndicator(
                    ev["category"], ev["title"], ev["points"], ev["explanation"], ev["severity"]
                ))

        # 5. Combined Risk Scoring
        risk_result = RiskEngine.calculate_risk(
            sender_indicators=sender_inds,
            body_indicators=body_inds,
            url_indicators=url_inds,
            attachment_indicators=att_inds,
            has_url=has_url,
            has_attachment=has_attachments
        )

        return {
            "parsed_email": {
                "sender": parsed["sender"],
                "subject": parsed["subject"],
                "date": parsed["date"],
                "body_snippet": parsed["body"][:300] + ("..." if len(parsed["body"]) > 300 else ""),
                "url_count": len(urls),
                "attachment_count": len(all_att_list)
            },
            "sender_analysis": sender_meta,
            "body_analysis": body_meta,
            "url_analysis": {
                "count": len(urls),
                "urls": url_metas
            },
            "attachment_reports": att_reports,
            "risk_assessment": risk_result
        }
