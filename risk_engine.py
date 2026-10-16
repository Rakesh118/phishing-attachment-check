"""
Risk-Scoring Engine
Combines independent indicators from Sender, Body, URL, and Attachment vectors.
Uses transparent, evidence-based weighted scoring with deduplication and score capping.
"""

from typing import Dict, List, Any, Optional

class RiskIndicator:
    def __init__(self, category: str, title: str, points: float, explanation: str, severity: str = "medium"):
        self.category = category  # 'sender', 'body', 'url', 'attachment'
        self.title = title
        self.points = points
        self.explanation = explanation
        self.severity = severity  # 'low', 'medium', 'high', 'critical'

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "title": self.title,
            "points": self.points,
            "explanation": self.explanation,
            "severity": self.severity
        }


class RiskEngine:
    # Baseline weights when all 4 vectors are present
    DEFAULT_WEIGHTS = {
        "sender": 0.25,
        "body": 0.20,
        "url": 0.25,
        "attachment": 0.30
    }

    # Thresholds for overall risk tiers
    TIERS = [
        (80, "Critical"),
        (55, "High"),
        (25, "Medium"),
        (0, "Low")
    ]

    @staticmethod
    def get_tier(score: float) -> str:
        for threshold, label in RiskEngine.TIERS:
            if score >= threshold:
                return label
        return "Low"

    @staticmethod
    def calculate_risk(
        sender_indicators: List[RiskIndicator],
        body_indicators: List[RiskIndicator],
        url_indicators: List[RiskIndicator],
        attachment_indicators: List[RiskIndicator],
        has_url: bool = True,
        has_attachment: bool = True
    ) -> Dict[str, Any]:
        """
        Calculates normalized, capped risk score (0-100) and produces itemized breakdown.
        Renormalizes weights dynamically when URL or attachment vectors are unavailable.
        """
        # Deduplicate indicators within each category by title
        def deduplicate(indicators: List[RiskIndicator]) -> List[RiskIndicator]:
            seen = set()
            unique = []
            for ind in indicators:
                key = (ind.category, ind.title)
                if key not in seen:
                    seen.add(key)
                    unique.append(ind)
            return unique

        sender_dedup = deduplicate(sender_indicators)
        body_dedup = deduplicate(body_indicators)
        url_dedup = deduplicate(url_indicators)
        att_dedup = deduplicate(attachment_indicators)

        # Raw vector scores capped at 100
        sender_raw = min(100.0, sum(i.points for i in sender_dedup))
        body_raw = min(100.0, sum(i.points for i in body_dedup))
        url_raw = min(100.0, sum(i.points for i in url_dedup)) if has_url else 0.0
        att_raw = min(100.0, sum(i.points for i in att_dedup)) if has_attachment else 0.0

        # Dynamic weight adjustment for unavailable vectors
        active_weights = {
            "sender": RiskEngine.DEFAULT_WEIGHTS["sender"],
            "body": RiskEngine.DEFAULT_WEIGHTS["body"],
            "url": RiskEngine.DEFAULT_WEIGHTS["url"] if has_url else 0.0,
            "attachment": RiskEngine.DEFAULT_WEIGHTS["attachment"] if has_attachment else 0.0
        }
        total_active_weight = sum(active_weights.values())
        if total_active_weight > 0:
            norm_weights = {k: v / total_active_weight for k, v in active_weights.items()}
        else:
            norm_weights = active_weights

        # Weighted calculation
        sender_contrib = sender_raw * norm_weights["sender"]
        body_contrib = body_raw * norm_weights["body"]
        url_contrib = url_raw * norm_weights["url"]
        att_contrib = att_raw * norm_weights["attachment"]

        aggregated_score = sender_contrib + body_contrib + url_contrib + att_contrib

        # Critical override logic:
        # If an attachment has a disguised executable or critical weaponized signature,
        # the overall risk must not be diluted by clean body/sender.
        critical_attachment = any(i.severity == "critical" and i.category == "attachment" for i in att_dedup)
        if critical_attachment:
            aggregated_score = max(aggregated_score, 85.0)

        # Final cap at 100
        final_score = min(100.0, max(0.0, round(aggregated_score, 1)))
        tier = RiskEngine.get_tier(final_score)

        all_indicators = sender_dedup + body_dedup + url_dedup + att_dedup

        return {
            "overall_score": final_score,
            "risk_level": tier,
            "vector_scores": {
                "sender": round(sender_raw, 1),
                "body": round(body_raw, 1),
                "url": round(url_raw, 1) if has_url else "Unavailable",
                "attachment": round(att_raw, 1) if has_attachment else "Unavailable"
            },
            "vector_contributions": {
                "sender": round(sender_contrib, 1),
                "body": round(body_contrib, 1),
                "url": round(url_contrib, 1) if has_url else 0.0,
                "attachment": round(att_contrib, 1) if has_attachment else 0.0
            },
            "weights_applied": {k: round(v, 2) for k, v in norm_weights.items()},
            "indicators": [i.to_dict() for i in all_indicators],
            "recommendation": RiskEngine.get_action_recommendation(tier, critical_attachment)
        }

    @staticmethod
    def get_action_recommendation(tier: str, critical_attachment: bool = False) -> str:
        if critical_attachment or tier == "Critical":
            return "CRITICAL RISK: Immediate isolation recommended. Do NOT open attachments or click links. Quarantine sample for SOC review."
        elif tier == "High":
            return "HIGH RISK: Quarantine message. High likelihood of social engineering, deceptive links, or weaponized payload."
        elif tier == "Medium":
            return "MEDIUM RISK: Exercise caution. Verify sender authenticity and request details out-of-band via phone or official portal."
        else:
            return "LOW RISK: Standard email handling. No immediate suspicious markers found, but maintain routine security vigilance."
