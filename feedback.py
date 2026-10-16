"""
Local Feedback Collection Module
Persists user classification feedback locally in CSV format.
Strict privacy protection: Never logs email passwords, full bodies, or attachment payloads.
"""

import os
import csv
from datetime import datetime
from typing import Dict, List, Any

FEEDBACK_DIR = os.path.join(os.path.dirname(__file__), "data")
FEEDBACK_FILE = os.path.join(FEEDBACK_DIR, "feedback.csv")

CSV_HEADERS = [
    "timestamp",
    "sample_id",
    "predicted_score",
    "predicted_level",
    "user_feedback",
    "comment"
]


class FeedbackSystem:
    @staticmethod
    def _ensure_storage() -> None:
        os.makedirs(FEEDBACK_DIR, exist_ok=True)
        if not os.path.exists(FEEDBACK_FILE):
            with open(FEEDBACK_FILE, mode="w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(CSV_HEADERS)

    @classmethod
    def record_feedback(
        cls,
        sample_id: str,
        predicted_score: float,
        predicted_level: str,
        user_feedback: str,
        comment: str = ""
    ) -> bool:
        """
        Appends user feedback record to data/feedback.csv.
        Permitted feedback options: 'Correct', 'False Positive', 'False Negative', 'Unsure'
        """
        valid_options = {"Correct", "False Positive", "False Negative", "Unsure"}
        if user_feedback not in valid_options:
            user_feedback = "Unsure"

        cls._ensure_storage()

        # Sanitize inputs
        clean_id = (sample_id or "adhoc_scan")[:80].replace(",", ";")
        clean_comment = (comment or "")[:300].replace("\n", " ").replace("\r", " ").replace(",", ";")
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        try:
            with open(FEEDBACK_FILE, mode="a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    timestamp,
                    clean_id,
                    round(predicted_score, 1),
                    predicted_level,
                    user_feedback,
                    clean_comment
                ])
            return True
        except Exception:
            return False

    @classmethod
    def get_feedback_records(cls) -> List[Dict[str, Any]]:
        """Retrieves all logged feedback records."""
        cls._ensure_storage()
        records = []
        try:
            with open(FEEDBACK_FILE, mode="r", newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    records.append(row)
        except Exception:
            pass
        return records

    @classmethod
    def get_summary_stats(cls) -> Dict[str, Any]:
        """Calculates telemetry summary statistics."""
        records = cls.get_feedback_records()
        total = len(records)
        counts = {
            "Correct": 0,
            "False Positive": 0,
            "False Negative": 0,
            "Unsure": 0
        }
        for r in records:
            fb = r.get("user_feedback", "Unsure")
            counts[fb] = counts.get(fb, 0) + 1

        accuracy_rate = (counts["Correct"] / total * 100.0) if total > 0 else 0.0

        return {
            "total_feedback_count": total,
            "counts": counts,
            "user_accuracy_rate": round(accuracy_rate, 1)
        }
