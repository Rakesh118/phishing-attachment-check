"""
Unit Tests: Attachment Analyzer (Mission 2 & Mission 3)
Tests magic byte signatures, disguised executables, PDFs, DOCX, macros, encrypted ZIPs, and safe handling.
"""

import unittest
from attachment_analyzer import AttachmentAnalyzer
from sample_generator import (
    create_minimal_pdf,
    create_minimal_docx,
    create_zip_with_images,
    create_disguised_mz_pdf,
    create_macro_docm,
    create_encrypted_zip
)

class TestAttachmentAnalyzer(unittest.TestCase):
    def test_normal_pdf_detection(self):
        """Valid PDF with %PDF- header is detected as application/pdf with low risk."""
        pdf_bytes = create_minimal_pdf()
        report = AttachmentAnalyzer.inspect_attachment("annual_report.pdf", pdf_bytes)
        self.assertEqual(report["detected_mime"], "application/pdf")
        self.assertEqual(report["risk_level"], "Low")
        self.assertLess(report["risk_score"], 25.0)

    def test_mz_signature_disguised_as_pdf(self):
        """CRITICAL: Disguised executable named invoice.pdf with MZ header triggers Critical tier."""
        mz_bytes = create_disguised_mz_pdf()
        report = AttachmentAnalyzer.inspect_attachment("invoice.pdf", mz_bytes)
        self.assertEqual(report["detected_mime"], "application/x-dosexec")
        self.assertEqual(report["risk_level"], "Critical")
        self.assertGreaterEqual(report["risk_score"], 85.0)
        features = " ".join(report["suspicious_features"])
        self.assertIn("DISGUISED EXECUTABLE", features)

    def test_docx_structure_validation(self):
        """Clean DOCX structure has Low risk."""
        docx_bytes = create_minimal_docx()
        report = AttachmentAnalyzer.inspect_attachment("project_overview.docx", docx_bytes)
        self.assertEqual(report["risk_level"], "Low")
        self.assertLess(report["risk_score"], 25.0)

    def test_macro_enabled_office_detection(self):
        """Macro-enabled file or presence of vbaProject.bin raises risk."""
        docm_bytes = create_macro_docm()
        report = AttachmentAnalyzer.inspect_attachment("urgent_invoice.docm", docm_bytes)
        self.assertIn(report["risk_level"], ["High", "Critical"])
        features = " ".join(report["suspicious_features"])
        self.assertIn("Macro", features)

    def test_encrypted_zip_detection(self):
        """Password-protected / encrypted ZIP archive is flagged as opaque."""
        enc_zip_bytes = create_encrypted_zip()
        report = AttachmentAnalyzer.inspect_attachment("confidential.zip", enc_zip_bytes)
        features = " ".join(report["suspicious_features"])
        self.assertIn("encrypted", features.lower())
        self.assertGreaterEqual(report["risk_score"], 25.0)

    def test_zip_containing_images_low_risk(self):
        """ZIP archive containing ordinary images is inspected and verified Low risk."""
        zip_images = create_zip_with_images()
        report = AttachmentAnalyzer.inspect_attachment("graphics.zip", zip_images)
        self.assertEqual(report["risk_level"], "Low")
        self.assertLess(report["risk_score"], 25.0)

    def test_oversized_file_handling(self):
        """Oversized file triggers safe bounded handling without crashing."""
        oversized = b"A" * (26 * 1024 * 1024)  # 26 MB
        report = AttachmentAnalyzer.inspect_attachment("huge_dump.iso", oversized)
        features = " ".join(report["suspicious_features"])
        self.assertIn("Oversized", features)

    def test_malformed_zip_handling(self):
        """Malformed ZIP bytes are caught gracefully and reported."""
        malformed = b"PK\x03\x04\x00\x00garbage_corrupted_payload"
        report = AttachmentAnalyzer.inspect_attachment("broken.zip", malformed)
        features = " ".join(report["suspicious_features"])
        self.assertIn("Malformed", features)

if __name__ == "__main__":
    unittest.main()
