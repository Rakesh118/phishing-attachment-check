"""
Harmless Synthetic Sample Generator
Generates safe, self-contained test fixtures for all 12 evaluation scenarios.
Contains zero live malware or active executable code.
"""

import io
import zipfile
from typing import Dict, Any, List

def create_minimal_pdf() -> bytes:
    """Returns a harmless valid minimal PDF byte stream."""
    return (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
        b"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n"
        b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n190\n%%EOF\n"
    )

def create_minimal_docx() -> bytes:
    """Returns a harmless minimal DOCX zip container."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", b'<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>')
        zf.writestr("word/document.xml", b'<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Quarterly Financial Overview</w:t></w:r></w:p></w:body></w:document>')
    return buf.getvalue()

def create_zip_with_images() -> bytes:
    """Returns a safe ZIP archive containing harmless PNG/JPEG test data."""
    buf = io.BytesIO()
    # Harmless 1x1 PNG header
    png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
    # Harmless JPEG header
    jpg_bytes = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00\xFF\xDB\x00C\x00\xFF\xD9"
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("chart_preview.png", png_bytes)
        zf.writestr("receipt_scan.jpg", jpg_bytes)
    return buf.getvalue()

def create_disguised_mz_pdf() -> bytes:
    """
    Returns a harmless 64-byte sample with 'MZ' signature named invoice.pdf.
    Contains no executable code, only the 2-byte MZ magic header.
    """
    return b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00\xB8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00" + b"\x00" * 36

def create_macro_docm() -> bytes:
    """Returns a harmless minimal docm containing a synthetic vbaProject.bin entry."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", b'<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        zf.writestr("word/document.xml", b'<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Invoice Document</w:t></w:r></w:p></w:body></w:document>')
        zf.writestr("word/vbaProject.bin", b"VBA_PROJECT_MOCK_TEST_BINARY_NON_EXECUTABLE")
    return buf.getvalue()

def create_encrypted_zip() -> bytes:
    """
    Returns a ZIP file with bit 0 set (encrypted flag).
    Sets flag_bits=0x1 in both local file header and central directory.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("confidential_payroll.pdf", b"ENCRYPTED_OPAQUE_STREAM_MOCK")
    raw = bytearray(buf.getvalue())
    # Set bit 0 in local header (offset 6)
    if len(raw) > 6:
        raw[6] = 1
    # Set bit 0 in central directory (PK\x01\x02 offset 8)
    cd_pos = raw.find(b"PK\x01\x02")
    if cd_pos != -1 and cd_pos + 8 < len(raw):
        raw[cd_pos + 8] = 1
    return bytes(raw)

def create_macro_xlsm() -> bytes:
    """Returns a harmless minimal xlsm containing a synthetic vbaProject.bin entry."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", b'<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        zf.writestr("xl/workbook.xml", b'<workbook/>')
        zf.writestr("xl/vbaProject.bin", b"MOCK_VBA_BIN_SAFE_DATA")
    return buf.getvalue()

def create_macro_pptm() -> bytes:
    """Returns a harmless minimal pptm containing a synthetic vbaProject.bin entry."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", b'<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        zf.writestr("ppt/presentation.xml", b'<presentation/>')
        zf.writestr("ppt/vbaProject.bin", b"MOCK_VBA_BIN_PPTM")
    return buf.getvalue()

def create_malformed_office_docx() -> bytes:
    """Returns corrupted non-zip bytes named with .docx extension."""
    return b"PK\x03\x04\x00\x00CORRUPT_NON_ZIP_CONTAINER_STREAM_DATA"

def create_corrupt_pdf() -> bytes:
    """Returns corrupted PDF missing %PDF- header."""
    return b"CORRUPTED_PDF_PAYLOAD_MISSING_MAGIC_HEADER"

def create_unknown_binary() -> bytes:
    """Returns 32 bytes of unrecognized binary data (application/octet-stream)."""
    return b"\x12\x34\x56\x78\x9A\xBC\xDE\xF0\x01\x02\x03\x04\x05\x06\x07\x08" * 2

def create_mismatch_pdf_png() -> bytes:
    """Returns a PNG file named invoice.pdf (mime/extension mismatch)."""
    return b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4"


class SampleGenerator:
    @staticmethod
    def get_all_scenarios() -> List[Dict[str, Any]]:
        """Returns the complete catalog of 12 built-in evaluation test scenarios."""
        return [
            # Scenario 1: Legitimate invoice email with benign PDF-like test file
            {
                "id": "scenario_01",
                "name": "1. Legitimate Invoice (Benign PDF)",
                "expected_label": "Legitimate",
                "expected_risk": "Low",
                "email_text": (
                    "From: billing@acme-corp.com\n"
                    "Subject: Invoice #INV-2026-884 for Acme Services\n"
                    "Date: Fri, 17 Oct 2026 09:00:00 +0000\n\n"
                    "Hi Finance Team,\n\n"
                    "Please find attached our monthly service invoice for September 2026.\n"
                    "Let us know if you have any questions regarding the line items.\n\n"
                    "Best regards,\nAccounting Department\nAcme Corporation"
                ),
                "attachments": [("invoice_acme_2026.pdf", create_minimal_pdf())],
                "description": "Standard business invoice from matching corporate domain with benign PDF header."
            },

            # Scenario 2: Normal DOCX document
            {
                "id": "scenario_02",
                "name": "2. Normal Business DOCX Document",
                "expected_label": "Legitimate",
                "expected_risk": "Low",
                "email_text": (
                    "From: Sarah Jenkins <sjenkins@enterprisecorp.com>\n"
                    "Subject: Draft Project Scope Document\n\n"
                    "Hello team,\n\n"
                    "Attached is the updated project charter for review ahead of Friday's sync.\n"
                    "No macros are used; standard OpenXML format.\n\n"
                    "Thanks,\nSarah"
                ),
                "attachments": [("project_scope_draft.docx", create_minimal_docx())],
                "description": "Clean standard Word DOCX OpenXML document with no macros or external relationships."
            },

            # Scenario 3: ZIP archive containing harmless PNG/JPEG test data
            {
                "id": "scenario_03",
                "name": "3. ZIP Archive with Harmless Images",
                "expected_label": "Legitimate",
                "expected_risk": "Low",
                "email_text": (
                    "From: Design Team <creatives@designstudio.org>\n"
                    "Subject: Asset package for upcoming campaign\n\n"
                    "Hi there,\n\n"
                    "Here is the zip archive containing the requested PNG banner and JPEG photo proofs.\n"
                    "Feel free to extract and integrate them into the slide deck.\n\n"
                    "Regards,\nDesign Studio"
                ),
                "attachments": [("assets_bundle.zip", create_zip_with_images())],
                "description": "ZIP file containing only verified image formats (PNG/JPEG) with safe compression ratio."
            },

            # Scenario 4: Legitimate email containing urgency words
            {
                "id": "scenario_04",
                "name": "4. Legitimate Email with Urgency Language",
                "expected_label": "Legitimate",
                "expected_risk": "Low",
                "email_text": (
                    "From: Robert Davis <rdavis@internal-network.com>\n"
                    "Subject: Urgent: Budget sign-off required today before 5 PM\n\n"
                    "Hi Team,\n\n"
                    "Action required: We have a hard deadline for the department budget today.\n"
                    "Please submit your travel expenses immediately so we can finalize the quarterly numbers.\n\n"
                    "Thank you,\nRobert Davis\nFinance Operations"
                ),
                "attachments": [],
                "description": "Work email with urgency keywords ('urgent', 'deadline', 'immediately') but no malicious payload or deceptive sender."
            },

            # Scenario 5: Legitimate email containing a long but benign URL
            {
                "id": "scenario_05",
                "name": "5. Legitimate Email with Long Query URL",
                "expected_label": "Legitimate",
                "expected_risk": "Low",
                "email_text": (
                    "From: Cloud Notifications <notify@aws-internal-audit.com>\n"
                    "Subject: Architecture Diagram Shared with You\n\n"
                    "Hello,\n\n"
                    "Your team member shared an architecture artifact. You can view it here:\n"
                    "https://s3.amazonaws.com/internal-corp-cloud-artifacts-2026/diagrams/network-topology-v4.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20261017%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20261017T020000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=d2c67b2d56a73c19e76d333066a3d6a7d5a5700885e34789123456789abcdef0\n\n"
                    "Best regards,\nCloud Ops"
                ),
                "attachments": [],
                "description": "Legitimate message with an authentic AWS S3 presigned URL containing lengthy parameters."
            },

            # Scenario 6: Harmless file named invoice.pdf with an MZ signature in tiny synthetic byte sample
            {
                "id": "scenario_06",
                "name": "6. Disguised Executable (MZ Header inside invoice.pdf)",
                "expected_label": "Phishing",
                "expected_risk": "Critical",
                "email_text": (
                    "From: Shipping Billing <invoice-update@dhl-tracking-desk.com>\n"
                    "Subject: Overdue Freight Invoice #99321\n\n"
                    "Dear Customer,\n\n"
                    "Your package is held at our depot. Please review the attached PDF invoice and settle clearance charges.\n\n"
                    "DHL Express Support"
                ),
                "attachments": [("invoice_overdue.pdf", create_disguised_mz_pdf())],
                "description": "File named 'invoice_overdue.pdf' starts with Windows PE executable magic bytes 'MZ'."
            },

            # Scenario 7: Synthetic macro-enabled Office fixture
            {
                "id": "scenario_07",
                "name": "7. Macro-Enabled Document (.docm with VBA)",
                "expected_label": "Phishing",
                "expected_risk": "High",
                "email_text": (
                    "From: Human Resources <hr-review@corp-consulting.xyz>\n"
                    "Subject: Annual Compensation Review Worksheet\n\n"
                    "Please find attached your compensation review sheet. Enable macros when prompted to compute your bonus.\n\n"
                    "HR Team"
                ),
                "attachments": [("compensation_review.docm", create_macro_docm())],
                "description": "Macro-enabled document containing embedded vbaProject.bin automation payload."
            },

            # Scenario 8: Password-protected ZIP fixture
            {
                "id": "scenario_08",
                "name": "8. Password-Protected Encrypted ZIP",
                "expected_label": "Phishing",
                "expected_risk": "Medium",
                "email_text": (
                    "From: External Vendor <audit-contractor@security-compliance.net>\n"
                    "Subject: Encrypted Audit Findings\n\n"
                    "Attached is the encrypted ZIP archive containing the preliminary audit findings.\n"
                    "The archive is password-protected for transit confidentiality.\n\n"
                    "Vendor Team"
                ),
                "attachments": [("audit_confidential.zip", create_encrypted_zip())],
                "description": "Encrypted archive where contents are opaque to static analysis."
            },

            # Scenario 9: Email mentioning a ZIP password
            {
                "id": "scenario_09",
                "name": "9. Email Stating Archive Password",
                "expected_label": "Phishing",
                "expected_risk": "High",
                "email_text": (
                    "From: Payroll Service <payroll@service-delivery.click>\n"
                    "Subject: Urgent: Salary Adjustment Notice\n\n"
                    "Dear Employee,\n\n"
                    "Please review the attached confidential salary report.\n"
                    "Your archive password is: Payroll2026!\n"
                    "Open the attachment immediately to verify details.\n\n"
                    "Payroll Dept"
                ),
                "attachments": [("salary_report.zip", create_encrypted_zip())],
                "description": "Body communicates archive password to evade gateway antimalware filters."
            },

            # Scenario 10: Email containing suspicious URL patterns
            {
                "id": "scenario_10",
                "name": "10. Suspicious URLs (Raw IP, Misleading Subdomains)",
                "expected_label": "Phishing",
                "expected_risk": "High",
                "email_text": (
                    "From: Security Alert <no-reply@account-notice.com>\n"
                    "Subject: Security Notice: Unauthorized Login Attempt\n\n"
                    "We noticed an unrecognized login to your portal from another country.\n"
                    "Review active sessions immediately at our IP portal:\n"
                    "http://192.168.1.105/auth/login.php?user=target\n"
                    "Or backup portal: http://paypal.com.verify-billing.xyz/signin\n\n"
                    "Security Operations"
                ),
                "attachments": [],
                "description": "Raw IP destination host combined with brand subdomain deceptive spoofing."
            },

            # Scenario 11: Suspicious sender combined with deceptive URL
            {
                "id": "scenario_11",
                "name": "11. Suspicious Sender + Deceptive URL",
                "expected_label": "Phishing",
                "expected_risk": "High",
                "email_text": (
                    "From: PayPal Support <service@paypa1-security-verification.xyz>\n"
                    "Reply-To: collections@offshore-redirect.net\n"
                    "Subject: Account Restriction Notice: Immediate Action Required\n\n"
                    "Dear Valued Customer,\n\n"
                    "Your PayPal wallet has been restricted due to suspicious activity.\n"
                    "Confirm your credentials now to restore full access:\n"
                    "http://bit.ly/paypal-account-restore-2026\n\n"
                    "Customer Care"
                ),
                "attachments": [],
                "description": "Lookalike sender domain (paypa1), inconsistent Reply-To, and URL shortener concealment."
            },

            # Scenario 12: Multiple combined warning indicators
            {
                "id": "scenario_12",
                "name": "12. Multi-Vector Attack (Sender + Urgency + Phish Link + Disguised Exe)",
                "expected_label": "Phishing",
                "expected_risk": "Critical",
                "email_text": (
                    "From: Microsoft Account Team <security@micros0ft-login-service.top>\n"
                    "Reply-To: drop-box@attacker-c2.xyz\n"
                    "Subject: URGENT: Your Microsoft 365 Account is Scheduled for Immediate Deletion\n\n"
                    "Dear User,\n\n"
                    "Action required immediately within 24 hours!\n"
                    "Your account will be permanently deleted unless you confirm your password:\n"
                    "http://10.20.30.40/microsoft-secure-login/auth\n\n"
                    "The password is: MS365Safe!\n"
                    "Also view the attached cancellation report.\n\n"
                    "Microsoft Security"
                ),
                "attachments": [("cancellation_notice.pdf", create_disguised_mz_pdf())],
                "description": "Simultaneous presence of typosquatted sender, high urgency, raw IP phish URL, and disguised MZ executable."
            }
        ]
