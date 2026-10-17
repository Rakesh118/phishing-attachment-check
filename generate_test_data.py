"""
Script to populate test_data/ directory with safe, reproducible synthetic test fixtures.
Zero live malware, zero active exploits, safe for academic and enterprise demonstration.
"""

import os
import io
import sys
import zipfile

sys.path.insert(0, os.path.dirname(__file__))

from sample_generator import (
    create_minimal_pdf,
    create_minimal_docx,
    create_zip_with_images,
    create_disguised_mz_pdf,
    create_macro_docm,
    create_encrypted_zip,
    create_macro_xlsm,
    create_macro_pptm,
    create_malformed_office_docx,
    create_corrupt_pdf,
    create_unknown_binary,
    create_mismatch_pdf_png
)

TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), "test_data")
os.makedirs(TEST_DATA_DIR, exist_ok=True)

# 1. Generate Binary / Attachment Fixtures
fixtures = {
    "legitimate_invoice.pdf": create_minimal_pdf(),
    "legitimate_project_charter.docx": create_minimal_docx(),
    "legitimate_images_bundle.zip": create_zip_with_images(),
    "synthetic_disguised_mz.pdf": create_disguised_mz_pdf(),
    "synthetic_macro_review.docm": create_macro_docm(),
    "synthetic_macro_sheet.xlsm": create_macro_xlsm(),
    "synthetic_macro_presentation.pptm": create_macro_pptm(),
    "synthetic_encrypted_payroll.zip": create_encrypted_zip(),
    "synthetic_malformed_container.docx": create_malformed_office_docx(),
    "synthetic_corrupt_header.pdf": create_corrupt_pdf(),
    "synthetic_mismatch_extension.pdf": create_mismatch_pdf_png(),
    "synthetic_unknown_payload.bin": create_unknown_binary(),
    "empty_zero_byte.dat": b""
}

for filename, content in fixtures.items():
    file_path = os.path.join(TEST_DATA_DIR, filename)
    with open(file_path, "wb") as f:
        f.write(content)
    print(f"Generated fixture: {filename} ({len(content)} bytes)")

# 2. Generate Harmless Synthetic Email (.eml / text) Fixtures
email_fixtures = {
    "email_01_legitimate_invoice.eml": (
        "From: billing@acme-corp.com\n"
        "To: accounts@enterprise.com\n"
        "Subject: Invoice #INV-2026-884 for Acme Services\n"
        "Date: Fri, 17 Oct 2026 09:00:00 +0000\n\n"
        "Hi Finance Team,\n\n"
        "Please find attached our monthly service invoice for September 2026.\n"
        "Let us know if you have any questions regarding the line items.\n\n"
        "Best regards,\nAccounting Department\nAcme Corporation\n"
    ),
    "email_02_legitimate_urgency.eml": (
        "From: Robert Davis <rdavis@internal-network.com>\n"
        "To: team@internal-network.com\n"
        "Subject: Urgent: Budget sign-off required today before 5 PM\n"
        "Date: Fri, 17 Oct 2026 10:15:00 +0000\n\n"
        "Hi Team,\n\n"
        "Action required: We have a hard deadline for the department budget today.\n"
        "Please submit your travel expenses immediately so we can finalize the quarterly numbers.\n\n"
        "Thank you,\nRobert Davis\nFinance Operations\n"
    ),
    "email_03_legitimate_long_url.eml": (
        "From: Cloud Notifications <notify@aws-internal-audit.com>\n"
        "To: devops@enterprise.com\n"
        "Subject: Architecture Diagram Shared with You\n"
        "Date: Fri, 17 Oct 2026 11:30:00 +0000\n\n"
        "Hello,\n\n"
        "Your team member shared an architecture artifact. You can view it here:\n"
        "https://s3.amazonaws.com/internal-corp-cloud-artifacts-2026/diagrams/network-topology-v4.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20261017%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20261017T020000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=d2c67b2d56a73c19e76d333066a3d6a7d5a5700885e34789123456789abcdef0\n\n"
        "Best regards,\nCloud Ops\n"
    ),
    "email_04_obvious_phishing.eml": (
        "From: PayPal Security <service@paypa1-security-verification.xyz>\n"
        "Reply-To: collections@offshore-redirect.net\n"
        "To: victim@company.com\n"
        "Subject: URGENT: Your PayPal Account Has Been Suspended!\n"
        "Date: Fri, 17 Oct 2026 12:00:00 +0000\n\n"
        "Dear Valued Customer,\n\n"
        "Your account has experienced unauthorized logins. Immediate action required within 24 hours!\n"
        "Verify your password and billing info here:\n"
        "http://192.168.1.105/auth/login.php?user=victim\n\n"
        "Alternatively, verify through our backup portal: http://paypal.com.verify-billing.xyz/signin\n\n"
        "Failure to do so will result in permanent account termination.\n\n"
        "PayPal Support Team\n"
    ),
    "email_05_password_in_body_archive.eml": (
        "From: Payroll Service <payroll@service-delivery.click>\n"
        "To: staff@corporate.com\n"
        "Subject: Urgent: Salary Adjustment Notice\n"
        "Date: Fri, 17 Oct 2026 13:00:00 +0000\n\n"
        "Dear Employee,\n\n"
        "Please review the attached confidential salary report.\n"
        "Your archive password is: Payroll2026!\n"
        "Open the attachment immediately to verify details.\n\n"
        "Payroll Dept\n"
    ),
    "email_06_missing_headers.eml": (
        "Hey, can you please review this document and check if we are on schedule for the presentation?\n"
        "Let me know before Monday.\n"
    ),
    "email_07_multivector_critical.eml": (
        "From: Microsoft Account Team <security@micros0ft-login-service.top>\n"
        "Reply-To: drop-box@attacker-c2.xyz\n"
        "To: employee@targetcorp.com\n"
        "Subject: URGENT: Your Microsoft 365 Account is Scheduled for Immediate Deletion\n"
        "Date: Fri, 17 Oct 2026 14:00:00 +0000\n\n"
        "Dear User,\n\n"
        "Action required immediately within 24 hours!\n"
        "Your account will be permanently deleted unless you confirm your password:\n"
        "http://10.20.30.40/microsoft-secure-login/auth\n\n"
        "The password is: MS365Safe!\n"
        "Also view the attached cancellation report.\n\n"
        "Microsoft Security\n"
    )
}

for filename, content in email_fixtures.items():
    file_path = os.path.join(TEST_DATA_DIR, filename)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Generated email fixture: {filename} ({len(content)} chars)")

print("\nSuccessfully populated test_data/ directory with all synthetic fixtures.")
