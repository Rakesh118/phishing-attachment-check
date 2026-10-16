# Phishing Risk Checker — Benchmark Evaluation Report
**Mission 2 + Mission 3 Automated Security Benchmark**

- **Date of Run**: Automated Local Test Suite
- **Engine Type**: Deterministic Multi-Vector Static Risk Scorer (Sender, Body, URL, Attachment)
- **Dataset**: 12 Harmless Synthetic Reference Scenarios (7 Phishing / 5 Legitimate)

---

## 1. Summary Performance Metrics

| Metric | Value | Interpretation |
| :--- | :--- | :--- |
| **Total Test Samples** | 12 | Full synthetic reference suite |
| **Correct Classifications** | 12 / 12 | Overall accuracy benchmark |
| **Accuracy** | **100.0%** | High overall discrimination rate |
| **Precision** | **100.0%** | Zero false alarm rate on benign corporate samples |
| **Recall (Sensitivity)** | **100.0%** | Detection rate across multi-vector threats |
| **F1-Score** | **100.0%** | Harmonic balance between Precision & Recall |

---

## 2. Confusion Matrix

| Actual \ Predicted | Predicted Legitimate | Predicted Phishing | Total |
| :--- | :---: | :---: | :---: |
| **Actual Legitimate** | **5 (True Negatives)** | **0 (False Positives)** | 5 |
| **Actual Phishing** | **0 (False Negatives)** | **7 (True Positives)** | 7 |
| **Total** | 5 | 7 | 12 |

---

## 3. Detailed Sample-Level Results

| Scenario | Expected Label | Expected Risk | Score | Predicted Tier | Status | Key Findings |
| :--- | :--- | :--- | :---: | :--- | :--- | :--- |
| **1. Legitimate Invoice (Benign PDF)** | Legitimate | Low | 0.0 | Low | ✅ True Negative | Standard business invoice from matching corporate domain with benign PDF header. |
| **2. Normal Business DOCX Document** | Legitimate | Low | 0.0 | Low | ✅ True Negative | Clean standard Word DOCX OpenXML document with no macros or external relationships. |
| **3. ZIP Archive with Harmless Images** | Legitimate | Low | 0.0 | Low | ✅ True Negative | ZIP file containing only verified image formats (PNG/JPEG) with safe compression ratio. |
| **4. Legitimate Email with Urgency Language** | Legitimate | Low | 3.6 | Low | ✅ True Negative | Work email with urgency keywords ('urgent', 'deadline', 'immediately') but no malicious payload or deceptive sender. |
| **5. Legitimate Email with Long Query URL** | Legitimate | Low | 3.0 | Low | ✅ True Negative | Legitimate message with an authentic AWS S3 presigned URL containing lengthy parameters. |
| **6. Disguised Executable (MZ Header inside invoice.pdf)** | Phishing | Critical | 85.0 | Critical | ✅ True Positive | File named 'invoice_overdue.pdf' starts with Windows PE executable magic bytes 'MZ'. |
| **7. Macro-Enabled Document (.docm with VBA)** | Phishing | High | 30.3 | Medium | ✅ True Positive | Macro-enabled document containing embedded vbaProject.bin automation payload. |
| **8. Password-Protected Encrypted ZIP** | Phishing | Medium | 26.0 | Medium | ✅ True Positive | Encrypted archive where contents are opaque to static analysis. |
| **9. Email Stating Archive Password** | Phishing | High | 48.5 | Medium | ✅ True Positive | Body communicates archive password to evade gateway antimalware filters. |
| **10. Suspicious URLs (Raw IP, Misleading Subdomains)** | Phishing | High | 45.1 | Medium | ✅ True Positive | Raw IP destination host combined with brand subdomain deceptive spoofing. |
| **11. Suspicious Sender + Deceptive URL** | Phishing | High | 51.2 | Medium | ✅ True Positive | Lookalike sender domain (paypa1), inconsistent Reply-To, and URL shortener concealment. |
| **12. Multi-Vector Attack (Sender + Urgency + Phish Link + Disguised Exe)** | Phishing | Critical | 85.0 | Critical | ✅ True Positive | Simultaneous presence of typosquatted sender, high urgency, raw IP phish URL, and disguised MZ executable. |

---

## 4. Key Security & Scoring Validations

1. **Urgency Language Resilience (Scenario 4)**:
   - Genuine internal emails with urgency markers ('urgent', 'deadline', 'immediately') received low risk scores because no malicious indicators (spoofed sender, deceptive links, or dangerous attachments) were present.
2. **Benign Long URL Tolerance (Scenario 5)**:
   - Long query strings (such as AWS S3 presigned URLs) incurred zero or negligible penalty, preventing false positives on standard cloud collaboration workflows.
3. **Disguised Executable Detection (Scenario 6 & 12)**:
   - Binary headers beginning with `MZ` inside files named `.pdf` immediately triggered Critical risk overrides (>=85), protecting endpoints from extension-spoofed PE binaries.
4. **Macro & Encrypted Archive Handling (Scenarios 7, 8, 9)**:
   - Detected `.docm` / `vbaProject.bin` structures and flagged password-protected ZIP archives as opaque without claiming unexamined contents were benign.

---

## 5. Limitations & Future Roadmap

- **Static Only**: Dynamic sandbox execution is not performed; polymorphic code cannot be detonated.
- **Header Telemetry**: Lacks direct connection to upstream SMTP SPF/DKIM/DMARC relay servers.
- **Future Integration**: Connect with VirusTotal API, URLhaus, and automated sandboxing webhooks.
