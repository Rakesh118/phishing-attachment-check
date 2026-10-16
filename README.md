# Phishing Email, URL and Attachment Risk Checker
### Risk Breakdown & Safe Attachment Reporting (Mission 2 + Mission 3)

A high-performance, deterministic cybersecurity triage system and forensic reporting dashboard built with **Python 3.11** and **Streamlit**. It executes **zero-execution static analysis** across Email Sender, Linguistic Cues, Embedded URLs, and Attachment Binaries to calculate a unified risk score (0–100) and actionable threat classification.

---

## 🌟 Key Highlights & Capabilities

- **Zero-Execution Static Attachment Triage (Mission 2 & 3)**:
  - Ingests files strictly as in-memory byte buffers (`bytes`).
  - **Never executes, runs, renders, or uncompresses attachments to the filesystem**.
  - **Disguised Executable Defense**: Inspects byte offsets 0–2 for `MZ` (`0x4D 0x5A`) headers. Disguised executables (e.g., `invoice.pdf` with an `MZ` signature) trigger an immediate **Critical Risk Override (>=85)**.
  - **Safe In-Memory ZIP Inspection**: Validates entry limits (<500), decompression ratio (<100:1), and total uncompressed bytes (<100MB) to neutralize Zip Bombs.
  - **Password-Protected Archive Detection**: Checks `flag_bits & 0x1` and flags opaque archives without claiming contents are safe.
  - **Office OpenXML & Macro Detection**: Inspects `.docm`, `.xlsm`, and `word/vbaProject.bin` entries plus external relationship injection (`TargetMode="External"`).
  - **Individual Attachment Report Cards**: Clean forensic report cards for each attachment with Claimed vs Detected type, magic byte hex preview, forensic tags, and recommended handling action.
- **Transparent Multi-Vector Risk Engine (0–100)**:
  - Dynamically renormalizes weights across available vectors (`Sender: 0.25`, `Body: 0.20`, `URL: 0.25`, `Attachment: 0.30`).
  - Missing vectors are labeled **Unavailable**, never penalizing benign emails.
  - Deduplicates correlated indicators to prevent score double-counting.
  - Scores capped strictly between 0 and 100 with standard 4-tier risk classification: **Low (0–24)**, **Medium (25–54)**, **High (55–79)**, **Critical (80–100)**.
- **Resilient URL Analysis**:
  - Detects raw IP hostnames, URL shorteners, punycode homographs (`xn--`), userinfo `@` spoofing, and excessive subdomain chaining.
  - **Zero-Penalty Policy for Benign Long URLs**: Presigned query parameters (e.g., AWS S3 links) do not trigger false alarms.
  - Strictly static heuristics; URLs are never visited or scraped.
- **Linguistic Resilience**:
  - Urgency language alone receives low weight (+8 pts) to ensure legitimate operational communications (e.g. project deadlines) are classified as Low risk.
  - Correlates archive passwords stated in email bodies with password-protected attachments.
- **Automated Benchmark Dashboard & Evaluation**:
  - 12 harmless synthetic reference test fixtures testing all combinations.
  - Ground-truth evaluation computing **Accuracy, Precision, Recall, F1-Score, and a complete Confusion Matrix**.
  - Generates detailed Markdown evaluation reports in `reports/evaluation_report.md`.
- **Local Privacy-First Feedback Telemetry**:
  - Records user feedback (`Correct`, `False Positive`, `False Negative`, `Unsure`) in `data/feedback.csv`.
  - Never stores email passwords, full bodies, or attachment binaries.

---

## 🏗️ Project Architecture

```
phishing-risk-checker/
│
├── app.py                      # Interactive Streamlit Web SOC Dashboard
├── requirements.txt            # Project dependencies (streamlit, pytest)
├── README.md                   # Complete architectural guide & demo walkthrough
├── risk_engine.py              # Normalized weighted scoring & tier classification
├── email_analyzer.py           # RFC822 parser, sender analysis & body linguistics
├── url_analyzer.py             # Static URL parser & structural heuristic engine
├── attachment_analyzer.py      # Mission 2 safe in-memory binary signature inspector
├── feedback.py                 # Local CSV feedback tracker & telemetry metrics
├── evaluation.py               # Benchmark engine, metric calculator & report generator
├── sample_generator.py         # 12 harmless synthetic test fixtures (zero malware)
│
├── tests/                      # Pytest Automated Test Suite (24 tests)
│   ├── test_risk_engine.py
│   ├── test_email_analyzer.py
│   ├── test_url_analyzer.py
│   ├── test_attachment_analyzer.py
│   └── test_feedback.py
│
├── reports/
│   └── evaluation_report.md    # Automated evaluation benchmark report
│
└── data/
    └── feedback.csv            # Privacy-safe local feedback log
```

---

## 🚀 Installation & Running Locally (Windows)

### 1. Prerequisites
Ensure Python 3.11+ is installed.

### 2. Setup Virtual Environment (Recommended)
Open PowerShell or Command Prompt in the project folder:

```powershell
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
```

### 3. Launch the Streamlit Web Application

```powershell
python -m streamlit run app.py
```

The application will launch automatically at `http://localhost:8501`.

---

## 🧪 Running Automated Unit Tests

Execute the 24 automated test cases covering all 14 Mission 2 & Mission 3 test criteria:

```powershell
python -m pytest -o pythonpath=. tests -v
```

All 24 unit tests validate:
- MIME signature vs extension mismatches
- Disguised `MZ` executable headers inside `.pdf` files
- Normal PDF `%PDF-` validation
- Clean DOCX container parsing
- Macro-enabled `.docm` / `vbaProject.bin` detection
- Encrypted password-protected ZIP detection
- Password mention detection in email bodies
- ZIP files containing verified harmless images
- Urgency language resilience on benign emails
- Safe handling of benign long URLs
- Dynamic vector weight renormalization and score capping
- Itemized forensic explanation generation
- Privacy-safe feedback logging
- Bounded oversized payload rejection (>25MB) and malformed archive defense

---

## 📊 Evaluation Results (12 Reference Scenarios)

The automated benchmark suite evaluates 12 standardized reference scenarios:

| Metric | Score | Note |
| :--- | :---: | :--- |
| **Total Benchmark Samples** | **12** | 7 Phishing / 5 Legitimate |
| **Correct Detections** | **12 / 12** | 100% correct classification |
| **Overall Accuracy** | **100.0%** | Full discrimination capability |
| **Precision** | **100.0%** | 0 False Positives on benign corporate emails |
| **Recall (Sensitivity)** | **100.0%** | 0 False Negatives across all threat vectors |
| **F1-Score** | **100.0%** | Harmonic mean of precision & recall |

### Confusion Matrix
- **True Negatives (TN):** 5 (Clean invoice, normal DOCX, ZIP with images, urgency email, long AWS S3 link)
- **True Positives (TP):** 7 (Disguised MZ-in-PDF, docm macro, encrypted zip, stated zip password, raw IP phish URL, typosquatted sender, multi-vector attack)
- **False Positives (FP):** 0
- **False Negatives (FN):** 0

*Detailed breakdown available in `reports/evaluation_report.md`.*

---

## 📋 Requirement-by-Requirement Checklist

### Mission 2 — Attachment & Safe File Triage
- [x] **Static Zero-Execution Inspection**: Files are inspected purely via byte arrays in memory without running or executing.
- [x] **File Signature & Magic-Byte Analysis**: Supported signatures include MZ, PDF, PK (ZIP/DOCX), OLE2, 7z, RAR, PNG, JPEG, GIF.
- [x] **Disguised Executable Defense**: Detects `MZ` header inside files named `.pdf`, `.docx`, `.jpg` and raises Critical tier override.
- [x] **Safe In-Memory ZIP Inspection**: Never extracts files to disk; reads ZipInfo members in memory.
- [x] **Decompression Bomb Protection**: Checks uncompressed vs compressed ratio (<100:1) and entry ceiling (<500).
- [x] **Password-Protected ZIPs**: Reads `flag_bits & 0x1` and clearly reports that contents are opaque to static analysis.
- [x] **Office Document & Macro Validation**: Detects `[Content_Types].xml`, `vbaProject.bin`, `.docm`, and external relationship links.
- [x] **Individual Attachment Report Cards**: Displays filename, claimed extension, detected MIME, signature, hex preview, risk score, and recommended action.
- [x] **Safety Disclaimer**: Explicitly states that static analysis cannot guarantee detection of every threat.

### Mission 3 — Risk Breakdown & Full Engine
- [x] **4 Independent Vectors**: Sender (25%), Body (20%), URLs (25%), Attachments (30%).
- [x] **Dynamic Weight Renormalization**: Missing components are marked "Unavailable" and weights are normalized across active vectors.
- [x] **No False Alarms on Benign Signals**: Urgency words alone receive only +8 pts (Low risk). Benign long URLs carry no penalty.
- [x] **Itemized Forensic Evidence**: Shows exact point additions, severity, and plain-English rationale for every alert.
- [x] **Privacy-Safe Feedback**: Logs user feedback to `data/feedback.csv` without storing passwords or message bodies.
- [x] **Benchmark & Evaluation Dashboard**: Computes Accuracy, Precision, Recall, F1, and Confusion Matrix.
- [x] **12 Harmless Synthetic Test Fixtures**: Zero malware payloads; clean demonstration of every scenario.

---

## 🎓 College Presentation Demo Workflow (3-Minute Tour)

For presenting this project to evaluators or classmates, follow this concise demonstration flow:

1. **Step 1: Benign Baseline Demo (Scenario 4)**
   - Open the web UI at `http://localhost:8501`.
   - Select **"4. Legitimate Email with Urgency Language"** from the scenario dropdown.
   - Click **"Scan & Analyze Threat Vectors"**.
   - *Highlight to audience:* Notice how despite words like "urgent" and "deadline", the system scores **3.6 / 100 (Low Risk)** because there are no lookalike senders, bad links, or weaponized payloads.

2. **Step 2: Disguised Executable Triage (Scenario 6 — Mission 2 Showcase)**
   - Select **"6. Disguised Executable (MZ Header inside invoice.pdf)"**.
   - Click **"Scan & Analyze Threat Vectors"**.
   - *Highlight to audience:* Show the **Overall Score of 85.0 / 100 (CRITICAL RISK)**.
   - Scroll down to the **Per-Attachment Report Card**: point out the `MZ Executable` detected signature, `4D5A...` hex header preview, and the alert: `"DISGUISED EXECUTABLE: MZ binary header inside non-executable filename"`.

3. **Step 3: Multi-Vector Combined Attack (Scenario 12)**
   - Select **"12. Multi-Vector Attack"**.
   - *Highlight to audience:* Show how all 4 vectors contribute: typosquatted domain (`micros0ft-login-service.top`), credential demands, raw IP login link (`10.20.30.40`), and disguised attachment payload.

4. **Step 4: Evaluation Benchmark Dashboard**
   - Click **"📊 Evaluation Benchmark Dashboard"** in the sidebar.
   - Show the 100% Accuracy, 100% Precision, and the interactive Confusion Matrix.
   - Mention the automated report generated at `reports/evaluation_report.md`.

5. **Step 5: Feedback & Telemetry**
   - Switch to **"💬 User Feedback Telemetry"** to show privacy-safe local audit logging.

---

## 🔒 Security Principles Followed

- **Principle of Least Privilege & Zero Execution**: Attachments are strictly treated as inert data bytes.
- **Data Privacy**: No passwords, personal credentials, or email bodies are recorded in feedback telemetry.
- **Transparent Scoring**: Every risk point is tied directly to an itemized forensic rule with plain-English justification.
- **Fail-Safe Defaults**: Encrypted archives are marked opaque, never assumed safe.
