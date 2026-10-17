# Phishing Email, URL and Attachment Risk Checker
### Risk Breakdown & Safe Attachment Reporting (Mission 5 Final Repository)

[![Python Version](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![UI Framework](https://img.shields.io/badge/Framework-Streamlit-red.svg)](https://streamlit.io/)
[![Automated Tests](https://img.shields.io/badge/Tests-53%20Passed-brightgreen.svg)](tests/)
[![Security Mandate](https://img.shields.io/badge/Security-Zero--Execution%20Static%20Analysis-purple.svg)](docs/architecture.md)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 📖 Table of Contents
1. [Project Overview & Problem Statement](#-project-overview--problem-statement)
2. [Core Objectives](#-core-objectives)
3. [Key Features & Mission Milestones](#-key-features--mission-milestones)
4. [System Architecture & Repository Structure](#-system-architecture--repository-structure)
5. [Technology Stack](#-technology-stack)
6. [Windows Installation & Setup Guide](#-windows-installation--setup-guide)
7. [Running the Application](#-running-the-application)
8. [Automated Testing & Verification Suite](#-automated-testing--verification-suite)
9. [Configuration Requirements](#-configuration-requirements)
10. [Example Usage & Walkthrough](#-example-usage--walkthrough)
11. [Safety Precautions & Zero-Execution Mandate](#-safety-precautions--zero-execution-mandate)
12. [Evaluation Benchmark & Ground-Truth Results](#-evaluation-benchmark--ground-truth-results)
13. [Deployment Instructions (Streamlit Community Cloud)](#-deployment-instructions-streamlit-community-cloud)
14. [Known Limitations & Future Improvements](#-known-limitations--future-improvements)
15. [Documentation Index](#-documentation-index)

---

## 🎯 Project Overview & Problem Statement

### The Problem
Email phishing remains the primary entry point for more than 90% of organizational cyber breaches, data exfiltration incidents, and ransomware infections. Modern threat actors rarely rely on simple typos; they employ sophisticated multi-vector techniques:
- **Disguised Executable Payloads:** Renaming Windows Portable Executables (`.exe`, `.scr`, `.dll`) with benign document extensions such as `invoice.pdf`.
- **Evasive Encrypted Archives:** Distributing password-protected ZIP archives and delivering the password within the email body to bypass gateway scanning.
- **Weaponized Office Documents:** Embedding VBA macro binaries (`vbaProject.bin`) in OpenXML files.
- **Deceptive URL Structures:** Obfuscating destinations via raw IP addresses, credential `@` userinfo tricks, and lookalike subdomains.

Traditional email filters either block messages indiscriminately (causing high false positives on legitimate business emails) or execute files in heavyweight sandboxes that introduce major latency and operational overhead.

### Our Solution
The **Phishing Email, URL and Attachment Risk Checker** is an explainable, deterministic cybersecurity triage system and forensic dashboard built with **Python 3.11** and **Streamlit**. It executes **zero-execution static analysis** across four independent vectors—Sender Headers, Linguistic Content, URLs, and Attachment Binaries—to calculate a unified threat score (**0–100**) and actionable risk classification (**Low, Medium, High, Critical**).

---

## 🎯 Core Objectives

1. **Zero-Execution Safety:** Analyze potentially dangerous attachments without executing binary code or extracting archives to disk.
2. **Multi-Vector Explainability:** Break down threat scores into itemized indicators with explicit point values and rationale.
3. **Low False-Positive Rate:** Preserve operational communication by tolerating legitimate business urgency language and lengthy presigned cloud storage URLs.
4. **Disguised Binary Defense:** Immediately identify disguised executable headers (`MZ` `0x4D 0x5A`) and trigger an unconditional **Critical Override**.
5. **Rigorous Verification:** Validate every detection capability with a 53-test automated regression suite and standardized ground-truth benchmark metrics.

---

## 🌟 Key Features & Mission Milestones

### Mission 2: Multi-Vector Risk Engine & URL Analysis
- **Dynamic Renormalization:** Intelligently balances weights across available vectors (`Sender: 0.25`, `Body: 0.20`, `URL: 0.25`, `Attachment: 0.30`). Unavailable vectors (e.g., emails without attachments) are marked `"Unavailable"` and never penalize benign messages.
- **Static URL Heuristics:** Detects raw IP hosts, deceptive brand subdomains, userinfo `@` obfuscation, and URL shorteners without making outbound HTTP requests.
- **Presigned URL Tolerance:** Benign long URLs with query parameters (e.g., AWS S3 tokens) are safely tolerated without false alarms.

### Mission 3: Safe Attachment Triage & MZ Executable Guard
- **Deep Byte-Signature Inspection:** Identifies true MIME types by reading start-of-file magic bytes, completely independent of the filename extension.
- **Disguised Executable Defense:** Detects DOS/PE `MZ` headers inside files claiming to be `.pdf` or `.docx` and triggers an immediate **Critical Override (score $\ge 95$)**.
- **In-Memory ZIP Container Inspection:** Inspects ZIP tables directly in memory via `io.BytesIO`, checking member extensions, compression ratios, and entry limits without disk extraction.
- **Encrypted Archive Detection:** Identifies encrypted ZIPs via `flag_bits & 0x1` and marks them opaque, warning analysts that contents cannot be proven safe.
- **Office Macro Detection:** Detects embedded `word/vbaProject.bin`, `xl/vbaProject.bin`, and macro extensions (`.docm`, `.xlsm`, `.pptm`).
- **Attachment Report Cards:** Renders clean forensic report cards displaying Claimed vs Detected type, magic byte hex preview, forensic tags, and handling guidance.

### Mission 4: Automated Testing & Ground-Truth Benchmark
- **53 Automated Pytest Tests:** 100% passing test suite across 5 categories in ~0.3 seconds.
- **12 Standardized Harmless Test Scenarios:** Built-in reproducible fixtures testing clean invoices, macros, disguised executables, encrypted archives, and multi-vector attacks.
- **Formal Evaluation Metrics:** Computes **Accuracy (100%)**, **Precision (100%)**, **Recall (100%)**, **F1-Score (100%)**, and full **Confusion Matrix**.
- **Interactive SOC Validation Tab:** Live Streamlit interface to filter tests, inspect expected vs actual outcomes, and review Markdown reports.

### Mission 5: Final Submission, Jury Defense & Deployment Readiness
- **Complete Architecture Specification:** Detailed module breakdown, sequence diagrams, and mathematical formulas in `docs/architecture.md`.
- **Jury Q&A Defense Guide:** 15 beginner-friendly technical viva questions and answers in `docs/jury_questions.md`.
- **AI & Tooling Disclosure:** Transparent disclosure distinguishing human vs AI contributions in `docs/ai_disclosure.md`.
- **2–3 Minute Demonstration Script:** Step-by-step video script with timestamps and Windows screen-recording instructions in `docs/demo_script.md`.
- **Offline & Cloud Ready:** Zero hardcoded paths, zero external API keys required, streamlined `.gitignore`, and full Streamlit Community Cloud readiness.

---

## 🏗️ System Architecture & Repository Structure

```
phishing-risk-checker/
│
├── app.py                          # Streamlit Web Application & SOC Dashboard
├── risk_engine.py                  # Dynamic weight renormalization & threat scoring engine
├── email_analyzer.py               # RFC822 parser, header forensics & linguistic analyzer
├── url_analyzer.py                 # Static URL heuristic parser & destination inspector
├── attachment_analyzer.py          # Zero-execution binary magic byte & archive inspector
├── sample_generator.py             # 12 synthetic test fixtures & byte generators (zero malware)
├── evaluation.py                   # Ground-truth evaluation engine & metrics calculator
├── feedback.py                     # Local privacy-first CSV feedback logger
├── generate_test_data.py           # Generator script to populate test_data/ fixtures
│
├── requirements.txt                # Project dependencies (streamlit, pytest)
├── pytest.ini                      # Pytest test discovery & execution configuration
├── README.md                       # Complete project documentation & setup manual
├── .gitignore                      # Git exclusion rules (secrets, venvs, caches)
├── run_app.bat                     # Windows 1-click batch launcher for Streamlit
├── run_tests.bat                   # Windows 1-click batch launcher for Pytest
│
├── tests/                          # 53 Automated Regression Tests
│   ├── test_email_analyzer.py      # Category A: Email header & linguistic tests (11 tests)
│   ├── test_url_analyzer.py        # Category B: URL heuristic tests (10 tests)
│   ├── test_attachment_analyzer.py # Category C & D: Attachment & safety tests (18 tests)
│   ├── test_risk_engine.py         # Category E: Risk scoring & threshold tests (12 tests)
│   └── test_feedback.py           # Category F: Telemetry & sanitization tests (2 tests)
│
├── test_data/                      # 100% Harmless Synthetic Test Fixtures
│   ├── README.md                   # Comprehensive test fixture catalog & verification guide
│   ├── legitimate_invoice.pdf      # Valid minimal PDF document
│   ├── legitimate_project_charter.docx # Valid clean DOCX OpenXML document
│   ├── legitimate_images_bundle.zip # Valid ZIP containing harmless PNG & JPEG images
│   ├── synthetic_disguised_mz.pdf  # 64-byte file with MZ header disguised as PDF
│   ├── synthetic_macro_review.docm # Harmless OpenXML document with mock vbaProject.bin
│   ├── synthetic_macro_sheet.xlsm  # Harmless spreadsheet with mock vbaProject.bin
│   ├── synthetic_macro_presentation.pptm # Harmless presentation with mock vbaProject.bin
│   ├── synthetic_encrypted_payroll.zip # Harmless ZIP with encryption bit flag set
│   ├── synthetic_malformed_container.docx # Corrupt non-zip container with docx extension
│   ├── synthetic_corrupt_header.pdf # Corrupt PDF stream missing magic header
│   ├── synthetic_mismatch_extension.pdf # PNG image payload named with .pdf extension
│   ├── synthetic_unknown_payload.bin # Unrecognized binary stream (octet-stream)
│   ├── empty_zero_byte.dat         # 0-byte boundary test fixture
│   └── email_01 to 07 (.eml)       # 7 RFC822 synthetic email message fixtures
│
├── reports/                        # Saved Audit & Evaluation Reports
│   ├── evaluation_report.md        # Benchmark evaluation metrics & confusion matrix
│   ├── mission4_test_report.md     # Mission 4 comprehensive test suite verification report
│   └── mission5_submission_report.md # Mission 5 final repository submission report
│
├── docs/                           # Mission 5 Final Documentation Suite
│   ├── architecture.md             # Detailed system architecture, data flow & formulas
│   ├── jury_questions.md           # 15 technical viva Q&A for college jury review
│   ├── ai_disclosure.md            # Transparent AI, tool & team contribution disclosure
│   └── demo_script.md              # 2-3 minute video demonstration script & recording guide
│
└── data/                           # Local Privacy-Safe Storage
    └── feedback.csv                # Local analyst feedback telemetry log
```

---

## 💻 Technology Stack

| Component | Technology | Rationale & Selection Criteria |
| :--- | :--- | :--- |
| **Programming Language** | **Python 3.11+** | Native typing, cross-platform compatibility, battle-tested standard libraries for binary and email manipulation. |
| **Web Presentation** | **Streamlit (>=1.30.0)** | Clean, responsive cybersecurity dashboard layout in pure Python without complex frontend build tools. |
| **Testing Framework** | **Pytest (>=7.4.0)** | Robust test runner with detailed output, fixtures, and sub-second execution speeds. |
| **Binary & Archive Inspection** | **`io.BytesIO`, `zipfile`** | Safe in-memory container inspection avoiding disk writes and Zip-Slip traversal. |
| **Network & URI Parsing** | **`urllib.parse`, `ipaddress`** | Strict RFC 3986 URL parsing and IP address validation without external network calls. |
| **Message Parsing** | **`email` (Python Stdlib)** | RFC 822 / RFC 2822 header extraction and MIME boundary decoding. |
| **Third-Party APIs** | **None (0)** | 100% offline, privacy-first design. No data leaves the local host. |

---

## 🚀 Windows Installation & Setup Guide

### 1. Prerequisites
- **Operating System:** Windows 10 or Windows 11 (also runs on Linux and macOS).
- **Python:** Python 3.11 or higher installed.
  - To verify Python, open PowerShell and run:
    ```powershell
    python --version
    ```
  - If Python is installed in a custom location (e.g., `C:\Users\<user>\python311\python.exe`), that path can be called directly.

### 2. Clone or Extract the Project
Open PowerShell or Command Prompt in the project workspace folder:
```powershell
cd "C:\path\to\phishing-risk-checker"
```

### 3. Setup Virtual Environment (Recommended)
```powershell
# Create virtual environment
python -m venv .venv

# Activate virtual environment (PowerShell)
.\.venv\Scripts\Activate.ps1

# (If PowerShell displays an execution policy error, run once:
#  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser)
```

### 4. Install Dependencies
```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

---

## 🖥️ Running the Application

### Option A: Via Python Command
With your virtual environment activated:
```powershell
python -m streamlit run app.py
```

### Option B: Via Windows 1-Click Batch Script
Double-click `run_app.bat` or run:
```cmd
run_app.bat
```

Once started, the application will automatically open in your default browser at:
```
http://localhost:8501
```

---

## 🧪 Automated Testing & Verification Suite

The repository includes a comprehensive regression test suite comprising **53 automated tests**:

### Option A: Standard Pytest Command
```powershell
python -m pytest -v
```

### Option B: Via Windows 1-Click Batch Script
Double-click `run_tests.bat` or run:
```cmd
run_tests.bat
```

### Actual Verified Test Outcome:
```
============================= test session starts =============================
platform win32 -- Python 3.11.9, pytest-9.1.1 -- rootdir: C:\...\phishing-risk-checker
collected 53 items

tests/test_attachment_analyzer.py ................. [ 33%]
tests/test_email_analyzer.py ...........            [ 54%]
tests/test_feedback.py ..                           [ 58%]
tests/test_risk_engine.py ............              [ 81%]
tests/test_url_analyzer.py ..........               [100%]

============================= 53 passed in 0.31s ==============================
```

---

## ⚙️ Configuration Requirements

- **External API Keys:** **None required.** The application runs 100% locally and offline.
- **Database Configuration:** **None required.** Local feedback is logged to `data/feedback.csv`.
- **Environment Variables:** **None required.** Default ports and settings are managed by Streamlit.

---

## 🔍 Example Usage & Walkthrough

### 1. Analyzing a Legitimate Invoice Email
1. Open the app at `http://localhost:8501`.
2. Under **🛡️ Email & Attachment Scanner**, select **"1. Legitimate Invoice (Benign PDF)"** from the quick-loader.
3. Click **⚡ Analyze Threat Risk & Forensic Breakdown**.
4. **Result:** The system displays **LOW RISK (Score: 0.0 / 100)**. The attachment card confirms `%PDF-` signature matches `.pdf` extension.

### 2. Detecting a Disguised Executable (MZ PE Header)
1. In the scanner, select **"6. Disguised Executable (MZ Header inside invoice.pdf)"** (or upload `test_data/synthetic_disguised_mz.pdf`).
2. Click **⚡ Analyze Threat Risk & Forensic Breakdown**.
3. **Result:** The system triggers an immediate **CRITICAL RISK (Score: 95.0 / 100)** override. The forensic report card flags:
   - *Claimed MIME:* `application/pdf`
   - *Detected Signature:* `0x4D 0x5A` (`MZ` - DOS/Windows PE Executable)
   - *Action:* **Isolate and block immediately.**

### 3. Reviewing Automated Benchmark Results
1. In the sidebar, select **🧪 Mission 4 – Testing & Validation**.
2. View the Metric Cards: **53 Tests Passed**, **100% Accuracy**, **100% Precision**.
3. Use the category filter to inspect specific tests (e.g., `Static Analysis Safety`).
4. Click the **🧮 Confusion Matrix & Metrics** tab to view the confusion matrix.

---

## 🛡️ Safety Precautions & Zero-Execution Mandate

Analyzing suspicious email attachments carries severe operational risks if files are executed. Our architecture enforces a **strict in-memory zero-execution policy**:

1. **Zero OS Process Execution:** The code never calls `subprocess.run`, `subprocess.Popen`, `os.system`, or shell commands. Verified by automated unit tests with mocks (`tests/test_attachment_analyzer.py::TestStaticAnalysisSafety`).
2. **Zero Filesystem Extraction:** Archives are never written or unpacked to disk. Inspection uses `io.BytesIO` streams in memory, neutralizing Zip-Slip directory traversal attacks.
3. **Denial-of-Service (DoS) Ceilings:**
   - 25 MB max attachment inspection size.
   - 500 entry limit per ZIP archive.
   - 100:1 maximum decompression expansion ratio check to neutralize Zip Bombs.
4. **Privacy-Preserving Telemetry:** User feedback logging stores only timestamps, risk scores, and feedback labels. It never logs credentials, full email bodies, or attachment binaries.

---

## 📊 Evaluation Benchmark & Ground-Truth Results

The evaluation engine (`evaluation.py`) benchmarks the risk engine against 12 standardized reference scenarios:

| Metric | Score | Note |
| :--- | :---: | :--- |
| **Total Benchmark Samples** | **12** | 7 Phishing / 5 Legitimate |
| **Correct Detections** | **12 / 12** | 100% correct classification |
| **Overall Accuracy** | **100.0%** | Full discrimination on reference test set |
| **Precision** | **100.0%** | 0 False Positives on benign corporate communications |
| **Recall (Sensitivity)** | **100.0%** | 0 False Negatives across all threat vectors |
| **F1-Score** | **100.0%** | Harmonic mean of precision & recall |

### Confusion Matrix
$$\begin{pmatrix} \text{True Negatives (TN)} = 5 & \text{False Positives (FP)} = 0 \\ \text{False Negatives (FN)} = 0 & \text{True Positives (TP)} = 7 \end{pmatrix}$$

> **Real-World Ground Truth Notice:** While the system achieves 100% precision and recall on the curated reference test fixtures, real-world email traffic contains novel social engineering, zero-day links, and evasion tactics that require continuous rule updates.

---

## ☁️ Deployment Instructions (Streamlit Community Cloud)

This repository is pre-configured for 1-click deployment on **Streamlit Community Cloud**:

### Step 1: Push Repository to GitHub
1. Create a new GitHub repository (e.g., `phishing-risk-checker`).
2. Push your project code:
   ```powershell
   git init
   git add .
   git commit -m "feat: Mission 5 final repository submission"
   git branch -M main
   git remote add origin https://github.com/<your-username>/phishing-risk-checker.git
   git push -u origin main
   ```

### Step 2: Deploy on Streamlit Cloud
1. Sign in to [share.streamlit.io](https://share.streamlit.io) using your GitHub account.
2. Click **New app**.
3. Select your repository (`<your-username>/phishing-risk-checker`), branch (`main`), and main file path:
   ```
   app.py
   ```
4. Click **Deploy!**
5. The cloud build installs dependencies from `requirements.txt` and launches the live web app in ~1–2 minutes.

---

## ⚠️ Known Limitations & Future Improvements

### Current Limitations
1. **Rule-Based Heuristics:** Detection is based on deterministic pattern matching and static signatures. Novel zero-day evasion techniques not covered by existing rules can bypass detection.
2. **Encrypted Archive Opacity:** Static analysis cannot peer inside AES-encrypted ZIP files without the password; such files are flagged as opaque and suspicious.
3. **URL Liveness:** The system does not make outbound network requests, meaning it cannot inspect multi-stage redirects or cloaked web pages.
4. **Synthetic Test Data:** Performance metrics are derived from standardized synthetic test cases, which may not capture the full variance of enterprise email traffic.

### Planned Future Improvements
- **Threat Intelligence Enrichment:** Optional integrations with VirusTotal, Google Safe Browsing, and AbuseIPDB APIs.
- **Deep Learning NLP:** Transformer models (e.g., DistilBERT) to analyze contextual intent and CEO fraud impersonation.
- **Isolated Docker Sandboxing:** Optional opt-in detonation container for behavioral dynamic runtime analysis.
- **Optical Character Recognition (OCR):** Ingest text embedded inside screenshots and image attachments.

---

## 📚 Documentation Index

For in-depth technical specifications and jury defense preparation, refer to the following documentation:

- 📐 **[System Architecture & Data Flow](docs/architecture.md)** — Detailed module breakdown, sequence diagrams, and mathematical scoring formulas.
- 🎓 **[Jury Q&A Defense Guide](docs/jury_questions.md)** — 15 technical questions and answers for viva defense.
- 🤝 **[AI & Development Disclosure](docs/ai_disclosure.md)** — Academic integrity disclosure of AI tools and team member contribution checklist.
- 🎬 **[Demonstration Video Script](docs/demo_script.md)** — 2–3 minute video presentation plan and Windows screen-recording instructions.
- 🧪 **[Synthetic Test Data Catalog](test_data/README.md)** — Full catalog of 20 safe test fixtures.
- 📋 **[Mission 4 Test Report](reports/mission4_test_report.md)** — Detailed verification of all 53 automated tests.
- 🏆 **[Mission 5 Submission Report](reports/mission5_submission_report.md)** — Comprehensive review of final repository deliverables.

---

## 📄 License & Academic Attribution
Developed for academic submission, software verification, and cybersecurity demonstration. All synthetic test fixtures are safe for educational and research use.
