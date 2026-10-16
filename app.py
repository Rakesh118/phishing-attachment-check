"""
Phishing Email, URL and Attachment Risk Checker
Risk Breakdown & Safe Attachment Reporting (Mission 2 + Mission 3)
Built with Streamlit and Python 3.11 Standard Libraries.
"""

import os
import sys
import io
import streamlit as st
import pandas as pd

# Add current workspace directory to sys.path
sys.path.insert(0, os.path.dirname(__file__))

from risk_engine import RiskEngine
from email_analyzer import EmailAnalyzer
from url_analyzer import URLAnalyzer
from attachment_analyzer import AttachmentAnalyzer
from feedback import FeedbackSystem
from sample_generator import SampleGenerator
from evaluation import EvaluationEngine

# Configure Streamlit page
st.set_page_config(
    page_title="Phishing Risk Checker — Risk Breakdown & Safe Attachment Reporting",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for modern cybersecurity SOC aesthetic
st.markdown("""
<style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        color: #1E293B;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1.05rem;
        color: #64748B;
        margin-bottom: 1.5rem;
    }
    .stat-card {
        background-color: #F8FAFC;
        border: 1px solid #E2E8F0;
        border-radius: 10px;
        padding: 16px;
        text-align: center;
    }
    .badge-critical {
        background-color: #FEE2E2;
        color: #991B1B;
        font-weight: 700;
        padding: 6px 14px;
        border-radius: 20px;
        border: 1px solid #F87171;
        display: inline-block;
    }
    .badge-high {
        background-color: #FFEDD5;
        color: #9A3412;
        font-weight: 700;
        padding: 6px 14px;
        border-radius: 20px;
        border: 1px solid #FB923C;
        display: inline-block;
    }
    .badge-medium {
        background-color: #FEF3C7;
        color: #92400E;
        font-weight: 700;
        padding: 6px 14px;
        border-radius: 20px;
        border: 1px solid #FCD34D;
        display: inline-block;
    }
    .badge-low {
        background-color: #DCFCE7;
        color: #166534;
        font-weight: 700;
        padding: 6px 14px;
        border-radius: 20px;
        border: 1px solid #86EFAC;
        display: inline-block;
    }
    .disclaimer-box {
        background-color: #EFF6FF;
        border-left: 4px solid #3B82F6;
        padding: 12px 18px;
        border-radius: 6px;
        font-size: 0.92rem;
        color: #1E3A8A;
        margin-bottom: 20px;
    }
    .report-card {
        background-color: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 8px;
        padding: 18px;
        margin-bottom: 16px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
</style>
""", unsafe_allow_html=True)


def get_badge_html(tier: str) -> str:
    t = tier.lower()
    if t == "critical":
        return '<span class="badge-critical">CRITICAL RISK</span>'
    elif t == "high":
        return '<span class="badge-high">HIGH RISK</span>'
    elif t == "medium":
        return '<span class="badge-medium">MEDIUM RISK</span>'
    else:
        return '<span class="badge-low">LOW RISK</span>'


# Sidebar Navigation
st.sidebar.image("https://img.icons8.com/fluency/96/shield.png", width=64)
st.sidebar.title("Navigation")
menu_selection = st.sidebar.radio(
    "Choose Mode",
    [
        "🛡️ Email & Attachment Scanner",
        "📊 Evaluation Benchmark Dashboard",
        "💬 User Feedback Telemetry",
        "🧪 Scenario Demo Playground",
        "📖 Security Precautions & Guidelines"
    ]
)

st.sidebar.markdown("---")
st.sidebar.markdown("**Mission 2 & 3 Compliance:**")
st.sidebar.markdown("✔️ Static Zero-Execution Attachment Triage")
st.sidebar.markdown("✔️ Disguised MZ-in-PDF Detection")
st.sidebar.markdown("✔️ Safe In-Memory ZIP Inspection")
st.sidebar.markdown("✔️ Bounded & Decompression Bomb Guard")
st.sidebar.markdown("✔️ Macro & Relationship Detection")
st.sidebar.markdown("✔️ Transparent Weighted Multi-Vector Engine")

# ==============================================================================
# SECTION 1: SCANNER
# ==============================================================================
if menu_selection == "🛡️ Email & Attachment Scanner":
    st.markdown('<div class="main-header">Phishing Email, URL & Attachment Risk Checker</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Multi-Vector Zero-Execution Static Threat Scorer & Safe Forensic Attachment Reporting</div>', unsafe_allow_html=True)

    st.markdown("""
    <div class="disclaimer-box">
        <strong>⚠️ Static Analysis Precautionary Notice:</strong><br>
        All inputs and attachments are inspected strictly via offline byte signatures, structural metadata, and bounded heuristics.
        Files are <strong>never executed, uncompressed to filesystem, or rendered</strong>. Static heuristic inspection cannot guarantee 100% detection of every novel threat.
    </div>
    """, unsafe_allow_html=True)

    # Built-in Scenario Quick Loader
    scenarios = SampleGenerator.get_all_scenarios()
    scenario_names = ["(Custom Input / Manual Entry)"] + [s["name"] for s in scenarios]
    
    col_preload, col_reset = st.columns([3, 1])
    with col_preload:
        chosen_scenario_name = st.selectbox("📂 Load Harmless Built-in Demo Scenario:", scenario_names)
    with col_reset:
        st.write("")
        st.write("")
        if st.button("Clear Input"):
            st.session_state["raw_email_input"] = ""
            st.session_state["preset_attachments"] = []
            st.rerun()

    preset_text = ""
    preset_attachments = []
    sample_id = "custom_scan"

    if chosen_scenario_name != "(Custom Input / Manual Entry)":
        for s in scenarios:
            if s["name"] == chosen_scenario_name:
                preset_text = s["email_text"]
                preset_attachments = s.get("attachments", [])
                sample_id = s["id"]
                st.info(f"💡 **Loaded Scenario Goal**: {s['description']} (Expected Tier: **{s['expected_risk']}**)")
                break

    tab_text, tab_eml = st.tabs(["📝 Paste Email Text / Headers", "📁 Upload .EML File"])

    email_to_scan = ""
    eml_extra_attachments = []

    with tab_text:
        email_to_scan = st.text_area(
            "Paste Raw RFC822 Email or Headers + Body:",
            value=preset_text,
            height=200,
            placeholder="From: Security Team <service@paypa1.com>\nSubject: Immediate Verification Needed\n\nPlease confirm your account details immediately: http://192.168.1.100/login"
        )

    with tab_eml:
        uploaded_eml = st.file_uploader("Upload raw .eml file", type=["eml"])
        if uploaded_eml is not None:
            eml_bytes = uploaded_eml.read()
            email_to_scan = eml_bytes
            sample_id = uploaded_eml.name

    st.subheader("📎 Additional Attachment Upload (Optional)")
    uploaded_files = st.file_uploader(
        "Upload files for zero-execution static inspection (PDF, DOCX, ZIP, etc.):",
        accept_multiple_files=True
    )

    extra_attachment_payloads = []
    # Add files from manual uploader
    if uploaded_files:
        for f in uploaded_files:
            extra_attachment_payloads.append((f.name, f.read()))
    # Add preset attachments if scenario was selected
    if preset_attachments and not uploaded_files:
        for fname, fbytes in preset_attachments:
            extra_attachment_payloads.append((fname, fbytes))
        st.caption(f"Included preset attachment(s): {', '.join(fname for fname, _ in preset_attachments)}")

    scan_button = st.button("🔍 Scan & Analyze Threat Vectors", type="primary", use_container_width=True)

    if scan_button or (chosen_scenario_name != "(Custom Input / Manual Entry)" and preset_text):
        if not email_to_scan and not extra_attachment_payloads:
            st.warning("Please provide email text, upload an .eml file, or upload an attachment to analyze.")
        else:
            with st.spinner("Analyzing message vectors statically..."):
                scan_output = EmailAnalyzer.scan_full_message(
                    raw_email=email_to_scan,
                    extra_attachments=extra_attachment_payloads
                )

            risk_eval = scan_output["risk_assessment"]
            overall_score = risk_eval["overall_score"]
            overall_tier = risk_eval["risk_level"]
            v_scores = risk_eval["vector_scores"]
            v_contribs = risk_eval["vector_contributions"]
            weights = risk_eval["weights_applied"]
            indicators = risk_eval["indicators"]

            st.markdown("---")
            st.subheader("🎯 Overall Risk Assessment")

            col_score, col_badge, col_rec = st.columns([1.5, 1.5, 3])
            with col_score:
                st.metric(label="Overall Risk Score", value=f"{overall_score:.1f} / 100")
                st.progress(overall_score / 100.0)

            with col_badge:
                st.write("**Risk Classification Tier**")
                st.markdown(get_badge_html(overall_tier), unsafe_allow_html=True)
                st.write("")
                st.caption("Thresholds: Low (0–24), Medium (25–54), High (55–79), Critical (80–100)")

            with col_rec:
                st.write("**Actionable Recommendation**")
                if overall_tier in ["High", "Critical"]:
                    st.error(risk_eval["recommendation"])
                elif overall_tier == "Medium":
                    st.warning(risk_eval["recommendation"])
                else:
                    st.success(risk_eval["recommendation"])

            st.markdown("---")
            st.subheader("📊 4-Vector Risk Contribution Breakdown")
            st.caption("Calculated using dynamically normalized vector weights to prevent penalizing missing components.")

            c1, c2, c3, c4 = st.columns(4)
            with c1:
                st.markdown("##### 👤 Sender Risk")
                st.metric(label="Raw Score", value=f"{v_scores['sender']} / 100")
                st.caption(f"Contribution: +{v_contribs['sender']} pts (Weight: {weights.get('sender', 0):.0%})")
                if isinstance(v_scores['sender'], (int, float)):
                    st.progress(min(1.0, v_scores['sender'] / 100.0))

            with c2:
                st.markdown("##### 📝 Body Linguistics")
                st.metric(label="Raw Score", value=f"{v_scores['body']} / 100")
                st.caption(f"Contribution: +{v_contribs['body']} pts (Weight: {weights.get('body', 0):.0%})")
                if isinstance(v_scores['body'], (int, float)):
                    st.progress(min(1.0, v_scores['body'] / 100.0))

            with c3:
                st.markdown("##### 🌐 Embedded URLs")
                u_val = v_scores['url']
                st.metric(label="Raw Score", value=f"{u_val}" if u_val == "Unavailable" else f"{u_val} / 100")
                st.caption(f"Contribution: +{v_contribs['url']} pts (Weight: {weights.get('url', 0):.0%})")
                if isinstance(u_val, (int, float)):
                    st.progress(min(1.0, u_val / 100.0))

            with c4:
                st.markdown("##### 📎 Attachment Risk")
                a_val = v_scores['attachment']
                st.metric(label="Raw Score", value=f"{a_val}" if a_val == "Unavailable" else f"{a_val} / 100")
                st.caption(f"Contribution: +{v_contribs['attachment']} pts (Weight: {weights.get('attachment', 0):.0%})")
                if isinstance(a_val, (int, float)):
                    st.progress(min(1.0, a_val / 100.0))

            # Itemized Evidence Breakdown
            st.markdown("---")
            st.subheader(f"🔍 Itemized Forensic Evidence & Alerts ({len(indicators)})")

            if indicators:
                df_indicators = pd.DataFrame(indicators)
                df_indicators = df_indicators.rename(columns={
                    "category": "Vector",
                    "title": "Triggered Rule",
                    "points": "Points",
                    "severity": "Severity",
                    "explanation": "Forensic Rationale"
                })
                st.dataframe(df_indicators[["Vector", "Triggered Rule", "Severity", "Points", "Forensic Rationale"]], use_container_width=True)
            else:
                st.success("No anomalous forensic rules triggered across inspected vectors.")

            # Individual Attachment Report Cards (Mission 2 & Mission 3 Core)
            st.markdown("---")
            st.subheader(f"📄 Per-Attachment Report Cards ({len(scan_output['attachment_reports'])})")

            if scan_output["attachment_reports"]:
                for idx, report in enumerate(scan_output["attachment_reports"]):
                    with st.expander(f"Attachment #{idx+1}: {report['filename']} — {report['risk_level']} Risk ({report['risk_score']} pts)", expanded=True):
                        col_card1, col_card2, col_card3 = st.columns([2, 2, 2])
                        with col_card1:
                            st.write(f"**Filename:** `{report['filename']}`")
                            st.write(f"**Claimed Extension:** `{report['claimed_extension']}`")
                            st.write(f"**File Size:** {report['file_size_formatted']}")
                        with col_card2:
                            st.write(f"**Detected MIME:** `{report['detected_mime']}`")
                            st.write(f"**File Signature:** {report['detected_signature']}")
                            st.write(f"**Header Magic Bytes:** `{report['header_hex_preview']}`")
                        with col_card3:
                            st.write("**Attachment Risk Level:**")
                            st.markdown(get_badge_html(report['risk_level']), unsafe_allow_html=True)
                            st.caption(f"Score: {report['risk_score']} / 100")

                        st.markdown("**Suspicious Features Detected:**")
                        for feat in report["suspicious_features"]:
                            st.markdown(f"- {feat}")

                        st.markdown(f"**Recommended Action:** {report['recommended_action']}")
                        st.caption(f"🔒 {report['disclaimer']}")
            else:
                st.info("No attachments were provided with this message.")

            # URL Analysis Details
            if scan_output["url_analysis"]["count"] > 0:
                with st.expander(f"🔗 Scanned URLs ({scan_output['url_analysis']['count']})", expanded=False):
                    for u in scan_output["url_analysis"]["urls"]:
                        st.write(f"**URL:** `{u['url']}`")
                        st.write(f"- Hostname: `{u['hostname']}` | HTTPS: `{u['uses_https']}` | Raw IP: `{u['is_ip']}` | Shortener: `{u['is_shortener']}`")
                        st.caption(f"Risk Score: {u['risk_score']} / 100")
                        st.markdown("---")

            # Feedback System Section
            st.markdown("---")
            st.subheader("💬 User Classification Feedback")
            st.caption("Help improve detection accuracy. All feedback is logged locally in data/feedback.csv without recording email contents or passwords.")

            fb_col1, fb_col2, fb_col3 = st.columns([2, 3, 1.5])
            with fb_col1:
                feedback_choice = st.selectbox(
                    "Classification Assessment:",
                    ["Correct", "False Positive", "False Negative", "Unsure"]
                )
            with fb_col2:
                feedback_comment = st.text_input("Optional Comment / Forensic Notes:")
            with fb_col3:
                st.write("")
                st.write("")
                if st.button("Submit Feedback", type="secondary"):
                    saved = FeedbackSystem.record_feedback(
                        sample_id=sample_id,
                        predicted_score=overall_score,
                        predicted_level=overall_tier,
                        user_feedback=feedback_choice,
                        comment=feedback_comment
                    )
                    if saved:
                        st.success("Feedback recorded locally!")
                    else:
                        st.error("Failed to save feedback.")

# ==============================================================================
# SECTION 2: EVALUATION BENCHMARK DASHBOARD
# ==============================================================================
elif menu_selection == "📊 Evaluation Benchmark Dashboard":
    st.markdown('<div class="main-header">Automated Evaluation & Ground-Truth Benchmark</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Rigorous Multi-Vector Validation Across 12 Standardized Harmless Synthetic Test Scenarios</div>', unsafe_allow_html=True)

    st.markdown("""
    <div class="disclaimer-box">
        <strong>Benchmarking Transparency Notice:</strong><br>
        This dashboard executes the full deterministic static scoring engine against all 12 standardized reference scenarios.
        Samples without ground-truth labels are never counted in metrics. Results are dynamically computed and exported to <code>reports/evaluation_report.md</code>.
    </div>
    """, unsafe_allow_html=True)

    if st.button("🚀 Re-Run Evaluation Benchmark Suite", type="primary"):
        with st.spinner("Executing benchmark across all 12 test fixtures..."):
            metrics = EvaluationEngine.run_benchmark()
            st.session_state["benchmark_metrics"] = metrics
            st.success("Benchmark completed and reports/evaluation_report.md updated!")

    # Load cached or initial run
    if "benchmark_metrics" not in st.session_state:
        st.session_state["benchmark_metrics"] = EvaluationEngine.run_benchmark()

    metrics = st.session_state["benchmark_metrics"]
    cm = metrics["confusion_matrix"]

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Total Test Scenarios", metrics["total_samples"])
    with col2:
        st.metric("Accuracy", f"{metrics['accuracy']}%")
    with col3:
        st.metric("Precision", f"{metrics['precision']}%")
    with col4:
        st.metric("Recall (Sensitivity)", f"{metrics['recall']}%")
    with col5:
        st.metric("F1-Score", f"{metrics['f1_score']}%")

    st.markdown("---")
    st.subheader("🧮 Confusion Matrix")

    col_cm_table, col_cm_desc = st.columns([3, 2])
    with col_cm_table:
        cm_df = pd.DataFrame({
            "Predicted Legitimate": [f"{cm['tn']} (True Negative)", f"{cm['fn']} (False Negative)"],
            "Predicted Phishing": [f"{cm['fp']} (False Positive)", f"{cm['tp']} (True Positive)"]
        }, index=["Actual Legitimate", "Actual Phishing"])
        st.table(cm_df)

    with col_cm_desc:
        st.markdown("**Metric Definitions:**")
        st.markdown(f"- **True Negatives (TN):** {cm['tn']} (Correctly passed benign messages)")
        st.markdown(f"- **True Positives (TP):** {cm['tp']} (Correctly alerted on multi-vector phishing)")
        st.markdown(f"- **False Positives (FP):** {cm['fp']} (Benign messages falsely blocked)")
        st.markdown(f"- **False Negatives (FN):** {cm['fn']} (Phishing messages missed)")

    st.markdown("---")
    st.subheader("📋 Sample-by-Sample Benchmark Results")

    sample_rows = []
    for s in metrics["sample_details"]:
        sample_rows.append({
            "Scenario": s["name"],
            "Ground Truth": s["expected_label"],
            "Expected Tier": s["expected_risk"],
            "Predicted Score": f"{s['predicted_score']:.1f}",
            "Predicted Tier": s["predicted_tier"],
            "Prediction Status": s["status"]
        })
    df_samples = pd.DataFrame(sample_rows)
    st.dataframe(df_samples, use_container_width=True)

# ==============================================================================
# SECTION 3: USER FEEDBACK TELEMETRY
# ==============================================================================
elif menu_selection == "💬 User Feedback Telemetry":
    st.markdown('<div class="main-header">User Classification Feedback Telemetry</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Auditing Real-World Triage Accuracy & False Positive Submissions</div>', unsafe_allow_html=True)

    stats = FeedbackSystem.get_summary_stats()
    records = FeedbackSystem.get_feedback_records()

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Total User Submissions", stats["total_feedback_count"])
    with c2:
        st.metric("Correct Confirmations", stats["counts"].get("Correct", 0))
    with c3:
        st.metric("False Positive Flags", stats["counts"].get("False Positive", 0))
    with c4:
        st.metric("False Negative Flags", stats["counts"].get("False Negative", 0))

    st.markdown("---")
    st.subheader("📜 Recent Feedback Audit Log")
    if records:
        df_records = pd.DataFrame(records)
        st.dataframe(df_records, use_container_width=True)
    else:
        st.info("No feedback has been recorded yet. Submit feedback after scanning any email or scenario.")

# ==============================================================================
# SECTION 4: SCENARIO PLAYGROUND
# ==============================================================================
elif menu_selection == "🧪 Scenario Demo Playground":
    st.markdown('<div class="main-header">Harmless Reference Scenarios Catalog</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Inspection of the 12 Synthetically Modeled Threat Vectors</div>', unsafe_allow_html=True)

    scenarios = SampleGenerator.get_all_scenarios()
    for scen in scenarios:
        with st.expander(f"{scen['name']} — Expected: {scen['expected_label']} ({scen['expected_risk']} Risk)", expanded=False):
            st.markdown(f"**Security Heuristic Tested:** {scen['description']}")
            st.markdown("**Sample Email Text:**")
            st.code(scen["email_text"], language="text")
            if scen.get("attachments"):
                st.markdown("**Harmless Attachment Fixture(s):**")
                for fname, fbytes in scen["attachments"]:
                    st.write(f"- `{fname}` ({len(fbytes)} bytes, static non-executable byte fixture)")

# ==============================================================================
# SECTION 5: SECURITY GUIDELINES & ARCHITECTURE
# ==============================================================================
elif menu_selection == "📖 Security Precautions & Guidelines":
    st.markdown('<div class="main-header">Security Precautions & Architecture Guide</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Principles of Safe Attachment Handling, Zero-Execution Triage & Weight Governance</div>', unsafe_allow_html=True)

    st.markdown("""
    ### 🛡️ Safe Attachment Handling Architecture (Mission 2 & 3)

    1. **Zero Execution Mandate**:
       - The scanner **never calls `os.system`, `subprocess`, shell runners, or external rendering engines**.
       - Files are ingested strictly as binary byte arrays (`bytes`) in memory.

    2. **Disguised Executable Defense**:
       - Attackers frequently name Windows PE executables `invoice.pdf` or `photo.jpg`.
       - The scanner inspects byte offset 0–2 for `MZ` (`0x4D 0x5A`).
       - If an `MZ` header is detected inside a file claiming a non-executable extension (`.pdf`, `.docx`), an immediate **Critical Risk Override (>=85 pts)** is triggered.

    3. **Safe In-Memory ZIP Inspection**:
       - Standard unzipping to the filesystem introduces directory traversal (`Zip Slip`) and payload drop vulnerabilities.
       - The scanner inspects ZIP metadata strictly in memory via `io.BytesIO` and `zipfile.ZipFile.infolist()`.
       - **Decompression Bomb Protection**: Enforces entry limits (<500 files), maximum uncompressed ratio (<100:1), and total byte ceiling (<100MB).
       - **Encryption Detection**: Inspects header `flag_bits & 0x1`. If encrypted, labels member contents as **opaque to static inspection** without false claims of safety.

    4. **DOCX / Office Security**:
       - Validates OpenXML container structure (`[Content_Types].xml`).
       - Detects macro storage binaries (`word/vbaProject.bin`, `.docm`, `.xlsm`).
       - Analyzes `word/_rels/*.rels` for external remote template injection (`TargetMode="External"`).

    5. **Linguistic & URL Heuristic Calibration**:
       - **Urgency Words Alone Are Low Risk**: Real corporate work requires prompt deadlines. Urgency words alone receive negligible weight (+8 pts).
       - **Benign Long URLs Tolerated**: Legitimate cloud storage links (AWS S3, Azure Blob, Google Drive) have extensive query tokens. Standalone length does not inflate risk.
       - **Transparent Weight Renormalization**: If an email has no URLs or attachments, weights are dynamically rebalanced across available vectors so scores remain calibrated between 0 and 100.
    """)
