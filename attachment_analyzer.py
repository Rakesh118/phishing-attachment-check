"""
Safe Static Attachment Analyzer (Mission 2 & Mission 3)
Performs zero-execution, bounded heuristic inspection of attachments.
Never extracts files to disk, executes code, or runs external utilities.
"""

import os
import io
import re
import zipfile
from typing import Dict, List, Any, Tuple, Optional
from risk_engine import RiskIndicator

# Magic byte signatures
MAGIC_SIGNATURES = [
    (b"\x4D\x5A", "application/x-dosexec", "MZ Executable (Windows PE/DOS)"),
    (b"%PDF-", "application/pdf", "PDF Document"),
    (b"\x50\x4B\x03\x04", "application/zip", "ZIP Archive / Office Open XML"),
    (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "application/x-ole-storage", "Legacy OLE2 Compound Document (MS Office 97-2003)"),
    (b"\x37\x7A\xBC\xAF\x27\x1C", "application/x-7z-compressed", "7-Zip Archive"),
    (b"\x52\x61\x72\x21\x1A\x07", "application/vnd.rar", "RAR Archive (v5)"),
    (b"\x52\x61\x72\x21\x1A\x00", "application/vnd.rar", "RAR Archive (v4)"),
    (b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A", "image/png", "PNG Image"),
    (b"\xFF\xD8\xFF", "image/jpeg", "JPEG Image"),
    (b"GIF87a", "image/gif", "GIF Image"),
    (b"GIF89a", "image/gif", "GIF Image"),
    (b"\x7F\x45\x4C\x46", "application/x-executable", "ELF Executable (Linux/Unix)")
]

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".cpl", ".msi",
    ".iso", ".img", ".vhd", ".wsf", ".jar", ".pif", ".gadget"
}

MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm"}

# Max analysis bounds
MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB
MAX_ZIP_ENTRIES = 500
MAX_UNCOMPRESSED_RATIO = 100.0
MAX_UNCOMPRESSED_TOTAL = 100 * 1024 * 1024  # 100 MB


class AttachmentAnalyzer:
    @staticmethod
    def detect_magic_signature(content: bytes) -> Tuple[str, str, str]:
        """
        Detects MIME type and signature description from leading bytes.
        Returns: (mime_type, description, hex_header)
        """
        if not content:
            return "application/x-empty", "Empty File", ""

        header_hex = content[:8].hex().upper()
        for magic, mime, desc in MAGIC_SIGNATURES:
            if content.startswith(magic):
                return mime, desc, header_hex

        # Check for plain ASCII / HTML
        sample = content[:512]
        if sample.startswith(b"<!DOCTYPE") or sample.startswith(b"<html") or b"<body" in sample.lower():
            return "text/html", "HTML Document", header_hex
        try:
            sample.decode("utf-8")
            return "text/plain", "Plain Text File", header_hex
        except UnicodeDecodeError:
            return "application/octet-stream", "Unknown Binary Stream", header_hex

    @staticmethod
    def inspect_attachment(filename: str, content: bytes, context_has_pw: bool = False) -> Dict[str, Any]:
        """
        Statically inspects a single attachment.
        Produces full forensic report card and risk indicators.
        """
        indicators: List[RiskIndicator] = []
        suspicious_features: List[str] = []

        claimed_ext = os.path.splitext(filename)[1].lower() if filename else ""
        file_size = len(content)

        # 1. Bounds & Malformed check
        if file_size > MAX_FILE_SIZE:
            indicators.append(RiskIndicator(
                "attachment", f"Oversized Attachment ({filename})", 30.0,
                f"File size ({file_size / (1024*1024):.1f}MB) exceeds safe inspection limit (25MB).", "medium"
            ))
            suspicious_features.append("Oversized payload rejected from deep inspection")

        if file_size == 0:
            indicators.append(RiskIndicator(
                "attachment", f"Zero-Byte File ({filename})", 10.0,
                "Attachment contains zero bytes or is corrupted.", "low"
            ))
            return AttachmentAnalyzer._build_report_card(
                filename, claimed_ext, "application/x-empty", "Empty File", "",
                file_size, indicators, ["Zero-byte empty file"]
            )

        detected_mime, detected_desc, header_hex = AttachmentAnalyzer.detect_magic_signature(content)

        # 2. Dangerous extension check
        if claimed_ext in DANGEROUS_EXTENSIONS:
            indicators.append(RiskIndicator(
                "attachment", f"Dangerous File Extension ({claimed_ext})", 65.0,
                f"File uses executable or script extension '{claimed_ext}' capable of direct code execution.", "high"
            ))
            suspicious_features.append(f"Direct executable extension: {claimed_ext}")

        # 3. Double extension check (e.g. invoice.pdf.exe)
        name_parts = filename.lower().split(".")
        if len(name_parts) > 2:
            second_last = "." + name_parts[-2]
            if second_last in {".pdf", ".docx", ".xlsx", ".jpg", ".png", ".txt", ".csv"} and claimed_ext in DANGEROUS_EXTENSIONS:
                indicators.append(RiskIndicator(
                    "attachment", f"Deceptive Double Extension ({second_last + claimed_ext})", 85.0,
                    f"File disguises executable payload with deceptive document extension: '{filename}'.", "critical"
                ))
                suspicious_features.append(f"Deceptive double extension: {second_last + claimed_ext}")

        # 4. CRITICAL: Extension vs Magic Byte Mismatch (e.g. invoice.pdf with MZ executable header)
        if detected_mime == "application/x-dosexec":
            if claimed_ext not in {".exe", ".dll", ".sys", ".scr", ".cpl"}:
                indicators.append(RiskIndicator(
                    "attachment", f"Disguised Windows PE Executable ({claimed_ext} has MZ header)", 95.0,
                    f"CRITICAL: File named '{filename}' claims to be '{claimed_ext}', but its header begins with 'MZ' (Windows PE Executable).", "critical"
                ))
                suspicious_features.append("DISGUISED EXECUTABLE: MZ binary header inside non-executable filename")
            else:
                indicators.append(RiskIndicator(
                    "attachment", "Windows PE Executable Payload", 70.0,
                    f"File contains standard Windows PE executable binary (MZ signature).", "high"
                ))
                suspicious_features.append("MZ Windows PE Executable")

        # Extension mismatch for other file types
        if claimed_ext in {".pdf"} and detected_mime != "application/pdf" and detected_mime != "application/x-dosexec":
            indicators.append(RiskIndicator(
                "attachment", f"MIME Signature Mismatch ({filename})", 45.0,
                f"File claims PDF extension, but binary header does not match %PDF- signature (detected: {detected_desc}).", "medium"
            ))
            suspicious_features.append(f"PDF header mismatch: detected {detected_desc}")

        if claimed_ext in {".docx", ".xlsx", ".pptm", ".docm", ".xlsm"} and detected_mime not in {"application/zip", "application/x-ole-storage"}:
            indicators.append(RiskIndicator(
                "attachment", f"Office Format Mismatch ({filename})", 45.0,
                f"Office document does not contain valid PK zip or OLE2 container signature.", "medium"
            ))
            suspicious_features.append(f"Office container invalid: detected {detected_desc}")

        # 5. Unknown or unsupported format: marked inconclusive rather than automatically safe
        if detected_mime == "application/octet-stream" and claimed_ext not in DANGEROUS_EXTENSIONS:
            indicators.append(RiskIndicator(
                "attachment", f"Unrecognized Binary Signature ({filename})", 15.0,
                f"File binary header '{header_hex}' does not match recognized document, archive, or media formats. Static inspection inconclusive.", "low"
            ))
            suspicious_features.append(f"Inconclusive format: Unrecognized binary stream ({header_hex})")

        # 6. PDF Inspection (Static byte scan)
        if detected_mime == "application/pdf" or claimed_ext == ".pdf":
            pdf_indicators, pdf_features = AttachmentAnalyzer._inspect_pdf(content, filename)
            indicators.extend(pdf_indicators)
            suspicious_features.extend(pdf_features)

        # 7. ZIP Archive Inspection (Safe in-memory metadata reading)
        if detected_mime == "application/zip" or claimed_ext in {".zip", ".docx", ".docm", ".xlsx", ".xlsm", ".pptm"}:
            zip_indicators, zip_features = AttachmentAnalyzer._inspect_zip_or_office(
                content, filename, claimed_ext, context_has_pw
            )
            indicators.extend(zip_indicators)
            suspicious_features.extend(zip_features)

        # 8. Password mention in email correlation
        if context_has_pw and claimed_ext in {".zip", ".7z", ".rar"}:
            indicators.append(RiskIndicator(
                "attachment", "Password-Coordinated Archive Concealment", 20.0,
                "Email body specifies an archive password, a common evasion tactic to bypass automated gateway AV scanners.", "medium"
            ))
            suspicious_features.append("Archive coordinated with email password delivery")

        return AttachmentAnalyzer._build_report_card(
            filename, claimed_ext, detected_mime, detected_desc, header_hex,
            file_size, indicators, suspicious_features
        )

    @staticmethod
    def _inspect_pdf(content: bytes, filename: str) -> Tuple[List[RiskIndicator], List[str]]:
        indicators: List[RiskIndicator] = []
        features: List[str] = []

        if not content.startswith(b"%PDF-"):
            indicators.append(RiskIndicator(
                "attachment", f"Corrupted or Disguised PDF Header ({filename})", 35.0,
                "File lacks valid '%PDF-' start-of-file magic signature.", "medium"
            ))
            features.append("Missing %PDF- header")
            return indicators, features

        # Bounded search for suspicious PDF actions in raw bytes
        sample_bytes = content[:min(len(content), 5 * 1024 * 1024)]  # First 5MB
        suspicious_pdf_tokens = [
            (b"/JavaScript", "Embedded JavaScript Engine (/JavaScript)", 35.0, "high"),
            (b"/JS", "Embedded Scripting Object (/JS)", 30.0, "medium"),
            (b"/Launch", "Direct Executable Launch Action (/Launch)", 65.0, "high"),
            (b"/OpenAction", "Automated Execution on Open (/OpenAction)", 20.0, "medium"),
            (b"/EmbeddedFiles", "Embedded File Carrier (/EmbeddedFiles)", 25.0, "medium")
        ]

        for token, title, pts, sev in suspicious_pdf_tokens:
            if token in sample_bytes:
                indicators.append(RiskIndicator(
                    "attachment", f"PDF Action: {title}", pts,
                    f"PDF contains active document capability '{token.decode()}' frequently abused for automated exploitation.", sev
                ))
                features.append(f"PDF active element: {token.decode()}")

        return indicators, features

    @staticmethod
    def _inspect_zip_or_office(
        content: bytes, filename: str, claimed_ext: str, context_has_pw: bool
    ) -> Tuple[List[RiskIndicator], List[str]]:
        indicators: List[RiskIndicator] = []
        features: List[str] = []

        try:
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                infolist = zf.infolist()
                entry_count = len(infolist)

                # Check entry limits
                if entry_count > MAX_ZIP_ENTRIES:
                    indicators.append(RiskIndicator(
                        "attachment", f"Excessive Archive Member Count ({entry_count})", 30.0,
                        f"Archive contains {entry_count} entries, triggering archive bomb heuristic.", "medium"
                    ))
                    features.append(f"High member count: {entry_count}")

                is_encrypted = False
                total_uncompressed = 0
                dangerous_members = []
                has_macros = False
                external_rels = []

                for info in infolist:
                    total_uncompressed += info.file_size
                    # Bit 0 of flag_bits indicates encryption
                    if info.flag_bits & 0x1:
                        is_encrypted = True

                    fname_lower = info.filename.lower()
                    member_ext = os.path.splitext(fname_lower)[1]
                    if member_ext in DANGEROUS_EXTENSIONS:
                        dangerous_members.append(info.filename)

                    # Macro detection in Office XML
                    if "vbaproject.bin" in fname_lower or fname_lower.endswith(".vba") or "macros/" in fname_lower:
                        has_macros = True

                    # DOCX relationship checks (safe in-memory read of small XML rels)
                    if fname_lower.endswith(".rels") and not is_encrypted:
                        try:
                            rel_data = zf.read(info.filename)[:65536]
                            if b'TargetMode="External"' in rel_data:
                                external_rels.append(info.filename)
                        except Exception:
                            pass

                # Decompression bomb ratio check
                compressed_size = max(1, len(content))
                ratio = total_uncompressed / compressed_size
                if ratio > MAX_UNCOMPRESSED_RATIO and total_uncompressed > 10 * 1024 * 1024:
                    indicators.append(RiskIndicator(
                        "attachment", f"Decompression Bomb Ratio ({ratio:.1f}:1)", 50.0,
                        f"Uncompressed size ({total_uncompressed / (1024*1024):.1f}MB) vs archive size triggers zip bomb heuristic.", "high"
                    ))
                    features.append(f"Extreme compression ratio ({ratio:.1f}:1)")

                # Encrypted archive report
                if is_encrypted:
                    indicators.append(RiskIndicator(
                        "attachment", "Encrypted / Password-Protected Archive", 65.0,
                        "Archive is encrypted with a password. Member contents cannot be statically inspected without credentials.", "medium"
                    ))
                    features.append("Password-protected encrypted archive (contents opaque)")

                # Dangerous members inside archive
                if dangerous_members:
                    indicators.append(RiskIndicator(
                        "attachment", f"Executable Concealed in Archive ({len(dangerous_members)} files)", 75.0,
                        f"Archive conceals executable member(s): {', '.join(dangerous_members[:3])}.", "critical"
                    ))
                    features.append(f"Hidden executable inside archive: {', '.join(dangerous_members[:2])}")

                # Office Macro detection
                if claimed_ext in MACRO_EXTENSIONS or has_macros:
                    indicators.append(RiskIndicator(
                        "attachment", f"Macro-Enabled Office Document ({claimed_ext or 'vbaProject.bin'})", 55.0,
                        "Document contains embedded VBA macros or macro-enabled container structure.", "high"
                    ))
                    features.append("VBA Macro automation payload detected")

                # External template injection / relationship
                if external_rels:
                    indicators.append(RiskIndicator(
                        "attachment", "External OLE / Template Relationship Injection", 35.0,
                        "Office document references external remote relationship targets (often used in Follina or template injection).", "medium"
                    ))
                    features.append("External remote template relationship detected")

        except zipfile.BadZipFile:
            if claimed_ext in {".zip", ".docx", ".xlsx", ".pptx"}:
                indicators.append(RiskIndicator(
                    "attachment", f"Malformed Archive Structure ({filename})", 35.0,
                    "ZIP container is structurally malformed or truncated, commonly seen in weaponized evasion attempts.", "medium"
                ))
                features.append("Malformed / corrupted ZIP structure")
        except Exception as e:
            indicators.append(RiskIndicator(
                "attachment", f"Archive Parsing Exception ({filename})", 20.0,
                f"Error during static metadata parse: {str(e)[:100]}.", "low"
            ))
            features.append(f"Parsing error: {str(e)[:50]}")

        return indicators, features

    @staticmethod
    def _build_report_card(
        filename: str, claimed_ext: str, detected_mime: str, detected_desc: str,
        header_hex: str, file_size: int, indicators: List[RiskIndicator],
        suspicious_features: List[str]
    ) -> Dict[str, Any]:
        """Constructs standardized individual Attachment Report Card."""
        raw_score = sum(i.points for i in indicators)
        score = min(100.0, max(0.0, round(raw_score, 1)))

        # Tier assignment
        if score >= 80 or any(i.severity == "critical" for i in indicators):
            tier = "Critical"
            action = "CRITICAL RISK: Isolate immediately and do NOT open. High likelihood of disguised weaponized payload."
        elif score >= 55:
            tier = "High"
            action = "HIGH RISK: Quarantine attachment pending review. Potentially hazardous macro or executable payload."
        elif score >= 25:
            tier = "Medium"
            action = "MEDIUM RISK: Verify context and sender out-of-band before interacting. File shows atypical attributes."
        else:
            tier = "Low"
            action = "LOW RISK: Normal handling with standard caution. No overt malicious indicators found during static check."

        return {
            "filename": filename,
            "claimed_extension": claimed_ext or "(none)",
            "detected_mime": detected_mime,
            "detected_signature": detected_desc,
            "header_hex_preview": header_hex,
            "file_size_bytes": file_size,
            "file_size_formatted": f"{file_size / 1024:.1f} KB" if file_size < 1024*1024 else f"{file_size / (1024*1024):.2f} MB",
            "suspicious_features": suspicious_features if suspicious_features else ["No suspicious structural markers identified"],
            "evidence": [i.to_dict() for i in indicators],
            "risk_score": score,
            "risk_level": tier,
            "recommended_action": action,
            "disclaimer": "Static inspection only; dynamic runtime behavior is not evaluated. Always exercise standard caution."
        }
