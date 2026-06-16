import re
from typing import Dict, Any, List
from pydantic import BaseModel, Field

class ScanResult(BaseModel):
    flagged: bool = Field(..., description="Whether this specific scan category triggered any alerts")
    score: int = Field(..., ge=0, le=100, description="Risk score for this category (0-100)")
    findings: List[str] = Field(default_factory=list, description="Specific identified items or patterns")
    details: str = Field(..., description="A narrative summary of the scan findings")

class AuditReport(BaseModel):
    payload_preview: str = Field(..., description="Short preview of the audited text")
    char_count: int = Field(..., description="Total characters analyzed")
    word_count: int = Field(..., description="Total words analyzed")
    risk_score: int = Field(..., ge=0, le=100, description="Overall aggregated risk score")
    risk_level: str = Field(..., description="Risk tier: Low, Medium, High, Critical")
    scans: Dict[str, ScanResult] = Field(..., description="Scan reports indexed by category")
    summary: str = Field(..., description="Overall auditor summary statement")

class NeuralAuditor:
    """
    Strategic Neural Auditor (AURA Core)
    Performs modular pattern matching, statistical profiling, and rule-based heuristics 
    to assess text payloads for misinformation, data leaks, security threats, and prompt injections.
    """
    
    def __init__(self):
        # Misinformation patterns
        self.misinfo_keywords = [
            (re.compile(r"\b(shocking truth|they don't want you to know|100% guaranteed miracle|scientists are silent|unverified proof|secret cure)\b", re.IGNORECASE), "Sensationalist clickbait conspiracy phrasing"),
            (re.compile(r"\b(miracle cure|magical remedy|reverse aging instantly|lose weight without dieting)\b", re.IGNORECASE), "Unsubstantiated medical/scientific claims"),
            (re.compile(r"\b(absolute proof|undeniable facts reveal|everyone knows that|without a doubt)\b", re.IGNORECASE), "Hyperbolic absolute assertions avoiding standard citations"),
            (re.compile(r"\b(forward this to everyone|viral warning|share before it's deleted|spread the word)\b", re.IGNORECASE), "Urgent viral distribution/chain letter hooks")
        ]

        # Security patterns
        self.security_patterns = [
            (re.compile(r"UNION\s+SELECT\s+", re.IGNORECASE), "SQL Injection: UNION SELECT pattern"),
            (re.compile(r"\b(DROP\s+TABLE|DELETE\s+FROM|INSERT\s+INTO|UPDATE\s+.*?\s+SET)\b", re.IGNORECASE), "SQL Injection: DDL/DML mutation attempts"),
            (re.compile(r"'\s+OR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", re.IGNORECASE), "SQL Injection: Tautology bypass pattern (e.g. ' OR 1=1)"),
            (re.compile(r"<\s*script[^>]*>", re.IGNORECASE), "Cross-Site Scripting (XSS): Script tags"),
            (re.compile(r"javascript\s*:\s*\S+", re.IGNORECASE), "Cross-Site Scripting (XSS): javascript: URI handler"),
            (re.compile(r"on\w+\s*=\s*['\"].*?['\"]", re.IGNORECASE), "Cross-Site Scripting (XSS): Event listener binding"),
            (re.compile(r"\.\./\.\./|\.\.\\\.\.\\", re.IGNORECASE), "Path Traversal: Parent directory navigation relative paths"),
            (re.compile(r"\b(etc/passwd|windows/win\.ini|system32/cmd\.exe)\b", re.IGNORECASE), "Path Traversal: Target OS core file references"),
            (re.compile(r"\b(rm\s+-rf|format\s+c:|mkfs|shutdown\s+-h|cmd\.exe\s+/c|/bin/sh|/bin/bash)\b", re.IGNORECASE), "System Command Injection command signatures")
        ]

        # Data Anomalies (leaks, structures, tokens)
        self.anomaly_patterns = [
            (re.compile(r"\b[A-Za-z0-9+/]{40,}\b"), "High entropy base64 block / possible encoded binary/token"),
            (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "UUID/GUID structure"),
            (re.compile(r"\b[A-Z0-9+_.-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE), "Exposed Email Address"),
            (re.compile(r"\b(AIzaSy[A-Za-z0-9_-]{33})\b"), "Google API Key signature"),
            (re.compile(r"\b(sk-proj-[A-Za-z0-9]{40,})\b"), "OpenAI API Key signature"),
            (re.compile(r"\b(xoxb-[0-9]{10,13}-[a-zA-Z0-9]{24})\b"), "Slack Token signature"),
            (re.compile(r"-----BEGIN\s+[A-Z ]+\s+PRIVATE\s+KEY-----"), "Cryptographic Private Key block"),
            (re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"), "Luhn-like 16-digit credit card pattern"),
            (re.compile(r"\b(mongodb(?:\+srv)?|postgres|mysql|redis):\/\/[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+@"), "Database connection URL containing credentials")
        ]

        # Adversarial Manipulation (Prompt Injection, Jailbreaking)
        self.adversarial_patterns = [
            (re.compile(r"\b(ignore\s+(?:all\s+)?previous\s+(?:instructions|directives|prompts))\b", re.IGNORECASE), "Direct instruction override (Jailbreak attempt)"),
            (re.compile(r"\b(you\s+are\s+now\s+(?:in\s+)?developer\s+mode|dan\s+mode|jailbroken)\b", re.IGNORECASE), "Persona enforcement / Developer mode bypass"),
            (re.compile(r"\b(bypass\s+safety\s+filters|override\s+guardrails)\b", re.IGNORECASE), "Direct command to ignore core alignment filters"),
            (re.compile(r"\b(system\s+prompt|system\s+instructions)\s+is\s+revealed\b", re.IGNORECASE), "System prompt exfiltration attempt"),
            (re.compile(r"\b(translate\s+this\s+but\s+ignore\s+rules|decode\s+and\s+execute)\b", re.IGNORECASE), "Instruction smuggling / indirect obfuscation"),
            (re.compile(r"<system>|\[system\]|=== SYSTEM ===", re.IGNORECASE), "System role spoofing delimiter injection")
        ]

    def audit(self, text: str) -> AuditReport:
        """
        Runs all scanners against the input text and computes risk metrics.
        """
        if not text:
            return AuditReport(
                payload_preview="Empty payload",
                char_count=0,
                word_count=0,
                risk_score=0,
                risk_level="Low",
                scans={
                    "misinformation": ScanResult(flagged=False, score=0, findings=[], details="No text submitted."),
                    "security": ScanResult(flagged=False, score=0, findings=[], details="No text submitted."),
                    "anomalies": ScanResult(flagged=False, score=0, findings=[], details="No text submitted."),
                    "adversarial": ScanResult(flagged=False, score=0, findings=[], details="No text submitted.")
                },
                summary="Audit completed for empty input. Risk is zero."
            )

        char_count = len(text)
        word_count = len(text.split())
        preview = text[:60] + "..." if char_count > 63 else text

        # 1. Misinformation Scan
        misinfo_findings = []
        for pattern, label in self.misinfo_keywords:
            matches = pattern.findall(text)
            if matches:
                misinfo_findings.append(f"{label} (found {len(matches)} instance(s))")
        
        misinfo_score = min(100, len(misinfo_findings) * 35)
        misinfo_flagged = len(misinfo_findings) > 0
        misinfo_details = (
            f"Flagged {len(misinfo_findings)} rhetorical misinformation pattern(s). Payload exhibits language typical of clickbait, unverified claims, or distribution requests."
            if misinfo_flagged else "Scan complete. No standard misinformation templates or sensationalized phrasings detected."
        )

        # 2. Security Scan
        security_findings = []
        for pattern, label in self.security_patterns:
            matches = pattern.findall(text)
            if matches:
                security_findings.append(f"{label}")
        
        # Security items are heavy risk triggers
        security_score = min(100, len(security_findings) * 50)
        security_flagged = len(security_findings) > 0
        security_details = (
            f"ALERT: Detected {len(security_findings)} severe security code pattern(s). The input contains signatures resembling SQL injection, cross-site scripting (XSS), or system commands."
            if security_flagged else "Scan complete. No standard SQL injection, script injections, path traversals, or shell execution sequences detected."
        )

        # 3. Anomaly Scan
        anomaly_findings = []
        for pattern, label in self.anomaly_patterns:
            matches = pattern.findall(text)
            if matches:
                anomaly_findings.append(f"{label} (detected {len(matches)} instance(s))")
        
        anomaly_score = min(100, len(anomaly_findings) * 30)
        anomaly_flagged = len(anomaly_findings) > 0
        anomaly_details = (
            f"Identified {len(anomaly_findings)} potential data anomalies or credential leak signatures. Structural formats match standard cryptographic keys, database connections, or common tokens."
            if anomaly_flagged else "Scan complete. No credential formats, base64 blobs, database configurations, or UUID patterns found."
        )

        # 4. Adversarial Scan
        adversarial_findings = []
        for pattern, label in self.adversarial_patterns:
            matches = pattern.findall(text)
            if matches:
                adversarial_findings.append(f"{label}")
        
        adversarial_score = min(100, len(adversarial_findings) * 45)
        adversarial_flagged = len(adversarial_findings) > 0
        adversarial_details = (
            f"CRITICAL: Identified {len(adversarial_findings)} instruction override attempt(s). Payload resembles adversarial prompt injection techniques targeting LLM alignment."
            if adversarial_flagged else "Scan complete. No prompt injection directives, system role spoofing, or guardrail override attempts detected."
        )

        # Compute Aggregated Risk Score
        # We weigh security and adversarial manipulations heavier
        weighted_score = (
            misinfo_score * 0.15 +
            anomaly_score * 0.20 +
            security_score * 0.35 +
            adversarial_score * 0.30
        )
        
        # Boost score if multiple domains are triggered
        categories_triggered = sum([misinfo_flagged, security_flagged, anomaly_flagged, adversarial_flagged])
        multiplier = 1.0 + (0.10 * max(0, categories_triggered - 1))
        final_score = min(100, int(weighted_score * multiplier))

        # Risk Classification
        if final_score >= 80:
            risk_level = "Critical"
        elif final_score >= 50:
            risk_level = "High"
        elif final_score >= 20:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        # Build Summary
        if categories_triggered == 0:
            summary = "Payload appears benign. No flags raised across security, data integrity, alignment, or information credibility scanners."
        else:
            summary = f"Audit complete. Raised flags in {categories_triggered} scanner category/categories. Action recommended: Review payload details before processing."

        return AuditReport(
            payload_preview=preview,
            char_count=char_count,
            word_count=word_count,
            risk_score=final_score,
            risk_level=risk_level,
            scans={
                "misinformation": ScanResult(
                    flagged=misinfo_flagged,
                    score=misinfo_score,
                    findings=misinfo_findings,
                    details=misinfo_details
                ),
                "security": ScanResult(
                    flagged=security_flagged,
                    score=security_score,
                    findings=security_findings,
                    details=security_details
                ),
                "anomalies": ScanResult(
                    flagged=anomaly_flagged,
                    score=anomaly_score,
                    findings=anomaly_findings,
                    details=anomaly_details
                ),
                "adversarial": ScanResult(
                    flagged=adversarial_flagged,
                    score=adversarial_score,
                    findings=adversarial_findings,
                    details=adversarial_details
                )
            },
            summary=summary
        )
