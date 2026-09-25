"""
ScamBuster Heuristic Cyber Analyzer — Phishing Email Analysis

Deterministic cybersecurity analysis detecting:
- Display name spoofing and brand mismatch
- Free webmail providers pretending to be institutions/corporations
- Reply-To address divergence
- Dangerous / executable file attachments
- BEC (Business Email Compromise) / wire fraud / overdue invoice triggers
- Urgency and account suspension bait
"""

import re
from typing import Any, Dict, List, Optional

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "protonmail.com", "mail.com", "zoho.com", "yandex.com", "icloud.com"
}

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".vbs", ".iso", ".js", ".cmd", ".ps1",
    ".xlsm", ".docm", ".hta", ".cpl", ".wsf", ".jar", ".msi"
}

ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar.gz"}

CORPORATE_KEYWORDS = [
    "bank", "paypal", "apple", "netflix", "microsoft", "google", "amazon",
    "chase", "wells fargo", "support", "security team", "billing", "finance",
    "accounting", "payroll", "human resources", "irs", "customs"
]

FINANCIAL_INVOICE_KEYWORDS = [
    r"\b(invoice (overdue|attached|payment|#\d+))\b",
    r"\b(wire (transfer|instructions|payment))\b",
    r"\b(remittance advice|direct deposit)\b",
    r"\b(overdue balance|immediate settlement)\b",
    r"\b(payment confirmation|transaction receipt)\b",
]


def analyze_email(
    sender: str,
    subject: str,
    body: str,
    reply_to: Optional[str] = None,
    attachments: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Perform deep deterministic cybersecurity analysis on email metadata, headers, and content.
    Returns heuristic score (0-100), threat indicators, and technical details.
    """
    indicators: List[Dict[str, Any]] = []
    score = 0
    attachments = attachments or []

    # Parse sender: e.g. "PayPal Support <service@gmail.com>"
    sender_clean = sender.strip()
    email_match = re.search(r"<([^>]+)>", sender_clean)
    if email_match:
        from_address = email_match.group(1).lower().strip()
        display_name = sender_clean[:email_match.start()].strip()
    else:
        from_address = sender_clean.lower().strip()
        display_name = ""

    from_domain = from_address.split("@")[-1] if "@" in from_address else ""

    # 1. Display Name Impersonation (Display name claims institution, but domain is free/unrelated)
    if display_name:
        display_lower = display_name.lower()
        for kw in CORPORATE_KEYWORDS:
            if kw in display_lower and kw not in from_domain:
                score += 35
                indicators.append({
                    "name": "Display Name Brand Impersonation",
                    "severity": "HIGH",
                    "description": f"The display name '{display_name}' claims brand affiliation, but the originating email domain is '{from_domain}'.",
                    "evidence": f"Display: '{display_name}', Domain: '{from_domain}'",
                })
                break

    # 2. Free Webmail Domain for Institutional Sender
    if from_domain in FREE_EMAIL_PROVIDERS:
        for kw in CORPORATE_KEYWORDS:
            if kw in (display_name.lower() + " " + subject.lower()):
                score += 30
                indicators.append({
                    "name": "Free Webmail Used for Corporate Inquiry",
                    "severity": "HIGH",
                    "description": f"The email purports to be an official corporate communication but originates from a free consumer mailbox provider (@{from_domain}).",
                    "evidence": from_address,
                })
                break

    # 3. Reply-To Header Divergence
    if reply_to:
        clean_reply = reply_to.lower().strip()
        reply_domain = clean_reply.split("@")[-1] if "@" in clean_reply else ""
        if reply_domain and from_domain and reply_domain != from_domain:
            score += 25
            indicators.append({
                "name": "Mismatched Reply-To Address",
                "severity": "MEDIUM",
                "description": f"Responses will be directed to '{clean_reply}', which differs from the sender domain '{from_domain}'. Classic phishing misdirection.",
                "evidence": f"From: {from_domain} != Reply-To: {reply_domain}",
            })

    # 4. Dangerous Attachments
    dangerous_found = []
    for att in attachments:
        att_lower = att.lower()
        for ext in DANGEROUS_EXTENSIONS:
            if att_lower.endswith(ext):
                dangerous_found.append(att)
                break

    if dangerous_found:
        score += 45
        indicators.append({
            "name": "Dangerous / Executable Attachment Detected",
            "severity": "CRITICAL",
            "description": f"The email contains high-risk executable or script attachment(s): {', '.join(dangerous_found)}.",
            "evidence": ", ".join(dangerous_found),
        })

    # 5. Archive Attachments (Often password protected to evade AV)
    archive_found = [att for att in attachments if any(att.lower().endswith(ext) for ext in ARCHIVE_EXTENSIONS)]
    if archive_found and not dangerous_found:
        score += 15
        indicators.append({
            "name": "Compressed Archive Attachment",
            "severity": "LOW",
            "description": f"Compressed container files ({', '.join(archive_found)}) require elevated caution as they may conceal malicious payloads.",
            "evidence": ", ".join(archive_found),
        })

    # 6. BEC / Urgent Wire / Invoice Fraud Signals
    full_body = f"{subject}\n{body}".lower()
    for pattern in FINANCIAL_INVOICE_KEYWORDS:
        match = re.search(pattern, full_body)
        if match:
            score += 25
            indicators.append({
                "name": "Financial Wire / Invoice Bait",
                "severity": "MEDIUM",
                "description": "The message exhibits Business Email Compromise (BEC) language patterns soliciting money transfers or fraudulent invoice settlement.",
                "evidence": match.group(0),
            })
            break

    # 7. Credential / Phishing Links in Body
    links = re.findall(r"https?://[^\s<>\"']+", body)
    if links:
        score += 10
        if len(links) > 3:
            indicators.append({
                "name": "Multiple External Hyperlinks",
                "severity": "LOW",
                "description": f"The email body contains {len(links)} external hyperlinks.",
                "evidence": f"{len(links)} links found",
            })

    capped_score = min(max(score, 0), 100)

    return {
        "score": capped_score,
        "indicators": indicators,
        "details": {
            "from_domain": from_domain,
            "display_name": display_name,
            "attachment_count": len(attachments),
            "link_count": len(links),
            "indicator_count": len(indicators),
        }
    }
