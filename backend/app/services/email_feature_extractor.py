"""
ScamBuster — Email Feature Extractor (Phase 05)

Extracts structured statistical, lexical, structural, and security features
from parsed email objects and preprocessed metadata.
"""

from dataclasses import asdict, dataclass
import re
from typing import Any, Dict, List

from app.services.email_parser import ParsedEmail
from app.services.email_preprocessor import PreprocessedEmailData


# Lexical patterns
URGENCY_KEYWORDS = [
    "urgent", "immediately", "immediate", "act now", "suspended", "suspension",
    "locked", "terminate", "deadline", "hours remaining", "within 24", "expir",
    "unauthorized", "action required", "critical alert", "warning", "compromised"
]

CREDENTIAL_KEYWORDS = [
    "password", "passcode", "login", "log in", "sign in", "verify account",
    "verification", "billing info", "social security", "ssn", "credentials",
    "security question", "authenticate", "confirm identity", "update details"
]

FINANCIAL_KEYWORDS = [
    "invoice", "wire transfer", "payment", "bank", "crypto", "bitcoin", "refund",
    "inheritance", "lottery", "prize", "cash", "million", "usd", "payout", "claim"
]


@dataclass
class EmailFeatures:
    # Text statistics
    subject_length: int
    body_length: int
    word_count: int
    line_count: int
    uppercase_ratio: float
    digit_ratio: float
    special_char_ratio: float

    # Keyword indicators
    urgency_keyword_count: int
    credential_keyword_count: int
    financial_keyword_count: int

    # Link features
    url_count: int
    unique_domain_count: int
    anchor_mismatch_count: int
    html_form_count: int
    html_hidden_element_count: int

    # Header & Domain relationships
    sender_replyto_mismatch: int
    received_hops_count: int
    spf_status: str
    dkim_status: str
    dmarc_status: str
    auth_failure_detected: int

    # Attachments
    attachment_count: int
    suspicious_attachment_count: int
    double_extension_count: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def extract_email_features(preprocessed: PreprocessedEmailData) -> EmailFeatures:
    """
    Compute structured statistical, lexical, link, header, and attachment features.
    """
    parsed = preprocessed.parsed_email
    body_text = preprocessed.clean_body_text
    subject_text = preprocessed.clean_subject_text

    combined_text = f"{subject_text} {body_text}".lower()

    # Text statistics
    char_count = len(body_text)
    words = re.findall(r"\b\w+\b", body_text)
    word_count = len(words)
    lines = [l for l in body_text.splitlines() if l.strip()]
    line_count = len(lines)

    upper_count = sum(1 for c in body_text if c.isupper())
    digit_count = sum(1 for c in body_text if c.isdigit())
    special_count = sum(1 for c in body_text if not c.isalnum() and not c.isspace())

    upper_ratio = round(upper_count / char_count, 4) if char_count > 0 else 0.0
    digit_ratio = round(digit_count / char_count, 4) if char_count > 0 else 0.0
    special_ratio = round(special_count / char_count, 4) if char_count > 0 else 0.0

    # Keyword counts
    urgency_count = sum(len(re.findall(rf"\b{re.escape(k)}\b", combined_text)) for k in URGENCY_KEYWORDS)
    credential_count = sum(len(re.findall(rf"\b{re.escape(k)}\b", combined_text)) for k in CREDENTIAL_KEYWORDS)
    financial_count = sum(len(re.findall(rf"\b{re.escape(k)}\b", combined_text)) for k in FINANCIAL_KEYWORDS)

    # Authentication failure detection
    auth = parsed.auth_results
    has_auth_fail = 1 if (
        auth.spf_status in ["fail", "softfail"] or
        auth.dkim_status == "fail" or
        auth.dmarc_status == "fail"
    ) else 0

    # Attachments
    susp_att_count = sum(1 for a in parsed.attachments if a.is_suspicious_extension)
    double_ext_count = sum(1 for a in parsed.attachments if a.is_double_extension)

    return EmailFeatures(
        subject_length=len(subject_text),
        body_length=char_count,
        word_count=word_count,
        line_count=line_count,
        uppercase_ratio=upper_ratio,
        digit_ratio=digit_ratio,
        special_char_ratio=special_ratio,
        urgency_keyword_count=urgency_count,
        credential_keyword_count=credential_count,
        financial_keyword_count=financial_count,
        url_count=len(preprocessed.extracted_urls),
        unique_domain_count=len(preprocessed.unique_domains),
        anchor_mismatch_count=len(preprocessed.anchor_mismatches),
        html_form_count=preprocessed.html_form_count,
        html_hidden_element_count=preprocessed.html_hidden_element_count,
        sender_replyto_mismatch=1 if preprocessed.has_sender_replyto_mismatch else 0,
        received_hops_count=parsed.received_hops_count,
        spf_status=auth.spf_status,
        dkim_status=auth.dkim_status,
        dmarc_status=auth.dmarc_status,
        auth_failure_detected=has_auth_fail,
        attachment_count=len(parsed.attachments),
        suspicious_attachment_count=susp_att_count,
        double_extension_count=double_ext_count,
    )
