"""
ScamBuster — Email Parser Service (Phase 05)

Standard RFC-822 / MIME email parser using Python's standard library.
Safely extracts headers, authentication records (SPF, DKIM, DMARC),
body parts (plain text & HTML), sender/reply-to domain relationships,
and attachment metadata.

Security Principles:
- Headers are untrusted evidence, not cryptographic truth.
- Zero network requests (no DNS or remote image lookups).
- Safe parsing: gracefully handles malformed MIME, nested boundaries, and character encodings.
"""

from dataclasses import dataclass, field
import email
from email import policy
from email.utils import parseaddr
import re
from typing import Any, Dict, List, Optional, Tuple


SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf",
    ".hta", ".cpl", ".jar", ".iso", ".img", ".pif", ".msi", ".reg"
}

DOUBLE_EXTENSION_PATTERN = re.compile(
    r"\.[a-zA-Z0-9]{2,5}\.(exe|scr|bat|cmd|ps1|vbs|js|hta|msi|pif)$",
    re.IGNORECASE
)


@dataclass
class AttachmentMetadata:
    filename: str
    extension: str
    mime_type: str
    size_bytes: int
    is_suspicious_extension: bool
    is_double_extension: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "filename": self.filename,
            "extension": self.extension,
            "mime_type": self.mime_type,
            "size_bytes": self.size_bytes,
            "is_suspicious_extension": self.is_suspicious_extension,
            "is_double_extension": self.is_double_extension,
        }


@dataclass
class AuthResults:
    spf_status: str = "unknown"  # pass, fail, softfail, neutral, none, temperror, permerror, unknown
    spf_details: Optional[str] = None
    dkim_status: str = "unknown"
    dkim_details: Optional[str] = None
    dmarc_status: str = "unknown"
    dmarc_details: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "spf": {"status": self.spf_status, "details": self.spf_details},
            "dkim": {"status": self.dkim_status, "details": self.dkim_details},
            "dmarc": {"status": self.dmarc_status, "details": self.dmarc_details},
        }


@dataclass
class ParsedEmail:
    subject: str
    sender_raw: str
    sender_address: str
    sender_domain: str
    sender_display_name: str

    reply_to_raw: Optional[str]
    reply_to_address: Optional[str]
    reply_to_domain: Optional[str]

    to_recipients: List[str]
    cc_recipients: List[str]
    date: Optional[str]
    message_id: Optional[str]

    received_hops_count: int
    received_servers: List[str]

    auth_results: AuthResults

    body_plain: str
    body_html: str
    body_text: str  # Consolidated normalized text for analysis

    attachments: List[AttachmentMetadata] = field(default_factory=list)
    is_malformed: bool = False
    raw_size_bytes: int = 0


def _extract_domain(email_str: str) -> str:
    """Extract lowercase domain from an email address or string."""
    if not email_str:
        return ""
    _, addr = parseaddr(email_str)
    target = addr if addr else email_str
    if "@" in target:
        return target.split("@")[-1].strip().lower()
    return ""


def _parse_authentication_headers(msg: email.message.EmailMessage) -> AuthResults:
    """
    Parse reported SPF, DKIM, and DMARC results from available email headers.
    Distinguishes reported header strings as analytical evidence, not absolute verification.
    """
    auth = AuthResults()

    # 1. Inspect 'Authentication-Results' header
    auth_results_headers = msg.get_all("Authentication-Results", [])
    combined_auth = " ; ".join(str(h) for h in auth_results_headers).lower()

    # Parse SPF
    if "spf=" in combined_auth:
        m = re.search(r"spf=([a-z]+)", combined_auth)
        if m:
            auth.spf_status = m.group(1)
            auth.spf_details = f"Reported in Authentication-Results: spf={m.group(1)}"
    elif msg.get("Received-SPF"):
        spf_header = str(msg.get("Received-SPF", "")).lower()
        for status in ["pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"]:
            if spf_header.startswith(status) or f" {status} " in spf_header:
                auth.spf_status = status
                auth.spf_details = f"Reported in Received-SPF: {status}"
                break

    # Parse DKIM
    if "dkim=" in combined_auth:
        m = re.search(r"dkim=([a-z]+)", combined_auth)
        if m:
            auth.dkim_status = m.group(1)
            auth.dkim_details = f"Reported in Authentication-Results: dkim={m.group(1)}"
    elif msg.get("DKIM-Signature"):
        # Header exists, but verification status depends on receiving MTA
        if auth.dkim_status == "unknown":
            auth.dkim_status = "none"
            auth.dkim_details = "DKIM-Signature present; receiving MTA results not recorded."

    # Parse DMARC
    if "dmarc=" in combined_auth:
        m = re.search(r"dmarc=([a-z]+)", combined_auth)
        if m:
            auth.dmarc_status = m.group(1)
            auth.dmarc_details = f"Reported in Authentication-Results: dmarc={m.group(1)}"

    return auth


def _parse_attachments(msg: email.message.EmailMessage) -> List[AttachmentMetadata]:
    """Extract metadata for attachments without executing or loading malicious payload binaries."""
    attachments = []
    if not msg.is_multipart():
        return attachments

    for part in msg.walk():
        content_disposition = str(part.get("Content-Disposition", ""))
        content_type = str(part.get_content_type() or "")
        filename = part.get_filename()

        if "attachment" in content_disposition or (filename and "inline" not in content_disposition):
            safe_filename = str(filename or "unnamed_attachment").strip()
            # Clean filename from path traversal attempt
            safe_filename = safe_filename.replace("\\", "/").split("/")[-1]

            # Extension detection
            ext_match = re.search(r"(\.[a-zA-Z0-9_\-]+)$", safe_filename)
            extension = ext_match.group(1).lower() if ext_match else ""

            is_suspicious = extension in SUSPICIOUS_EXTENSIONS
            is_double = bool(DOUBLE_EXTENSION_PATTERN.search(safe_filename))

            # Payload size approximation
            payload = part.get_payload(decode=True)
            size = len(payload) if payload else 0

            attachments.append(
                AttachmentMetadata(
                    filename=safe_filename,
                    extension=extension,
                    mime_type=content_type,
                    size_bytes=size,
                    is_suspicious_extension=is_suspicious,
                    is_double_extension=is_double,
                )
            )

    return attachments


def _strip_html_tags(html: str) -> str:
    """Safely strip HTML markup to plain text for NLP feature extraction."""
    if not html:
        return ""
    text = re.sub(r"(?is)<style.*?</style>", " ", html)
    text = re.sub(r"(?is)<script.*?</script>", " ", text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"&nbsp;", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"&amp;", "&", text, flags=re.IGNORECASE)
    text = re.sub(r"&lt;", "<", text, flags=re.IGNORECASE)
    text = re.sub(r"&gt;", ">", text, flags=re.IGNORECASE)
    text = re.sub(r"&quot;", '"', text, flags=re.IGNORECASE)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def parse_raw_email(raw_content: str) -> ParsedEmail:
    """
    Parse raw email text (RFC-822 or MIME structure) into structured ParsedEmail.
    Handles plain text, multipart, HTML, and malformed emails gracefully.
    """
    raw_size = len(raw_content.encode("utf-8", errors="replace"))
    is_malformed = False

    try:
        msg = email.message_from_string(raw_content, policy=policy.default)
    except Exception:
        try:
            msg = email.message_from_string(raw_content, policy=policy.compat32)
            is_malformed = True
        except Exception:
            is_malformed = True
            msg = email.message_from_string(
                f"Subject: Unparseable Email\nFrom: unknown@unknown\n\n{raw_content}",
                policy=policy.compat32,
            )

    # 1. Headers Extraction
    subject = str(msg.get("Subject", "") or "").strip()

    from_header = str(msg.get("From", "") or "").strip()
    sender_name, sender_addr = parseaddr(from_header)
    sender_domain = _extract_domain(sender_addr or from_header)

    reply_to_header = msg.get("Reply-To")
    if reply_to_header:
        reply_to_raw = str(reply_to_header).strip()
        _, reply_to_addr = parseaddr(reply_to_raw)
        reply_to_domain = _extract_domain(reply_to_addr or reply_to_raw)
    else:
        reply_to_raw = None
        reply_to_address = None
        reply_to_domain = None

    to_headers = [str(t).strip() for t in msg.get_all("To", [])]
    cc_headers = [str(c).strip() for c in msg.get_all("Cc", [])]
    date_header = str(msg.get("Date", "") or "").strip() or None
    message_id = str(msg.get("Message-ID", "") or "").strip() or None

    # Received chain
    received_headers = [str(r).strip() for r in msg.get_all("Received", [])]
    received_hops_count = len(received_headers)

    # Authentication headers
    auth_results = _parse_authentication_headers(msg)

    # 2. Body Extraction
    plain_parts = []
    html_parts = []

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            cdisp = str(part.get("Content-Disposition", ""))
            if "attachment" in cdisp:
                continue

            try:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    decoded = payload.decode(charset, errors="replace")
                    if ctype == "text/plain":
                        plain_parts.append(decoded)
                    elif ctype == "text/html":
                        html_parts.append(decoded)
            except Exception:
                continue
    else:
        try:
            payload = msg.get_payload(decode=True)
            ctype = msg.get_content_type()
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                decoded = payload.decode(charset, errors="replace")
                if ctype == "text/html":
                    html_parts.append(decoded)
                else:
                    plain_parts.append(decoded)
            else:
                raw_payload = str(msg.get_payload() or "")
                if ctype == "text/html":
                    html_parts.append(raw_payload)
                else:
                    plain_parts.append(raw_payload)
        except Exception:
            plain_parts.append(str(msg.get_payload() or ""))

    body_plain = "\n".join(plain_parts).strip()
    body_html = "\n".join(html_parts).strip()

    # Form normalized body text
    if body_plain:
        body_text = body_plain
    elif body_html:
        body_text = _strip_html_tags(body_html)
    else:
        # Fallback if body is directly the string
        body_text = _strip_html_tags(raw_content)

    # 3. Attachments Extraction
    attachments = _parse_attachments(msg)

    return ParsedEmail(
        subject=subject,
        sender_raw=from_header,
        sender_address=sender_addr,
        sender_domain=sender_domain,
        sender_display_name=sender_name,
        reply_to_raw=reply_to_raw,
        reply_to_address=reply_to_addr if reply_to_header else None,
        reply_to_domain=reply_to_domain,
        to_recipients=to_headers,
        cc_recipients=cc_headers,
        date=date_header,
        message_id=message_id,
        received_hops_count=received_hops_count,
        received_servers=received_headers[:5],  # top 5 hops
        auth_results=auth_results,
        body_plain=body_plain,
        body_html=body_html,
        body_text=body_text,
        attachments=attachments,
        is_malformed=is_malformed,
        raw_size_bytes=raw_size,
    )


def parse_structured_email(
    subject: str,
    sender: str,
    body: str,
    reply_to: Optional[str] = None,
    attachments: Optional[List[str]] = None,
) -> ParsedEmail:
    """
    Construct a ParsedEmail object from structured input fields (e.g. JSON API request).
    """
    sender_name, sender_addr = parseaddr(sender)
    sender_domain = _extract_domain(sender_addr or sender)

    reply_to_addr = None
    reply_to_domain = None
    if reply_to:
        _, reply_to_addr = parseaddr(reply_to)
        reply_to_domain = _extract_domain(reply_to_addr or reply_to)

    # Parse attachment filenames
    att_meta_list = []
    if attachments:
        for att in attachments:
            clean_name = str(att).strip().replace("\\", "/").split("/")[-1]
            ext_match = re.search(r"(\.[a-zA-Z0-9_\-]+)$", clean_name)
            ext = ext_match.group(1).lower() if ext_match else ""
            is_suspicious = ext in SUSPICIOUS_EXTENSIONS
            is_double = bool(DOUBLE_EXTENSION_PATTERN.search(clean_name))
            att_meta_list.append(
                AttachmentMetadata(
                    filename=clean_name,
                    extension=ext,
                    mime_type="application/octet-stream",
                    size_bytes=0,
                    is_suspicious_extension=is_suspicious,
                    is_double_extension=is_double,
                )
            )

    # Clean body text
    body_text = _strip_html_tags(body) if ("<html" in body.lower() or "<p" in body.lower()) else body

    return ParsedEmail(
        subject=subject,
        sender_raw=sender,
        sender_address=sender_addr or sender,
        sender_domain=sender_domain,
        sender_display_name=sender_name,
        reply_to_raw=reply_to,
        reply_to_address=reply_to_addr,
        reply_to_domain=reply_to_domain,
        to_recipients=[],
        cc_recipients=[],
        date=None,
        message_id=None,
        received_hops_count=0,
        received_servers=[],
        auth_results=AuthResults(),
        body_plain=body if "<html" not in body.lower() else "",
        body_html=body if "<html" in body.lower() else "",
        body_text=body_text,
        attachments=att_meta_list,
        is_malformed=False,
        raw_size_bytes=len(body.encode("utf-8", errors="replace")),
    )
