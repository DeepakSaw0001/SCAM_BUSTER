"""
ScamBuster — Message Analysis Package (Phase 10)
"""

from app.services.message_analysis.normalizer import (
    NormalizedMessageData,
    detect_language,
    normalize_message_input,
)
from app.services.message_analysis.text_extractor import (
    ExtractedHTMLLink,
    ExtractedHTMLForm,
    SafeHTMLExtractionResult,
    evaluate_anchor_mismatch,
    extract_html_email_content,
)
from app.services.message_analysis.metadata_extractor import (
    HeaderAuthReport,
    SenderConsistencyReport,
    analyze_sender_consistency,
    parse_authentication_results,
)

__all__ = [
    "NormalizedMessageData",
    "detect_language",
    "normalize_message_input",
    "ExtractedHTMLLink",
    "ExtractedHTMLForm",
    "SafeHTMLExtractionResult",
    "evaluate_anchor_mismatch",
    "extract_html_email_content",
    "HeaderAuthReport",
    "SenderConsistencyReport",
    "analyze_sender_consistency",
    "parse_authentication_results",
]
