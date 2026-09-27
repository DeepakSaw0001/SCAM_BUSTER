"""
Web Analysis Subsystem (Phase 09)

Provides safe HTTP fetching, SSRF defense, redirect chain tracking,
HTML content extraction, payload inspection, and APK handoff.
"""

from app.services.web_analysis.fetcher import perform_safe_web_analysis
from app.services.web_analysis.security_policy import (
    validate_web_fetch_url,
    resolve_and_validate_destination,
    is_ip_prohibited,
    is_hostname_prohibited,
)
from app.services.web_analysis.redirect_analyzer import (
    RedirectTracker,
    extract_registrable_domain,
)
from app.services.web_analysis.response_analyzer import (
    analyze_http_response,
    analyze_security_headers,
)
from app.services.web_analysis.content_analyzer import (
    analyze_html_content,
    SafeContentParser,
)
from app.services.web_analysis.download_analyzer import (
    inspect_download_metadata,
    analyze_downloaded_payload,
)

__all__ = [
    "perform_safe_web_analysis",
    "validate_web_fetch_url",
    "resolve_and_validate_destination",
    "is_ip_prohibited",
    "is_hostname_prohibited",
    "RedirectTracker",
    "extract_registrable_domain",
    "analyze_http_response",
    "analyze_security_headers",
    "analyze_html_content",
    "SafeContentParser",
    "inspect_download_metadata",
    "analyze_downloaded_payload",
]
