"""
Web Analysis Limits & Resource Constraints

Enforces strict boundaries on network operations, redirect hops,
payload sizes, and timeouts to ensure ScamBuster operates safely
and does not consume unbounded system or network resources.
"""

# Maximum redirect hops to follow
MAX_REDIRECTS = 10

# Maximum response size to read into memory for HTML/text analysis (2 MB)
MAX_RESPONSE_SIZE = 2 * 1024 * 1024

# Maximum payload size to stream for download inspection / APK analysis (15 MB)
MAX_DOWNLOAD_SIZE = 15 * 1024 * 1024

# Maximum number of resources / iframes / forms to extract from a single page
MAX_EXTRACTED_FORMS = 50
MAX_EXTRACTED_IFRAMES = 50
MAX_EXTRACTED_SCRIPTS = 100
MAX_EXTRACTED_LINKS = 200

# Network timeouts (in seconds)
DNS_TIMEOUT = 3.0
CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 8.0
TOTAL_SCAN_TIMEOUT = 20.0

# Scanner User-Agent identification
SCANNER_USER_AGENT = "ScamBusterSecurityScanner/1.0 (+https://scambuster.security; automated defensive security analysis)"
