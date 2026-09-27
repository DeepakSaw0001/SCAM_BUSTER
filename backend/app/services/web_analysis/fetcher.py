"""
Safe Web Fetcher & Web Analysis Orchestrator

Coordinates safe, policy-governed outbound HTTP fetching.
Enforces SSRF prevention, DNS rebinding checks, redirect tracking,
content inspection, payload extraction, and limitation disclaimers.
"""

import asyncio
from typing import Any, Dict, Optional
import httpx
import urllib.parse

from app.services.web_analysis.limits import (
    CONNECT_TIMEOUT,
    MAX_DOWNLOAD_SIZE,
    MAX_REDIRECTS,
    MAX_RESPONSE_SIZE,
    READ_TIMEOUT,
    SCANNER_USER_AGENT,
    TOTAL_SCAN_TIMEOUT,
)
from app.services.web_analysis.security_policy import validate_web_fetch_url
from app.services.web_analysis.redirect_analyzer import RedirectTracker
from app.services.web_analysis.response_analyzer import analyze_http_response
from app.services.web_analysis.content_analyzer import analyze_html_content
from app.services.web_analysis.download_analyzer import (
    inspect_download_metadata,
    analyze_downloaded_payload,
)


LIMITATION_DISCLAIMER = (
    "IMPORTANT LIMITATION: Static website and redirect analysis evaluates HTTP headers, server responses, "
    "HTML forms, and downloaded payloads. The scanner does NOT execute client-side JavaScript, submit credentials, "
    "or bypass authentication. Absence of detected threats does not guarantee benevolence."
)


async def perform_safe_web_analysis(url: str) -> Dict[str, Any]:
    """
    Execute full safe web analysis pipeline on the target URL.
    Returns structured analysis dictionary adhering to ScamBuster schema.
    """
    clean_url = url.strip()
    if not clean_url.startswith(("http://", "https://")):
        clean_url = "https://" + clean_url

    # 1. Initial SSRF Security Gate
    is_safe, ssrf_error, parsed_url, resolved_ips = validate_web_fetch_url(clean_url)
    if not is_safe:
        return {
            "status": "blocked",
            "failure_reason": f"SSRF Security Violation: {ssrf_error}",
            "original_url": clean_url,
            "final_url": clean_url,
            "resolved_ips": resolved_ips,
            "redirects": {
                "count": 0,
                "cross_domain_count": 0,
                "has_cross_domain": False,
                "domain_hopping": False,
                "loop_detected": False,
                "limit_reached": False,
                "shortener_detected": False,
                "chain": [],
            },
            "response": None,
            "content": None,
            "download": None,
            "limitation_disclaimer": LIMITATION_DISCLAIMER,
        }

    tracker = RedirectTracker(clean_url)
    current_url = clean_url
    redirect_count = 0
    final_response_headers: Dict[str, str] = {}
    final_status_code = 0
    final_body_bytes = b""
    stop_reason: Optional[str] = None

    client_headers = {
        "User-Agent": SCANNER_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "identity",  # Keep uncompressed or let httpx handle gzip
        "Connection": "close",
    }

    try:
        async with httpx.AsyncClient(
            verify=True,
            timeout=httpx.Timeout(READ_TIMEOUT, connect=CONNECT_TIMEOUT),
            headers=client_headers,
            follow_redirects=False,  # Handle redirects manually to validate each hop
        ) as client:

            while redirect_count <= MAX_REDIRECTS:
                # Validate current hop against SSRF before making request
                is_safe_hop, hop_error, _, _ = validate_web_fetch_url(current_url)
                if not is_safe_hop:
                    stop_reason = f"Redirect to prohibited destination blocked (SSRF): {hop_error}"
                    break

                try:
                    resp = await client.get(current_url)
                except httpx.ConnectTimeout:
                    stop_reason = "Connection timeout reaching server"
                    break
                except httpx.ReadTimeout:
                    stop_reason = "Read timeout awaiting response payload"
                    break
                except httpx.ConnectError as e:
                    stop_reason = f"Connection failed: {str(e)}"
                    break
                except Exception as e:
                    stop_reason = f"Network transport error: {str(e)}"
                    break

                final_status_code = resp.status_code
                final_response_headers = dict(resp.headers)

                # Check if this is an HTTP redirect (3xx)
                if resp.status_code in (301, 302, 303, 307, 308) and "location" in resp.headers:
                    target_candidate = resp.headers["location"]
                    continue_redirect, reason = tracker.add_hop(
                        from_url=current_url,
                        to_url=target_candidate,
                        status_code=resp.status_code,
                        redirect_type=f"HTTP_{resp.status_code}",
                    )

                    redirect_count += 1
                    if redirect_count > MAX_REDIRECTS:
                        tracker.limit_reached = True
                        stop_reason = f"Maximum redirect limit reached ({MAX_REDIRECTS} hops)"
                        break

                    if not continue_redirect:
                        stop_reason = reason
                        break

                    current_url = urllib.parse.urljoin(current_url, target_candidate)
                    continue

                # Terminal non-redirect response received
                # Read content safely with cap
                content_chunks = []
                bytes_read = 0
                async for chunk in resp.aiter_bytes():
                    content_chunks.append(chunk)
                    bytes_read += len(chunk)
                    if bytes_read >= MAX_DOWNLOAD_SIZE:
                        break

                final_body_bytes = b"".join(content_chunks)
                break

    except asyncio.TimeoutError:
        stop_reason = "Total scan timeout exceeded"
    except Exception as e:
        stop_reason = f"Analysis execution exception: {str(e)}"

    # If aborted before any response
    if final_status_code == 0:
        return {
            "status": "failed",
            "failure_reason": stop_reason or "Unknown network error",
            "original_url": clean_url,
            "final_url": current_url,
            "redirects": tracker.get_summary(current_url),
            "response": None,
            "content": None,
            "download": None,
            "limitation_disclaimer": LIMITATION_DISCLAIMER,
        }

    # 4. Analyze HTTP Response & TLS
    response_analysis = analyze_http_response(
        status_code=final_status_code,
        headers=final_response_headers,
        final_url=current_url,
    )

    # 5. Inspect for File Download
    download_meta = inspect_download_metadata(
        url=current_url,
        headers=final_response_headers,
        initial_bytes=final_body_bytes[:64],
    )

    download_result = None
    if download_meta["download_detected"]:
        download_result = analyze_downloaded_payload(
            file_bytes=final_body_bytes,
            meta=download_meta,
            source_url=current_url,
        )

    # 6. Analyze HTML Content (if response is HTML/text)
    content_analysis = None
    content_type_lower = final_response_headers.get("content-type", "").lower()
    is_html_or_text = (
        "text/html" in content_type_lower
        or "application/xhtml" in content_type_lower
        or (not download_meta["download_detected"] and ("text/" in content_type_lower or content_type_lower == ""))
    )

    if is_html_or_text and final_body_bytes:
        # Decode safely
        encoding = "utf-8"
        try:
            html_text = final_body_bytes[:MAX_RESPONSE_SIZE].decode(encoding, errors="replace")
        except Exception:
            html_text = final_body_bytes[:MAX_RESPONSE_SIZE].decode("latin-1", errors="replace")

        # Check for HTML meta refresh or JS redirects
        html_redirect = tracker.analyze_html_redirects(html_text, current_url)
        content_analysis = analyze_html_content(html_text, current_url)

    redirects_summary = tracker.get_summary(current_url)

    return {
        "status": "completed",
        "original_url": clean_url,
        "final_url": current_url,
        "redirects": redirects_summary,
        "response": response_analysis,
        "content": content_analysis,
        "download": download_result,
        "resolved_ips": resolved_ips,
        "limitation_disclaimer": LIMITATION_DISCLAIMER,
    }
