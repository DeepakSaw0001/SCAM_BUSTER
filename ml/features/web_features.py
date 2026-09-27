"""
ScamBuster ML — Web Risk Feature Extractor (Phase 09)

Extracts 24 consistent structural, redirect, response, and content features
from live web analysis results for machine learning inference.
"""

from typing import Any, Dict, List
import numpy as np

WEB_FEATURE_VERSION = "web-feat-v1.0"

WEB_FEATURE_NAMES = [
    "redirect_count",
    "cross_domain_count",
    "distinct_domain_count",
    "has_cross_domain",
    "domain_hopping",
    "loop_detected",
    "limit_reached",
    "shortener_detected",
    "meta_refresh_detected",
    "js_redirect_detected",
    "is_https",
    "missing_hsts",
    "missing_csp",
    "hardening_score",
    "form_count",
    "password_form_count",
    "payment_form_count",
    "has_credential_form",
    "iframe_count",
    "hidden_iframe_count",
    "cross_domain_iframe_count",
    "download_detected",
    "is_executable",
    "is_apk",
]


def extract_web_features(web_analysis: Dict[str, Any]) -> Dict[str, float]:
    """
    Extract a dictionary of named numerical features from a WebAnalysisResult.
    """
    redirects = web_analysis.get("redirects") or {}
    response = web_analysis.get("response") or {}
    content = web_analysis.get("content") or {}
    download = web_analysis.get("download") or {}
    sec_headers = (response.get("security_headers") or {}).get("present_headers") or {}

    features: Dict[str, float] = {
        "redirect_count": float(redirects.get("redirect_count", 0)),
        "cross_domain_count": float(redirects.get("cross_domain_count", 0)),
        "distinct_domain_count": float(redirects.get("distinct_domain_count", 1)),
        "has_cross_domain": 1.0 if redirects.get("has_cross_domain") else 0.0,
        "domain_hopping": 1.0 if redirects.get("domain_hopping") else 0.0,
        "loop_detected": 1.0 if redirects.get("loop_detected") else 0.0,
        "limit_reached": 1.0 if redirects.get("limit_reached") else 0.0,
        "shortener_detected": 1.0 if redirects.get("shortener_detected") else 0.0,
        "meta_refresh_detected": 1.0 if redirects.get("meta_refresh_detected") else 0.0,
        "js_redirect_detected": 1.0 if redirects.get("js_redirect_detected") else 0.0,
        "is_https": 1.0 if response.get("is_https", True) else 0.0,
        "missing_hsts": 0.0 if sec_headers.get("strict_transport_security") else 1.0,
        "missing_csp": 0.0 if sec_headers.get("content_security_policy") else 1.0,
        "hardening_score": float((response.get("security_headers") or {}).get("hardening_score", 50)),
        "form_count": float(content.get("form_count", 0)),
        "password_form_count": float(content.get("password_form_count", 0)),
        "payment_form_count": float(content.get("payment_form_count", 0)),
        "has_credential_form": 1.0 if content.get("has_credential_form") else 0.0,
        "iframe_count": float(content.get("iframe_count", 0)),
        "hidden_iframe_count": float(content.get("hidden_iframe_count", 0)),
        "cross_domain_iframe_count": float(content.get("cross_domain_iframe_count", 0)),
        "download_detected": 1.0 if download.get("download_detected") else 0.0,
        "is_executable": 1.0 if download.get("is_executable") else 0.0,
        "is_apk": 1.0 if download.get("is_apk") else 0.0,
    }

    return features


def extract_web_features_vector(web_analysis: Dict[str, Any]) -> np.ndarray:
    """
    Extract ordered numerical feature vector matching WEB_FEATURE_NAMES.
    """
    feat_dict = extract_web_features(web_analysis)
    return np.array([feat_dict[k] for k in WEB_FEATURE_NAMES], dtype=np.float32)
