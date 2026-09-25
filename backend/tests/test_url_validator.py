"""
Unit Tests for URL Validation (Phase 02)
"""

import pytest
from app.services.url_validator import validate_url, ensure_valid_url, UrlValidationError


def test_valid_https_url():
    is_valid, error = validate_url("https://example.com/login")
    assert is_valid is True
    assert error is None


def test_valid_http_url():
    is_valid, error = validate_url("http://sub.example.com:8080/test?query=1")
    assert is_valid is True
    assert error is None


def test_empty_and_whitespace_url():
    is_valid, error = validate_url("")
    assert is_valid is False
    assert "empty" in error.lower()

    is_valid, error = validate_url("   ")
    assert is_valid is False
    assert "empty" in error.lower()

    is_valid, error = validate_url(None)
    assert is_valid is False


def test_unsupported_schemes():
    unsupported = [
        "ftp://example.com/file.txt",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "data:text/html,<html>test</html>",
        "mailto:test@example.com",
        "ws://example.com/socket",
    ]
    for url in unsupported:
        is_valid, error = validate_url(url)
        assert is_valid is False, f"Expected {url} to be invalid"
        assert "not permitted" in error.lower() or "only 'http://' and 'https://'" in error.lower()


def test_extremely_long_url():
    long_url = "https://example.com/" + ("a" * 2050)
    is_valid, error = validate_url(long_url)
    assert is_valid is False
    assert "maximum" in error.lower()


def test_missing_scheme():
    is_valid, error = validate_url("example.com/login")
    assert is_valid is False
    assert "scheme" in error.lower()


def test_malformed_hostname():
    is_valid, error = validate_url("http://")
    assert is_valid is False
    assert "hostname" in error.lower()


def test_ensure_valid_url_raises():
    with pytest.raises(UrlValidationError):
        ensure_valid_url("javascript:alert(1)")

    # Should not raise for valid URL
    ensure_valid_url("https://secure.example.com")
