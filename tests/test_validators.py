"""
Unit tests for the OSINT Bot validators module.
"""

import pytest
from utils.validators import (
    sanitize_input,
    validate_ipv4,
    validate_ipv6,
    validate_ip,
    validate_domain,
    validate_hash,
    validate_email,
    validate_cve,
    validate_port,
    validate_url,
)


class TestSanitizeInput:
    """Test input sanitization."""

    def test_basic_string(self):
        assert sanitize_input("hello world") == "hello world"

    def test_strip_whitespace(self):
        assert sanitize_input("  hello  ") == "hello"

    def test_remove_null_bytes(self):
        assert sanitize_input("hello\x00world") == "helloworld"

    def test_max_length(self):
        long_input = "A" * 1000
        result = sanitize_input(long_input, max_length=100)
        assert len(result) == 100

    def test_empty_input(self):
        assert sanitize_input("") == ""

    def test_none_input(self):
        assert sanitize_input(None) == ""

    def test_html_not_stripped(self):
        # sanitize_input does NOT strip HTML — that's intentional
        assert "<b>bold</b>" in sanitize_input("<b>bold</b>")


class TestValidateIPv4:
    """Test IPv4 validation."""

    def test_valid_public(self):
        assert validate_ipv4("8.8.8.8") is True

    def test_valid_private(self):
        assert validate_ipv4("192.168.1.1") is True

    def test_valid_localhost(self):
        assert validate_ipv4("127.0.0.1") is True

    def test_invalid(self):
        assert validate_ipv4("999.999.999.999") is False

    def test_empty(self):
        assert validate_ipv4("") is False

    def test_domain_instead(self):
        assert validate_ipv4("example.com") is False

    def test_with_port(self):
        assert validate_ipv4("8.8.8.8:443") is False


class TestValidateIPv6:
    """Test IPv6 validation."""

    def test_valid(self):
        assert validate_ipv6("::1") is True

    def test_valid_full(self):
        assert validate_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is True

    def test_invalid(self):
        assert validate_ipv6("not:valid:ipv6") is False


class TestValidateIP:
    """Test combined IP validation."""

    def test_ipv4(self):
        assert validate_ip("8.8.8.8") is True

    def test_ipv6(self):
        assert validate_ip("::1") is True

    def test_invalid(self):
        assert validate_ip("not.an.ip") is False


class TestValidateDomain:
    """Test domain validation."""

    def test_simple(self):
        assert validate_domain("example.com") is True

    def test_subdomain(self):
        assert validate_domain("api.example.com") is True

    def test_long_tld(self):
        assert validate_domain("example.co.uk") is True

    def test_with_hyphen(self):
        assert validate_domain("my-domain.com") is True

    def test_with_protocol(self):
        assert validate_domain("https://example.com") is False

    def test_empty(self):
        assert validate_domain("") is False

    def test_spaces(self):
        assert validate_domain("example .com") is False

    def test_ip_as_domain(self):
        assert validate_domain("192.168.1.1") is False


class TestValidateHash:
    """Test hash type detection."""

    def test_md5(self):
        assert validate_hash("5d41402abc4b2a76b9719d911017c592") == "MD5"

    def test_sha1(self):
        assert validate_hash("356a192b7913b04c54574d18c28d46e6395428ab") == "SHA-1"

    def test_sha256(self):
        assert validate_hash("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824") == "SHA-256"

    def test_sha512(self):
        result = validate_hash("9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043")
        assert result == "SHA-512"

    def test_unknown(self):
        assert validate_hash("notahash") == ""

    def test_empty(self):
        assert validate_hash("") == ""

    def test_uppercase(self):
        # Should handle uppercase input
        result = validate_hash("5D41402ABC4B2A76B9719D911017C592")
        assert result == "MD5"


class TestValidateEmail:
    """Test email validation."""

    def test_simple(self):
        assert validate_email("user@example.com") is True

    def test_with_subdomain(self):
        assert validate_email("user@mail.example.com") is True

    def test_with_plus(self):
        assert validate_email("user+tag@example.com") is True

    def test_with_dots(self):
        assert validate_email("first.last@example.com") is True

    def test_no_at(self):
        assert validate_email("userexample.com") is False

    def test_no_domain(self):
        assert validate_email("user@") is False

    def test_no_user(self):
        assert validate_email("@example.com") is False

    def test_empty(self):
        assert validate_email("") is False

    def test_double_at(self):
        assert validate_email("user@@example.com") is False


class TestValidateCVE:
    """Test CVE ID validation."""

    def test_valid(self):
        assert validate_cve("CVE-2024-1234") is True

    def test_valid_long(self):
        assert validate_cve("CVE-2024-123456") is True

    def test_lowercase(self):
        assert validate_cve("cve-2024-1234") is True

    def test_missing_prefix(self):
        assert validate_cve("2024-1234") is False

    def test_empty(self):
        assert validate_cve("") is False


class TestValidatePort:
    """Test port validation."""

    def test_valid_port(self):
        assert validate_port("80") is True

    def test_https(self):
        assert validate_port("443") is True

    def test_max_port(self):
        assert validate_port("65535") is True

    def test_zero(self):
        assert validate_port("0") is False

    def test_over_max(self):
        assert validate_port("65536") is False

    def test_negative(self):
        assert validate_port("-1") is False

    def test_not_number(self):
        assert validate_port("abc") is False

    def test_empty(self):
        assert validate_port("") is False


class TestValidateURL:
    """Test URL validation."""

    def test_https(self):
        assert validate_url("https://example.com") is True

    def test_http(self):
        assert validate_url("http://example.com") is True

    def test_with_path(self):
        assert validate_url("https://example.com/path") is True

    def test_no_protocol(self):
        assert validate_url("example.com") is False

    def test_ftp(self):
        assert validate_url("ftp://example.com") is False

    def test_empty(self):
        assert validate_url("") is False
