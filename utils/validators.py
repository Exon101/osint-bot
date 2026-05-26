"""
Input Validation Utilities
Sanitize and validate all user inputs.
"""

import re
import ipaddress


def sanitize_input(text: str, max_length: int = 512) -> str:
    """Strip dangerous characters, limit length."""
    if not text:
        return ""
    text = text.strip()
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    return text[:max_length]


def validate_ipv4(ip: str) -> bool:
    try:
        ipaddress.IPv4Address(ip)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def validate_ipv6(ip: str) -> bool:
    try:
        ipaddress.IPv6Address(ip)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def validate_ip(ip: str) -> bool:
    return validate_ipv4(ip) or validate_ipv6(ip)


def validate_domain(domain: str) -> bool:
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def validate_hash(hash_str: str) -> str:
    """Detect hash type. Returns type name or empty string."""
    h = hash_str.strip().lower()
    if re.fullmatch(r'[a-f0-9]{32}', h):
        return "MD5"
    if re.fullmatch(r'[a-f0-9]{40}', h):
        return "SHA-1"
    if re.fullmatch(r'[a-f0-9]{64}', h):
        return "SHA-256"
    if re.fullmatch(r'[a-f0-9]{128}', h):
        return "SHA-512"
    return ""


def validate_email(email: str) -> bool:
    pattern = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_cve(cve: str) -> bool:
    return bool(re.fullmatch(r'CVE-\d{4}-\d{4,}', cve, re.IGNORECASE))


def validate_port(port_str: str) -> int:
    try:
        port = int(port_str)
        return 1 <= port <= 65535
    except (ValueError, TypeError):
        return False


def validate_url(url: str) -> bool:
    """Check basic URL format."""
    pattern = r'^https?://[^\s/$.?#].[^\s]*$'
    return bool(re.match(pattern, url))


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private, loopback, link-local, or cloud metadata."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip == ipaddress.ip_address("169.254.169.254")  # cloud metadata
        )
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_url_safe_for_fetch(url: str) -> bool:
    """Validate a URL is safe to fetch — blocks private IPs and cloud metadata."""
    import urllib.parse
    if not validate_url(url):
        return False
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return False
    # Check if hostname is an IP address
    if is_private_ip(hostname):
        return False
    # Block common metadata endpoints
    blocked_hosts = {"metadata.google.internal", "metadata"}
    if hostname.lower() in blocked_hosts:
        return False
    return True
