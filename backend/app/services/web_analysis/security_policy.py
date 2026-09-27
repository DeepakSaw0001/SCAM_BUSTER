"""
SSRF & Web Fetch Security Policy

Implements defense-in-depth protection against Server-Side Request Forgery (SSRF),
DNS rebinding, private network access, cloud metadata exfiltration, and local service attacks.

Never allows requests to internal networks, localhost, or reserved IP spaces.
"""

import ipaddress
import re
import socket
import urllib.parse
from typing import List, Optional, Set, Tuple

# Prohibited hostnames and suffixes
PROHIBITED_HOSTNAMES: Set[str] = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
    "169.254.169.254",
}

PROHIBITED_SUFFIXES: Tuple[str, ...] = (
    ".local",
    ".localhost",
    ".internal",
    ".lan",
    ".home",
    ".corp",
    ".intranet",
    ".private",
    ".test",
    ".example",
    ".invalid",
)

# Additional specifically prohibited IP networks
PROHIBITED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network (RFC 1122)
    ipaddress.ip_network("10.0.0.0/8"),         # Private-use (RFC 1918)
    ipaddress.ip_network("100.64.0.0/10"),      # Shared Address Space (RFC 6598)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback (RFC 1122)
    ipaddress.ip_network("169.254.0.0/16"),     # Link Local (RFC 3927) & AWS/Cloud Metadata
    ipaddress.ip_network("172.16.0.0/12"),      # Private-use (RFC 1918)
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments (RFC 6890)
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("192.168.0.0/16"),     # Private-use (RFC 1918)
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmarking (RFC 2544)
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3 (RFC 5737)
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast (RFC 5771)
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved (RFC 1112)
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    # IPv6
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped IPv6
    ipaddress.ip_network("64:ff9b::/96"),       # IPv4/IPv6 translation
    ipaddress.ip_network("100::/64"),           # Discard prefix
    ipaddress.ip_network("2001::/23"),          # IETF Protocol Assignments
    ipaddress.ip_network("2001:db8::/32"),      # Documentation
    ipaddress.ip_network("fc00::/7"),           # Unique Local (RFC 4193)
    ipaddress.ip_network("fe80::/10"),          # Link Local (RFC 4291)
    ipaddress.ip_network("ff00::/8"),           # Multicast
]


def is_ip_prohibited(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Tuple[bool, str]:
    """
    Check if an IP address belongs to any private, loopback, link-local,
    reserved, or cloud metadata network.
    """
    # Unpack IPv4-mapped IPv6 addresses if present
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    if ip.is_loopback:
        return True, f"Loopback address prohibited: {ip}"
    if ip.is_private:
        return True, f"Private network address prohibited: {ip}"
    if ip.is_link_local:
        return True, f"Link-local / cloud metadata address prohibited: {ip}"
    if ip.is_multicast:
        return True, f"Multicast address prohibited: {ip}"
    if ip.is_reserved:
        return True, f"Reserved address prohibited: {ip}"
    if ip.is_unspecified:
        return True, f"Unspecified address prohibited: {ip}"

    # Explicit network checks
    for net in PROHIBITED_NETWORKS:
        if ip in net:
            return True, f"Address {ip} belongs to prohibited network {net}"

    return False, ""


def is_hostname_prohibited(hostname: str) -> Tuple[bool, str]:
    """
    Check if a raw hostname is prohibited prior to DNS resolution.
    """
    cleaned = hostname.strip().lower().rstrip(".")
    if not cleaned:
        return True, "Empty hostname"

    if cleaned in PROHIBITED_HOSTNAMES:
        return True, f"Direct access to prohibited host '{cleaned}' is blocked."

    for suffix in PROHIBITED_SUFFIXES:
        if cleaned.endswith(suffix):
            return True, f"Access to internal domain suffix '{suffix}' is prohibited."

    # Prevent octal/hex IP evasion like 0177.0.0.1 or 0x7f000001
    if re.match(r"^(0[0-9]+|0x[0-9a-fA-F]+)", cleaned):
        return True, "Alternative base IP encoding prohibited."

    return False, ""


def resolve_and_validate_destination(hostname: str, port: int = 80) -> Tuple[bool, str, List[str]]:
    """
    Resolve DNS for the destination and validate that NONE of the resolved IP addresses
    belong to private or prohibited ranges (DNS Rebinding Defense).
    
    Returns:
        (is_safe, failure_reason, resolved_ips)
    """
    hostname_clean = hostname.strip().lower().rstrip(".")

    # 1. Hostname string checks
    prohibited, reason = is_hostname_prohibited(hostname_clean)
    if prohibited:
        return False, reason, []

    # 2. Check if hostname is already a direct IP address
    try:
        direct_ip = ipaddress.ip_address(hostname_clean)
        is_bad, ip_reason = is_ip_prohibited(direct_ip)
        if is_bad:
            return False, ip_reason, [str(direct_ip)]
        return True, "", [str(direct_ip)]
    except ValueError:
        pass  # Standard domain name, proceed to DNS resolution

    # 3. Resolve DNS records
    resolved_ips: List[str] = []
    try:
        # socket.getaddrinfo returns list of 5-tuples: (family, type, proto, canonname, sockaddr)
        addr_info = socket.getaddrinfo(hostname_clean, port, proto=socket.IPPROTO_TCP)
        for item in addr_info:
            sockaddr = item[4]
            ip_str = sockaddr[0]
            if ip_str not in resolved_ips:
                resolved_ips.append(ip_str)
    except socket.gaierror as e:
        return False, f"DNS resolution failed for '{hostname_clean}': {e}", []
    except Exception as e:
        return False, f"Resolution error for '{hostname_clean}': {e}", []

    if not resolved_ips:
        return False, f"No IP addresses resolved for '{hostname_clean}'", []

    # 4. Strict validation of ALL resolved addresses
    for ip_str in resolved_ips:
        try:
            parsed_ip = ipaddress.ip_address(ip_str)
            is_bad, ip_reason = is_ip_prohibited(parsed_ip)
            if is_bad:
                return False, f"DNS rebinding / SSRF defense: {hostname_clean} resolved to prohibited IP ({ip_reason})", resolved_ips
        except ValueError:
            return False, f"Invalid IP returned by DNS: {ip_str}", resolved_ips

    return True, "", resolved_ips


def validate_web_fetch_url(url: str) -> Tuple[bool, str, Optional[urllib.parse.ParseResult], List[str]]:
    """
    Complete security gate for any outbound web fetch.
    Validates scheme, hostname, port, and resolved IP addresses.
    
    Returns:
        (is_safe, error_reason, parsed_url, resolved_ips)
    """
    if not url or not isinstance(url, str):
        return False, "Empty or invalid URL provided", None, []

    clean_url = url.strip()
    if not clean_url.startswith(("http://", "https://")):
        return False, "Only HTTP and HTTPS protocols are permitted for web fetching", None, []

    try:
        parsed = urllib.parse.urlparse(clean_url)
    except Exception as e:
        return False, f"URL parsing error: {e}", None, []

    if parsed.scheme.lower() not in ("http", "https"):
        return False, f"Prohibited URL scheme: {parsed.scheme}", parsed, []

    hostname = parsed.hostname
    if not hostname:
        return False, "Missing hostname in URL", parsed, []

    # Port restriction: only standard web ports allowed
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    if port not in (80, 443, 8080, 8443):
        return False, f"Non-standard web port {port} is prohibited by SSRF security policy", parsed, []

    # Validate destination and resolved IPs
    is_safe, reason, resolved_ips = resolve_and_validate_destination(hostname, port)
    if not is_safe:
        return False, reason, parsed, resolved_ips

    return True, "", parsed, resolved_ips
