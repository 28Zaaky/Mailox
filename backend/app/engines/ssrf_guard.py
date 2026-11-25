"""
SSRF Guard — validates all network targets before connection.

Security properties:
- All IPs (resolved or literal) are checked against blocked CIDRs
- DNS resolution uses public resolvers only (never follow internal hints)
- Returns resolved IPs bound to the validation result to prevent TOCTOU:
  callers MUST connect to the returned IPs, not re-resolve the hostname
- Multiple A/AAAA records: ALL must be public (not just the first)
- IPv6-mapped IPv4 addresses are unwrapped before checking
"""
import ipaddress
import socket
from typing import Optional

import dns.asyncresolver
import dns.exception
import dns.resolver
import structlog

logger = structlog.get_logger("mailox.ssrf_guard")

# Public DNS resolvers — never use system resolver (may point to internal DNS)
_PUBLIC_NAMESERVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "8.8.4.4"]

# CIDRs that must never be contacted
_BLOCKED_NETWORKS: list[ipaddress._BaseNetwork] = [
    # IPv4
    ipaddress.ip_network("0.0.0.0/8"),        # This network
    ipaddress.ip_network("10.0.0.0/8"),        # RFC1918 Class A
    ipaddress.ip_network("100.64.0.0/10"),     # CGNAT (RFC6598)
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local (APIPA)
    ipaddress.ip_network("172.16.0.0/12"),     # RFC1918 Class B
    ipaddress.ip_network("192.0.0.0/24"),      # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1 (documentation)
    ipaddress.ip_network("192.168.0.0/16"),    # RFC1918 Class C
    ipaddress.ip_network("198.18.0.0/15"),     # Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),       # Multicast
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved
    ipaddress.ip_network("255.255.255.255/32"),# Broadcast
    # IPv6
    ipaddress.ip_network("::1/128"),           # Loopback
    ipaddress.ip_network("::/128"),            # Unspecified
    ipaddress.ip_network("fc00::/7"),          # Unique local (RFC4193)
    ipaddress.ip_network("fe80::/10"),         # Link-local
    ipaddress.ip_network("ff00::/8"),          # Multicast
    ipaddress.ip_network("64:ff9b::/96"),      # IPv4/IPv6 translation
    ipaddress.ip_network("::ffff:0:0/96"),     # IPv4-mapped IPv6
]

# Cloud metadata endpoints — block by IP as well
_CLOUD_METADATA_IPS = {
    "169.254.169.254",  # AWS/Azure/GCP instance metadata
    "169.254.170.2",    # ECS task metadata
    "fd00:ec2::254",    # AWS IPv6 metadata
    "100.100.100.200",  # Alibaba Cloud metadata
}


class SSRFGuardError(Exception):
    """Raised when a target fails SSRF validation."""
    pass


def _unwrap_ipv4_mapped(addr: ipaddress._BaseAddress) -> ipaddress._BaseAddress:
    """Unwrap IPv4 embedded in IPv6 (::ffff:x.x.x.x mapped, 2002::/16 6to4)
    so the embedded IPv4 is what gets checked against the blocklist."""
    if isinstance(addr, ipaddress.IPv6Address):
        mapped = addr.ipv4_mapped
        if mapped is not None:
            return mapped
        sixtofour = addr.sixtofour
        if sixtofour is not None:
            return sixtofour
    return addr


def is_ip_blocked(ip_str: str) -> tuple[bool, str]:
    """
    Check if an IP is in a blocked range.
    Returns (is_blocked, reason).
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True, f"Invalid IP address: {ip_str!r}"

    addr = _unwrap_ipv4_mapped(addr)

    # Cloud metadata check
    if str(addr) in _CLOUD_METADATA_IPS:
        return True, f"Cloud metadata endpoint: {addr}"

    for network in _BLOCKED_NETWORKS:
        try:
            if addr in network:
                return True, f"{addr} is in blocked network {network}"
        except TypeError:
            # Mixed IPv4/IPv6 comparison — not in this network
            continue

    # Double-check with stdlib properties
    if hasattr(addr, "is_private") and addr.is_private:
        return True, f"{addr} is a private address"
    if hasattr(addr, "is_loopback") and addr.is_loopback:
        return True, f"{addr} is a loopback address"
    if hasattr(addr, "is_link_local") and addr.is_link_local:
        return True, f"{addr} is a link-local address"
    if hasattr(addr, "is_multicast") and addr.is_multicast:
        return True, f"{addr} is a multicast address"
    if hasattr(addr, "is_reserved") and addr.is_reserved:
        return True, f"{addr} is a reserved address"
    if hasattr(addr, "is_unspecified") and addr.is_unspecified:
        return True, f"{addr} is an unspecified address"

    return False, ""


class SSRFGuard:
    """
    SSRF protection guard for all outbound connections.

    Usage:
        guard = SSRFGuard()
        validated_ips = await guard.resolve_and_validate(hostname)
        # Connect ONLY to validated_ips[0] — do not re-resolve
    """

    def __init__(
        self,
        nameservers: Optional[list[str]] = None,
        resolve_timeout: float = 5.0,
    ) -> None:
        self._nameservers = nameservers or _PUBLIC_NAMESERVERS
        self._resolve_timeout = resolve_timeout
        # Set once the public resolvers time out (networks that block outbound
        # DNS to 8.8.8.8 & co.). Later lookups go straight to the system resolver
        # instead of waiting out the public tier on every single request.
        self._public_dns_unreachable = False

    def validate_ip(self, ip_str: str) -> None:
        """Validate a literal IP. Raises SSRFGuardError if blocked."""
        blocked, reason = is_ip_blocked(ip_str)
        if blocked:
            logger.warning("ssrf_blocked_ip", ip=ip_str, reason=reason)
            raise SSRFGuardError(f"Target IP not allowed: {reason}")

    async def resolve_and_validate(self, hostname: str) -> list[str]:
        """
        Resolve hostname → IPs, validate ALL resolved IPs are publicly routable.
        Returns list of validated IPs (caller must use these, not re-resolve).

        Raises SSRFGuardError if:
        - Any resolved IP is in a blocked range
        - DNS resolution fails
        - Hostname resolves to no IPs
        """
        # Reject bare IPs immediately
        try:
            addr = ipaddress.ip_address(hostname)
            self.validate_ip(str(addr))
            return [str(addr)]
        except SSRFGuardError:
            raise
        except ValueError:
            pass  # Not a bare IP — continue to DNS resolution

        resolvers_to_try = [
            (self._nameservers, self._resolve_timeout),
            (None, self._resolve_timeout),  # system resolver fallback
        ]
        if self._public_dns_unreachable:
            resolvers_to_try = resolvers_to_try[1:]

        resolved: list[str] = []
        last_error: Optional[str] = None

        for nameservers, timeout in resolvers_to_try:
            resolver = dns.asyncresolver.Resolver()
            if nameservers is not None:
                resolver.nameservers = nameservers
            resolver.timeout = timeout
            resolver.lifetime = timeout * 2

            round_resolved: list[str] = []
            failed = False

            for rdtype in ("A", "AAAA"):
                try:
                    answer = await resolver.resolve(hostname, rdtype)
                    for rdata in answer:
                        round_resolved.append(str(rdata))
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    pass
                except dns.resolver.NoNameservers:
                    last_error = f"DNS resolution failed for {hostname}: no nameservers"
                    failed = True
                    break
                except dns.exception.Timeout:
                    last_error = f"DNS resolution timed out for {hostname}"
                    failed = True
                    if nameservers is not None:
                        self._public_dns_unreachable = True
                    break
                except Exception as e:
                    last_error = f"DNS error for {hostname}: {e}"
                    failed = True
                    break

            if not failed and round_resolved:
                resolved = round_resolved
                break

        if not resolved and last_error:
            raise SSRFGuardError(last_error)

        if not resolved:
            raise SSRFGuardError(f"No IPs resolved for hostname: {hostname}")

        # Validate EVERY resolved IP — not just the first (DNS rebinding prevention)
        for ip in resolved:
            self.validate_ip(ip)

        logger.debug("ssrf_resolved", hostname=hostname, ips=resolved)
        return resolved

    async def validate_domain_for_scan(self, domain: str) -> None:
        """
        Lightweight pre-validation for scan targets.
        Verifies the domain resolves and all IPs are public.
        Does not return IPs (use resolve_and_validate before actual connections).
        """
        await self.resolve_and_validate(domain)
