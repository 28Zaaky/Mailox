"""
Shared DNS resolver factory.

Tests public DNS reachability once per process, then returns the
appropriate resolver for all subsequent queries — no repeated timeouts.
"""
from __future__ import annotations

from typing import Optional

import dns.asyncresolver
import dns.exception
import dns.resolver

_PUBLIC_NS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
_public_dns_ok: Optional[bool] = None


def _build(timeout: float = 5.0, use_system: bool = False) -> dns.asyncresolver.Resolver:
    r = dns.asyncresolver.Resolver()
    if not use_system:
        r.nameservers = _PUBLIC_NS
    r.timeout = timeout
    r.lifetime = timeout * len(_PUBLIC_NS) if not use_system else timeout * 2
    return r


async def _probe_public() -> bool:
    """Return True if 8.8.8.8 is reachable within 1.5s."""
    probe = dns.asyncresolver.Resolver()
    probe.nameservers = ["8.8.8.8"]
    probe.timeout = 1.5
    probe.lifetime = 1.5
    try:
        await probe.resolve("google.com", "A")
        return True
    except Exception:
        return False


async def get_resolver(timeout: float = 5.0) -> dns.asyncresolver.Resolver:
    """
    Return a resolver using public DNS if reachable, system DNS otherwise.
    Reachability is tested once per process (asyncio cooperative — no race risk).
    """
    global _public_dns_ok
    if _public_dns_ok is None:
        _public_dns_ok = await _probe_public()
    if _public_dns_ok:
        return _build(timeout=timeout, use_system=False)
    return _build(timeout=timeout, use_system=True)
