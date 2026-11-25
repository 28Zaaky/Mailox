"""
Pinned DNS transport for WebmailEngine.

Closes the TOCTOU gap between SSRFGuard.validate_domain_for_scan() and httpx's
own DNS resolution: without pinning, httpx queries the OS resolver again after
our trusted-DNS validation — a DNS rebinding window.

How it works
------------
httpcore (the HTTP/1.1 layer under httpx) calls ``AsyncNetworkBackend.connect_tcp(host, port)``
for every TCP connection, including redirect hops. We replace the pool's default
network backend with ``_SSRFPinnedNetworkBackend``, which:

1. Calls ``SSRFGuard.resolve_and_validate(host)`` via trusted public resolvers
2. Validates ALL resolved IPs against blocked CIDRs (RFC1918, link-local, metadata, …)
3. Establishes the TCP socket to ``validated_ips[0]`` — OS resolver never called

TLS correctness
---------------
httpcore sets TLS SNI and certificate-verification hostname from ``_origin.host``
(the URL's hostname), NOT from the IP passed to ``connect_tcp``.  So:

- TCP socket → validated IP (1.2.3.4)       ← rebinding prevented
- TLS SNI   → "webmail.example.com"          ← correct
- Cert check → against "webmail.example.com" ← correct

This means ``verify=True`` continues to work correctly when checking certificates.

Redirect handling
-----------------
Every redirect causes a new connection → a new ``connect_tcp`` call → a new
``resolve_and_validate`` call.  Redirect targets to private IPs are blocked at
the transport layer, before the event-hook layer (which remains as defence-in-depth).

Compatibility
-------------
Relies on two semi-private attributes that have been stable since httpcore 0.17:
  - ``httpx.AsyncHTTPTransport._pool``          (httpcore.AsyncConnectionPool)
  - ``httpcore.AsyncConnectionPool._network_backend``

Both are set in ``__init__`` and not monkey-patched elsewhere.  If the attribute
is absent (future httpcore API break), ``__init__`` raises ``RuntimeError`` loudly
rather than silently degrading to unprotected DNS.
"""
from typing import Any, Optional

import httpcore
import httpx
import structlog

from app.engines.ssrf_guard import SSRFGuard, SSRFGuardError

logger = structlog.get_logger("mailox.engines.webmail_transport")


class _SSRFPinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """
    httpcore AsyncNetworkBackend that pins every TCP connection to a
    pre-validated IP returned by SSRFGuard.

    ``connect_tcp("webmail.example.com", 443)`` → resolves via trusted DNS →
    validates all IPs → connects to ``validated_ips[0]``.  The original
    hostname is never passed to the OS resolver.
    """

    def __init__(self, ssrf_guard: SSRFGuard, real: httpcore.AsyncNetworkBackend) -> None:
        self._guard = ssrf_guard
        self._real = real

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
        local_address: Optional[str] = None,
        socket_options: Optional[Any] = None,
    ) -> httpcore.AsyncNetworkStream:
        """Validate ``host``, then connect to its first validated IP."""
        # SSRFGuardError propagates through httpcore → httpx and is caught by
        # _probe_url's ``except SSRFGuardError`` handler.
        try:
            validated_ips = await self._guard.resolve_and_validate(host)
        except SSRFGuardError:
            raise

        connect_host = validated_ips[0]
        logger.debug("dns_pinned_connect", host=host, ip=connect_host)

        return await self._real.connect_tcp(
            connect_host,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def connect_unix_domain_socket(
        self,
        path: str,
        timeout: Optional[float] = None,
        socket_options: Optional[Any] = None,
    ) -> httpcore.AsyncNetworkStream:
        return await self._real.connect_unix_domain_socket(
            path, timeout=timeout, socket_options=socket_options
        )

    async def sleep(self, seconds: float) -> None:
        return await self._real.sleep(seconds)


class PinnedDNSTransport(httpx.AsyncHTTPTransport):
    """
    Drop-in replacement for ``httpx.AsyncHTTPTransport`` with DNS pinning.

    Pass ``ssrf_guard`` as the first argument; all other keyword arguments
    are forwarded to ``httpx.AsyncHTTPTransport`` (e.g. ``verify``, ``retries``).

    Example::

        transport = PinnedDNSTransport(ssrf_guard=guard, verify=False)
        async with httpx.AsyncClient(transport=transport, ...) as client:
            resp = await client.get(url)
    """

    def __init__(self, ssrf_guard: SSRFGuard, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        # _pool is set by AsyncHTTPTransport.__init__ before we run.
        # _network_backend is the anyio/asyncio backend used for TCP connections.
        try:
            real_backend = self._pool._network_backend
        except AttributeError as exc:
            raise RuntimeError(
                "PinnedDNSTransport: httpcore.AsyncConnectionPool._network_backend "
                "not found — httpcore API may have changed. "
                "Pin httpcore to a version that exposes this attribute."
            ) from exc

        self._pool._network_backend = _SSRFPinnedNetworkBackend(ssrf_guard, real_backend)
