"""
CredentialProbesEngine: credential testing.

OPT-IN ONLY. Requires CRED_PROBE_ENABLED=true in config.
Never enabled by default. Requires written authorization from target owner.

Design constraints:
- Hard-coded short list of DEFAULT/FACTORY credentials only (not a wordlist)
- Rate-limited: CRED_PROBE_RATE_LIMIT_SECONDS between each attempt
- Hard cap: CRED_PROBE_MAX_ATTEMPTS per protocol per target
- Never store or log discovered credentials — finding records redacted password
- SMTP: test on SUBMISSION port (587) only, never port 25 (MTA relay)
- IMAP: test on IMAPS (993) only
- Webmail: HTTP POST to detected login endpoint, no session persistence
- First success → stop immediately (no exhaustive enumeration)
- Each attempt is a single connection — no connection reuse across users

check_id prefix: APC-

Checks implemented:
  APC-SMTP-DEFAULT-CREDS    SMTP AUTH LOGIN/PLAIN with known defaults on port 587
  APC-IMAP-DEFAULT-CREDS    IMAP LOGIN with known defaults on port 993
  APC-WEBMAIL-DEFAULT-CREDS HTTP login to detected webmail (Roundcube/Zimbra/OWA)
"""
import asyncio
import base64
import imaplib
import re
import ssl
import time
from dataclasses import dataclass
from typing import Optional

import httpx
import structlog

from app.core.config import settings
from app.engines.base import BaseEngine, EngineResult
from app.engines.active_probes import _smtp_cmd, _smtp_quit
from app.engines.ssrf_guard import SSRFGuard
from app.engines.webmail_transport import PinnedDNSTransport
from app.schemas.findings import Evidence, EvidenceType, Finding, RiskLevel

_CONNECT_TIMEOUT = 8.0
_READ_TIMEOUT = 10.0
_HTTP_TIMEOUT = 15.0

logger = structlog.get_logger("mailox.engines.credential_probes")

# ---------------------------------------------------------------------------
# Default credential list — factory defaults, not a bruteforce wordlist.
# username may be a literal or one of:
#   {domain}  → replaced with the target domain
#   {user}@{domain} → generates per-domain variant
# ---------------------------------------------------------------------------
_DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "Password1"),
    ("admin", "changeme"),
    ("admin", ""),
    ("postmaster", "postmaster"),
    ("postmaster", "password"),
    ("postmaster", ""),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("test", "test"),
    ("info", "info"),
    ("mailtest", "mailtest"),
    ("noreply", "noreply"),
]

_WEBMAIL_PROFILES = {
    "roundcube": {
        "login_path": "/index.php",
        "method": "POST",
        "user_field": "_user",
        "pass_field": "_pass",
        "action_field": "_action",
        "action_value": "login",
        "success_indicators": ["logout", "compose", "mailbox", "rcmcoreusr"],
        "failure_indicators": ["invalid", "failed", "error", "Login failed"],
    },
    "zimbra": {
        "login_path": "/",
        "method": "POST",
        "user_field": "loginOp",
        "pass_field": "password",
        "action_field": "loginOp",
        "action_value": "login",
        "success_indicators": ["logoff", "compose", "zm_auth_token", "doLogoff"],
        "failure_indicators": ["invalid", "failed", "error", "authentication failed"],
    },
    "owa": {
        "login_path": "/owa/auth.owa",
        "method": "POST",
        "user_field": "username",
        "pass_field": "password",
        "action_field": "flags",
        "action_value": "0",
        "success_indicators": ["logoff", "OWA", "inbox", "X-OWA-Version"],
        "failure_indicators": ["invalid", "failed", "error", "0x8004010F"],
    },
}


# Lockout/throttle detection patterns
_LOCKOUT_PATTERNS = [
    "too many",
    "locked",
    "try again later",
    "temporarily blocked",
    "rate limit",
    "account disabled",
    "authentication failed.*times",
    "exceeded.*attempts",
]

# SMTP response codes indicating throttle/lockout
_SMTP_LOCKOUT_CODES = ("421", "452", "450")

# Max attempts per account (not per credential)
_MAX_ATTEMPTS_PER_ACCOUNT = 3


@dataclass
class CredResult:
    check_id: str
    hit: bool                    # True = valid credential found
    username: Optional[str] = None
    protocol: Optional[str] = None
    inconclusive: bool = False
    attempts: int = 0
    stopped_early: bool = False  # hit found before exhausting list
    evidence_value: Optional[str] = None
    error: Optional[str] = None
    lockout_detected: bool = False  # True if lockout/throttle was detected


class CredentialProbesEngine(BaseEngine):
    """
    Credential brute-force with default credentials only.
    Requires CRED_PROBE_ENABLED=True in config.
    """
    name: str = "credential_probes"
    default_timeout: float = 180.0

    def __init__(self, ssrf_guard: Optional[SSRFGuard] = None, timeout: Optional[float] = None) -> None:
        super().__init__(timeout=timeout)
        self._guard = ssrf_guard if ssrf_guard else SSRFGuard()

    async def _validated_smtp_connect(self, host: str, port: int) -> Optional[tuple]:
        """SMTP connect with IP validation via SSRF guard."""
        try:
            validated_ips = await self._guard.resolve_and_validate(host)
            connect_ip = validated_ips[0]
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(connect_ip, port),
                timeout=_CONNECT_TIMEOUT,
            )
            try:
                banner = await asyncio.wait_for(reader.readline(), timeout=_READ_TIMEOUT)
            except BaseException:
                writer.close()
                raise
            return reader, writer, banner.decode(errors="replace").strip()
        except Exception:
            return None

    async def _validated_smtp_connect_tls(self, host: str, port: int) -> tuple:
        """SMTP TLS connect with IP validation via SSRF guard."""
        try:
            validated_ips = await self._guard.resolve_and_validate(host)
            connect_ip = validated_ips[0]
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(connect_ip, port),
                timeout=_CONNECT_TIMEOUT,
            )
            try:
                banner = await asyncio.wait_for(reader.readline(), timeout=_READ_TIMEOUT)
            except BaseException:
                writer.close()
                raise
            return reader, writer, banner.decode(errors="replace").strip()
        except Exception:
            return None, None, None

    def _make_http_client(self) -> httpx.AsyncClient:
        """Build httpx client with DNS pinning via SSRFGuard."""
        transport = PinnedDNSTransport(self._guard, verify=False)
        return httpx.AsyncClient(
            transport=transport,
            timeout=_HTTP_TIMEOUT,
            verify=False,
            follow_redirects=True,
            max_redirects=3,
        )

    async def _run(self, domain: str) -> EngineResult:
        result = EngineResult(engine=self.name, domain=domain)
        result.metadata["note"] = "Call run_from_findings() with mx_host / webmail_url."
        return result

    async def run_from_findings(
        self,
        domain: str,
        mx_host: Optional[str] = None,
        webmail_url: Optional[str] = None,
        webmail_type: Optional[str] = None,
    ) -> EngineResult:
        result = EngineResult(engine=self.name, domain=domain)

        if not settings.CRED_PROBE_ENABLED:
            result.metadata["skipped"] = "CRED_PROBE_ENABLED=false"
            logger.info("cred_probes_skipped", domain=domain, reason="opt-in disabled")
            return result

        target_host = mx_host or domain
        # Build credential list: literals + domain-specific variants
        all_creds = list(_DEFAULT_CREDS) + [
            (f"admin@{domain}", "admin"),
            (f"admin@{domain}", "password"),
            (f"postmaster@{domain}", "postmaster"),
            (f"administrator@{domain}", "administrator"),
        ]

        # Group credentials by username, limit to _MAX_ATTEMPTS_PER_ACCOUNT per account
        # This prevents account lockout from multiple protocols testing the same user
        from collections import defaultdict
        creds_by_user: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for username, password in all_creds:
            if len(creds_by_user[username]) < _MAX_ATTEMPTS_PER_ACCOUNT:
                creds_by_user[username].append((username, password))

        # Flatten back to list, respecting per-account limit
        creds = []
        for user_creds in creds_by_user.values():
            creds.extend(user_creds)

        # Apply global hard cap (explicit, not silent truncation)
        if len(creds) > settings.CRED_PROBE_MAX_ATTEMPTS:
            logger.info("cred_probe_truncated", original=len(creds), limit=settings.CRED_PROBE_MAX_ATTEMPTS)
            creds = creds[:settings.CRED_PROBE_MAX_ATTEMPTS]

        # ── SMTP AUTH on submission port ──────────────────────────────────────
        cr1 = await self._probe_smtp_auth(target_host, settings.CRED_PROBE_SMTP_PORT, domain, creds)
        result.metadata["smtp_attempts"] = cr1.attempts
        if cr1.hit:
            result.add_finding(self._smtp_cred_finding(cr1, domain, target_host))

        # ── IMAP AUTH ─────────────────────────────────────────────────────────
        cr2 = await self._probe_imap_auth(target_host, settings.CRED_PROBE_IMAP_PORT, domain, creds)
        result.metadata["imap_attempts"] = cr2.attempts
        if cr2.hit:
            result.add_finding(self._imap_cred_finding(cr2, domain, target_host))

        # ── Webmail HTTP login ────────────────────────────────────────────────
        if webmail_url:
            wtype = webmail_type or _detect_webmail_type(webmail_url)
            if wtype and wtype in _WEBMAIL_PROFILES:
                cr3 = await self._probe_webmail_auth(webmail_url, wtype, domain, creds)
                result.metadata["webmail_attempts"] = cr3.attempts
                if cr3.hit:
                    result.add_finding(self._webmail_cred_finding(cr3, domain, webmail_url))

        return result

    # ── Lockout detection helper ───────────────────────────────────────────────

    def _is_lockout_response(self, response_text: str) -> bool:
        """Check if response indicates account lockout or throttling."""
        response_lower = response_text.lower()
        return any(
            re.search(pattern, response_lower)
            for pattern in _LOCKOUT_PATTERNS
        )

    def _is_smtp_lockout(self, response: str) -> bool:
        """Check if SMTP response indicates lockout (codes or text patterns)."""
        if any(response.startswith(code) for code in _SMTP_LOCKOUT_CODES):
            return True
        return self._is_lockout_response(response)

    # ── Probe: SMTP AUTH LOGIN on submission port ─────────────────────────────

    async def _probe_smtp_auth(
        self, host: str, port: int, domain: str, creds: list[tuple[str, str]]
    ) -> CredResult:
        check_id = "APC-SMTP-DEFAULT-CREDS"
        attempts = 0
        locked_users: set[str] = set()  # Track users that triggered lockout

        for username, password in creds:
            # Skip if this user already triggered a lockout
            if username in locked_users:
                logger.debug("smtp_skip_locked_user", host=host, username=username)
                continue

            await asyncio.sleep(settings.CRED_PROBE_RATE_LIMIT_SECONDS)
            attempts += 1
            writer = None
            try:
                # Fresh connection per attempt
                reader, writer, banner = await self._validated_smtp_connect_tls(host, port)
                if reader is None:
                    continue

                ehlo = await _smtp_cmd(reader, writer, f"EHLO probe.{domain}")

                # Check for lockout in banner or EHLO response
                if self._is_smtp_lockout(banner or "") or self._is_smtp_lockout(ehlo):
                    logger.warning("smtp_lockout_detected", host=host, username=username)
                    locked_users.add(username)
                    await _smtp_quit(writer)
                    continue

                # Try STARTTLS if advertised and not already TLS
                if "STARTTLS" in ehlo.upper() and not getattr(writer, "_over_ssl", False):
                    stls = await _smtp_cmd(reader, writer, "STARTTLS")
                    if stls.startswith("220"):
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        try:
                            await writer.start_tls(ctx)
                            ehlo = await _smtp_cmd(reader, writer, f"EHLO probe.{domain}")
                        except Exception:
                            pass

                if "AUTH" not in ehlo.upper():
                    await _smtp_quit(writer)
                    return CredResult(check_id=check_id, hit=False, inconclusive=True,
                                      attempts=attempts, error="AUTH not advertised")

                # Try AUTH LOGIN
                auth_resp = await _smtp_cmd(reader, writer, "AUTH LOGIN")
                if auth_resp.startswith("334"):
                    u64 = base64.b64encode(username.encode()).decode()
                    await _smtp_cmd(reader, writer, u64)
                    p64 = base64.b64encode(password.encode()).decode()
                    final = await _smtp_cmd(reader, writer, p64)

                    # Check for lockout in auth response
                    if self._is_smtp_lockout(final):
                        logger.warning("smtp_lockout_on_auth", host=host, username=username)
                        locked_users.add(username)
                        await _smtp_quit(writer)
                        continue

                    if final.startswith("235"):
                        await _smtp_quit(writer)
                        logger.warning(
                            "cred_probe_hit_smtp",
                            host=host, port=port,
                            username=username,
                        )
                        return CredResult(
                            check_id=check_id,
                            hit=True,
                            username=username,
                            protocol="SMTP/AUTH LOGIN",
                            attempts=attempts,
                            stopped_early=True,
                            evidence_value=(
                                f"SMTP AUTH LOGIN succeeded for user '{username}' "
                                f"on {host}:{port} with default credential"
                            ),
                        )

                await _smtp_quit(writer)

            except asyncio.TimeoutError:
                logger.debug("smtp_auth_probe_timeout", host=host, username=username)
                if writer is not None:
                    writer.close()
                continue
            except Exception as exc:
                logger.debug("smtp_auth_probe_error", host=host, error=str(exc))
                if writer is not None:
                    writer.close()
                continue

        return CredResult(
            check_id=check_id, hit=False, attempts=attempts,
            lockout_detected=len(locked_users) > 0
        )

    # ── Probe: IMAP LOGIN on IMAPS port ──────────────────────────────────────

    async def _probe_imap_auth(
        self, host: str, port: int, domain: str, creds: list[tuple[str, str]]
    ) -> CredResult:
        check_id = "APC-IMAP-DEFAULT-CREDS"
        attempts = 0
        locked_users: set[str] = set()  # Track users that triggered lockout

        for username, password in creds:
            # Skip if this user already triggered a lockout
            if username in locked_users:
                logger.debug("imap_skip_locked_user", host=host, username=username)
                continue

            await asyncio.sleep(settings.CRED_PROBE_RATE_LIMIT_SECONDS)
            attempts += 1
            try:
                success, lockout_detected, error_msg = await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(
                        None,
                        _imap_login_sync,
                        host, port, username, password,
                    ),
                    timeout=settings.CRED_PROBE_RATE_LIMIT_SECONDS + 10.0,
                )

                # Check for lockout
                if lockout_detected:
                    logger.warning("imap_lockout_detected", host=host, username=username, error=error_msg)
                    locked_users.add(username)
                    continue

                if success:
                    logger.warning(
                        "cred_probe_hit_imap",
                        host=host, port=port, username=username,
                    )
                    return CredResult(
                        check_id=check_id,
                        hit=True,
                        username=username,
                        protocol="IMAP/LOGIN",
                        attempts=attempts,
                        stopped_early=True,
                        evidence_value=(
                            f"IMAP LOGIN succeeded for user '{username}' "
                            f"on {host}:{port} with default credential"
                        ),
                    )
            except asyncio.TimeoutError:
                logger.debug("imap_probe_timeout", host=host, username=username)
                continue
            except Exception as exc:
                logger.debug("imap_probe_error", host=host, error=str(exc))
                continue

        return CredResult(
            check_id=check_id, hit=False, attempts=attempts,
            lockout_detected=len(locked_users) > 0
        )

    # ── Probe: Webmail HTTP login ─────────────────────────────────────────────

    async def _probe_webmail_auth(
        self, base_url: str, wtype: str, domain: str, creds: list[tuple[str, str]]
    ) -> CredResult:
        check_id = "APC-WEBMAIL-DEFAULT-CREDS"
        profile = _WEBMAIL_PROFILES[wtype]
        login_url = base_url.rstrip("/") + profile["login_path"]
        attempts = 0
        locked_users: set[str] = set()  # Track users that triggered lockout

        async with self._make_http_client() as client:
            for username, password in creds:
                # Skip if this user already triggered a lockout
                if username in locked_users:
                    logger.debug("webmail_skip_locked_user", url=login_url, username=username)
                    continue

                await asyncio.sleep(settings.CRED_PROBE_RATE_LIMIT_SECONDS)
                attempts += 1
                try:
                    data = {
                        profile["user_field"]: username,
                        profile["pass_field"]: password,
                    }
                    if profile.get("action_field"):
                        data[profile["action_field"]] = profile["action_value"]

                    resp = await client.post(login_url, data=data)
                    body = resp.text[:5000].lower()
                    headers_str = str(resp.headers).lower()

                    # Check for lockout/throttle indicators in response
                    if self._is_lockout_response(body) or resp.status_code == 429:
                        logger.warning("webmail_lockout_detected", url=login_url, username=username)
                        locked_users.add(username)
                        continue

                    success = any(
                        ind.lower() in body or ind.lower() in headers_str
                        for ind in profile["success_indicators"]
                    )
                    failure = any(
                        ind.lower() in body
                        for ind in profile["failure_indicators"]
                    )

                    if success and not failure:
                        logger.warning(
                            "cred_probe_hit_webmail",
                            url=login_url, username=username, wtype=wtype,
                        )
                        return CredResult(
                            check_id=check_id,
                            hit=True,
                            username=username,
                            protocol=f"HTTP/{wtype}",
                            attempts=attempts,
                            stopped_early=True,
                            evidence_value=(
                                f"Webmail ({wtype}) login succeeded for user '{username}' "
                                f"at {login_url} with default credential"
                            ),
                        )
                except Exception as exc:
                    logger.debug("webmail_probe_error", url=login_url, error=str(exc))
                    continue

        return CredResult(
            check_id=check_id, hit=False, attempts=attempts,
            lockout_detected=len(locked_users) > 0
        )

    # ── Finding builders ──────────────────────────────────────────────────────

    def _smtp_cred_finding(self, cr: CredResult, domain: str, host: str) -> Finding:
        return self._make_finding(
            check_id=cr.check_id,
            title=f"Default SMTP credentials valid — '{cr.username}' authenticated",
            description=(
                f"SMTP AUTH LOGIN succeeded for user '{cr.username}' on {host} "
                f"using a factory-default credential. "
                "This account can be used to send email through your infrastructure, "
                "enabling spam, phishing, and business email compromise."
            ),
            risk_level=RiskLevel.CRITICAL,
            confidence=0.99,
            evidence=[Evidence(
                type=EvidenceType.SMTP_RESPONSE,
                observed_value=cr.evidence_value,
                expected_value="535 Authentication failed",
                source=f"smtp://{host}:{settings.CRED_PROBE_SMTP_PORT}",
                technical_details={
                    "protocol": cr.protocol,
                    "attempts_before_hit": cr.attempts,
                    "username": cr.username,
                    "password": "REDACTED",
                },
            )],
            remediation=(
                f"Immediately change the password for '{cr.username}'. "
                "Audit all mailbox accounts for default credentials. "
                "Enforce a minimum-length password policy on all mail accounts."
            ),
            affected_asset=domain,
            business_impact=(
                "Attacker with SMTP credentials can send unlimited email as your domain, "
                "bypass SPF (authenticated sender), cause IP blacklisting, "
                "and conduct BEC (Business Email Compromise) attacks."
            ),
            references=["https://attack.mitre.org/techniques/T1110/001/"],
        )

    def _imap_cred_finding(self, cr: CredResult, domain: str, host: str) -> Finding:
        return self._make_finding(
            check_id=cr.check_id,
            title=f"Default IMAP credentials valid — '{cr.username}' authenticated",
            description=(
                f"IMAP LOGIN succeeded for user '{cr.username}' on {host} "
                f"using a factory-default credential. "
                "An attacker can read all email in this mailbox, exfiltrate data, "
                "monitor communications, and pivot to password reset flows."
            ),
            risk_level=RiskLevel.CRITICAL,
            confidence=0.99,
            evidence=[Evidence(
                type=EvidenceType.SMTP_RESPONSE,
                observed_value=cr.evidence_value,
                expected_value="NO LOGIN failed",
                source=f"imaps://{host}:{settings.CRED_PROBE_IMAP_PORT}",
                technical_details={
                    "protocol": cr.protocol,
                    "attempts_before_hit": cr.attempts,
                    "username": cr.username,
                    "password": "REDACTED",
                },
            )],
            remediation=(
                f"Immediately change the password for '{cr.username}'. "
                "Enable account lockout after N failed attempts. "
                "Consider OAuth2/XOAUTH2 instead of password-based IMAP auth."
            ),
            affected_asset=domain,
            business_impact=(
                "Full mailbox access: attacker can read historical email, "
                "intercept reset tokens, harvest credentials from emails, "
                "and conduct long-term covert surveillance."
            ),
            references=["https://attack.mitre.org/techniques/T1110/001/"],
        )

    def _webmail_cred_finding(self, cr: CredResult, domain: str, url: str) -> Finding:
        return self._make_finding(
            check_id=cr.check_id,
            title=f"Default webmail credentials valid — '{cr.username}' authenticated",
            description=(
                f"Webmail ({cr.protocol}) login succeeded for user '{cr.username}' "
                f"at {url} using a factory-default credential. "
                "Full browser-based mailbox access including compose, search, and settings."
            ),
            risk_level=RiskLevel.CRITICAL,
            confidence=0.95,
            evidence=[Evidence(
                type=EvidenceType.HTTP_RESPONSE,
                observed_value=cr.evidence_value,
                expected_value="Login failure page",
                source=url,
                technical_details={
                    "protocol": cr.protocol,
                    "attempts_before_hit": cr.attempts,
                    "username": cr.username,
                    "password": "REDACTED",
                },
            )],
            remediation=(
                f"Immediately change the password for '{cr.username}'. "
                "Enforce strong password policy at account creation. "
                "Enable 2FA/MFA on webmail portal."
            ),
            affected_asset=domain,
            business_impact=(
                "Full webmail access: attacker can read, send, delete email, "
                "access contacts, and abuse any integrations linked to the account."
            ),
            references=["https://attack.mitre.org/techniques/T1110/001/"],
        )


# ── Sync helpers (run in executor to avoid blocking event loop) ───────────────

def _imap_login_sync(host: str, port: int, username: str, password: str) -> tuple[bool, bool, str]:
    """
    Returns (success, lockout_detected, error_message).
    success: True if IMAP login succeeds.
    lockout_detected: True if response indicates account lockout/throttle.
    Runs in thread executor.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        conn = imaplib.IMAP4_SSL(host, port, ssl_context=ctx)
        typ, data = conn.login(username, password)
        conn.logout()
        return (typ == "OK", False, "")
    except imaplib.IMAP4.error as e:
        error_msg = str(e).lower()
        # Check for lockout patterns
        lockout = any(
            pattern in error_msg
            for pattern in ["too many", "locked", "try again", "rate limit", "disabled", "exceeded"]
        )
        return (False, lockout, str(e))
    except Exception as e:
        return (False, False, str(e))


async def _smtp_connect_tls(host: str, port: int):
    """
    Connect to SMTP submission port. Returns (reader, writer, banner) or (None, None, None).
    Tries plain TCP first; TLS upgrade handled per-connection in probe.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=8.0,
        )
        banner = await asyncio.wait_for(reader.readline(), timeout=10.0)
        return reader, writer, banner.decode(errors="replace").strip()
    except Exception:
        return None, None, None


# ── Webmail type detection ─────────────────────────────────────────────────────

def _detect_webmail_type(url: str) -> Optional[str]:
    """Cheap heuristic: check URL path for known patterns."""
    u = url.lower()
    if "roundcube" in u or "/rc/" in u:
        return "roundcube"
    if "zimbra" in u or "/zimbrawebclient" in u:
        return "zimbra"
    if "/owa" in u or "outlook" in u:
        return "owa"
    return None
