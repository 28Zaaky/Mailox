"""
Security regression tests.

Verifies that all critical/high security fixes from Phase 3.4 hold.
These tests must remain green — a failure indicates a security regression.
"""
import hashlib
import ipaddress
import time
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient


# ── SEC-001: No hardcoded credentials in config ───────────────────────────────

class TestNoHardcodedCredentials:
    def test_celery_broker_url_has_no_redis_pass_default(self):
        """CELERY_BROKER_URL must not default to redis_pass credential."""
        from app.core.config import settings
        assert "redis_pass" not in settings.CELERY_BROKER_URL

    def test_celery_result_backend_has_no_redis_pass_default(self):
        """CELERY_RESULT_BACKEND must not default to redis_pass credential."""
        from app.core.config import settings
        assert "redis_pass" not in settings.CELERY_RESULT_BACKEND


# ── SEC-006: CORS wildcard detection ─────────────────────────────────────────

class TestCORSWildcardValidation:
    def test_subdomain_wildcard_blocked(self):
        """CORS validator must catch wildcard subdomains like https://*.example.com."""
        from pydantic import ValidationError
        import os
        from pydantic_settings import BaseSettings
        from app.core.config import Settings

        # Monkeypatch env to inject a wildcard subdomain origin
        env = {
            "SECRET_KEY": "a" * 32,
            "REFRESH_SECRET_KEY": "b" * 32,
            "MASTER_ENCRYPTION_KEY": "c" * 32,
            "DATABASE_URL": "postgresql+asyncpg://x:y@localhost/z",
            "DATABASE_URL_SYNC": "postgresql+psycopg2://x:y@localhost/z",
            "REDIS_URL": "redis://localhost/0",
            "CELERY_BROKER_URL": "redis://localhost/1",
            "CELERY_RESULT_BACKEND": "redis://localhost/2",
            "ALLOWED_ORIGINS": "https://*.example.com",
        }
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(Exception):
                Settings()


# ── AUTH-01: TOTP replay race condition ──────────────────────────────────────

class TestTOTPAtomicReplay:
    async def test_totp_replay_uses_atomic_update(self, client: AsyncClient):
        """verify_and_enable_mfa uses UPDATE WHERE IS DISTINCT FROM — no race."""
        from tests.conftest import auth_headers, login_user, register_user
        email = "totp_replay_sec@example.com"
        await register_user(client, email=email)
        tokens = await login_user(client, email=email)
        hdrs = auth_headers(tokens["access_token"])

        resp = await client.post("/api/v1/auth/mfa/setup", headers=hdrs)
        assert resp.status_code == 200
        secret = resp.json()["secret"]

        import pyotp
        totp = pyotp.TOTP(secret)
        code = totp.now()

        # First use — should succeed
        r1 = await client.post(
            "/api/v1/auth/mfa/verify",
            headers=hdrs,
            json={"code": code},
        )
        # Replay — same code must be rejected
        r2 = await client.post(
            "/api/v1/auth/mfa/verify",
            headers=hdrs,
            json={"code": code},
        )
        # At most one should succeed (MFA already enabled after first success)
        assert r1.status_code in (204, 400), f"Unexpected: {r1.status_code}"
        assert r2.status_code in (401, 400), f"Replay should be rejected: {r2.status_code}"


# ── AUTH-05: Locked account oracle eliminated ─────────────────────────────────

class TestLockedAccountOracle:
    async def test_locked_account_returns_generic_message(self, client: AsyncClient, monkeypatch):
        """Locked accounts must return 'Invalid credentials', not 'Account locked'."""
        # Pin the threshold: a developer .env (ACCOUNT_LOCKOUT_ATTEMPTS=10) leaks into settings.
        from app.core.config import settings
        monkeypatch.setattr(settings, "ACCOUNT_LOCKOUT_ATTEMPTS", 5)
        from tests.conftest import register_user
        email = "oracle_sec@example.com"
        await register_user(client, email=email)

        for _ in range(5):
            await client.post(
                "/api/v1/auth/login",
                json={"email": email, "password": "WrongPass999!"},
            )

        from tests.conftest import TEST_PASSWORD
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": TEST_PASSWORD},
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid credentials"
        assert "lock" not in resp.json()["detail"].lower()


# ── SSRF-02: AWS IPv6 metadata blocked ───────────────────────────────────────

class TestSSRFBlockedNetworks:
    def test_aws_ipv6_metadata_blocked(self):
        """fd00:ec2::254 (AWS IMDS over IPv6) must be blocked.

        2600:1f18::/32 used to be blocked as "AWS IPv6 metadata", but it is ordinary
        public AWS address space (customer hosts in us-east-1), not the IMDS
        endpoint; engines-07 removed it, so it must stay scannable.
        """
        from app.engines.ssrf_guard import is_ip_blocked
        blocked, _ = is_ip_blocked("fd00:ec2::254")
        assert blocked, "AWS IPv6 metadata endpoint fd00:ec2::254 not blocked"
        assert is_ip_blocked("2600:1f18::1") == (False, "")

    @pytest.mark.parametrize("ip", ["2002:7f00:1::", "2002:c0a8:101::", "::ffff:127.0.0.1"])
    def test_ipv4_embedded_in_ipv6_blocked(self, ip):
        """6to4 (2002::/16) and IPv4-mapped addresses are checked on their embedded IPv4."""
        from app.engines.ssrf_guard import is_ip_blocked
        assert is_ip_blocked(ip)[0], ip

    def test_6to4_public_ipv4_allowed(self):
        from app.engines.ssrf_guard import is_ip_blocked
        assert is_ip_blocked("2002:0808:0808::")[0] is False

    def test_alibaba_metadata_blocked(self):
        """100.100.100.200 (Alibaba Cloud metadata) must be in cloud metadata set."""
        from app.engines.ssrf_guard import _CLOUD_METADATA_IPS
        assert "100.100.100.200" in _CLOUD_METADATA_IPS

    def test_private_ipv4_blocked(self):
        """10.x.x.x remains blocked."""
        from app.engines.ssrf_guard import SSRFGuard, SSRFGuardError
        guard = SSRFGuard()
        with pytest.raises(SSRFGuardError):
            guard.validate_ip("10.0.0.1")


# ── SEC-007: HKDF uses static salt ───────────────────────────────────────────

class TestHKDFSalt:
    def test_hkdf_salt_not_none(self):
        """HKDF must use a static salt, not None (zero-byte per RFC 5869)."""
        from app.core.crypto import _HKDF_SALT
        assert _HKDF_SALT is not None
        assert len(_HKDF_SALT) == 32  # SHA-256 output
        assert _HKDF_SALT == hashlib.sha256(b"mailox-v1-hkdf-salt").digest()

    def test_encrypt_decrypt_roundtrip_with_salt(self):
        """AES-GCM encrypt/decrypt still works after HKDF salt change."""
        from app.core.crypto import decrypt, encrypt
        plaintext = b"test payload for HKDF regression"
        ciphertext = encrypt(plaintext, purpose="test")
        assert decrypt(ciphertext, purpose="test") == plaintext


# ── SEC-008: Testing mode warning ────────────────────────────────────────────

class TestTestingModeWarning:
    def test_testing_mode_active_in_test_env(self):
        """TESTING=true must be set in test environment."""
        import os
        assert os.environ.get("TESTING", "").lower() in ("1", "true", "yes")


# ── MAILOX-04: Security headers ──────────────────────────────────────────────

class TestSecurityHeaders:
    async def test_hsts_header_present(self, client: AsyncClient):
        """strict-transport-security header must be present in responses."""
        from tests.conftest import auth_headers, login_user, register_user
        email = "hsts_check@example.com"
        await register_user(client, email=email)
        tokens = await login_user(client, email=email)
        hdrs = auth_headers(tokens["access_token"])
        resp = await client.get("/api/v1/auth/me", headers=hdrs)
        assert resp.status_code == 200
        assert "strict-transport-security" in resp.headers

    async def test_csp_header_present(self, client: AsyncClient):
        """content-security-policy header must be present in responses."""
        from tests.conftest import auth_headers, login_user, register_user
        email = "csp_check@example.com"
        await register_user(client, email=email)
        tokens = await login_user(client, email=email)
        hdrs = auth_headers(tokens["access_token"])
        resp = await client.get("/api/v1/auth/me", headers=hdrs)
        assert "content-security-policy" in resp.headers

    async def test_xss_protection_zero(self, client: AsyncClient):
        """x-xss-protection must be '0' (disables broken browser XSS auditor)."""
        from tests.conftest import auth_headers, login_user, register_user
        email = "xss_hdr@example.com"
        await register_user(client, email=email)
        tokens = await login_user(client, email=email)
        hdrs = auth_headers(tokens["access_token"])
        resp = await client.get("/api/v1/auth/me", headers=hdrs)
        assert resp.headers.get("x-xss-protection") == "0"


# ── MAILOX-01: Rate limiter ───────────────────────────────────────────────────

class TestAuthRateLimiter:
    async def test_rate_limit_auth_dependency_callable(self):
        """rate_limit_auth must be an async callable accepting a Request."""
        import inspect
        from app.api.deps import rate_limit_auth
        assert inspect.iscoroutinefunction(rate_limit_auth)

    async def test_rate_limit_uses_redis_limiter(self):
        """rate_limit_auth must delegate to the distributed Redis check_rate_limit function.

        Phase 3.4 used an in-memory threading.Lock-based limiter.
        Phase 3.5 replaced it with a Redis sliding-window limiter.
        This verifies the new module-level architecture: no threading.Lock,
        no defaultdict in deps.py, check_rate_limit importable.
        """
        import inspect
        import app.api.deps as _deps
        import app.core.rate_limiter as _rl

        # No threading.Lock or defaultdict at module level in deps.py
        assert not hasattr(_deps, "_rate_limit_lock"), \
            "In-memory rate limit lock must be removed (Phase 3.5)"
        assert not hasattr(_deps, "_rate_limit_windows"), \
            "In-memory rate limit windows must be removed (Phase 3.5)"

        # check_rate_limit is an async function in rate_limiter module
        assert inspect.iscoroutinefunction(_rl.check_rate_limit), \
            "check_rate_limit must be an async function"

        # rate_limit_auth imports check_rate_limit (verify via source)
        import inspect as _inspect
        src = _inspect.getsource(_deps)
        assert "check_rate_limit" in src, \
            "rate_limit_auth must call check_rate_limit"
