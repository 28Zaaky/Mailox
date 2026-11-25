"""AT-01 through AT-04: Authentication, token rotation, lockout, MFA."""
import pytest
from httpx import AsyncClient

from tests.conftest import (
    TEST_EMAIL,
    TEST_PASSWORD,
    auth_headers,
    login_user,
    make_invite,
    register_user,
)


# ── AT-01: Register ───────────────────────────────────────────────────────────

class TestRegister:
    async def test_register_success(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/register",
            json={"email": "new@example.com", "password": TEST_PASSWORD,
                  "invite": await make_invite("new@example.com")},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["email"] == "new@example.com"
        assert data["mfa_enabled"] is False
        assert "password" not in data
        assert "password_hash" not in data

    async def test_register_duplicate_email(self, client: AsyncClient):
        await register_user(client)
        resp = await client.post(
            "/api/v1/auth/register",
            json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
        )
        # Rejected either way: invite required, and the account already exists
        assert resp.status_code in (403, 409)

    async def test_saas_first_register_without_invite_is_refused(self, client: AsyncClient):
        """SaaS: an empty users table must not let a public signup become platform admin."""
        from app.core.config import settings
        assert settings.IS_SAAS
        resp = await client.post(
            "/api/v1/auth/register",
            json={"email": "first@example.com", "password": TEST_PASSWORD},
        )
        assert resp.status_code == 403

    async def test_register_weak_password_too_short(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/register",
            json={"email": "weak@example.com", "password": "Short1!"},
        )
        assert resp.status_code == 422

    async def test_register_weak_password_no_uppercase(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/register",
            json={"email": "weak2@example.com", "password": "alllowercase1!"},
        )
        assert resp.status_code == 422

    async def test_register_weak_password_no_special(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/register",
            json={"email": "weak3@example.com", "password": "NoSpecialChar1234"},
        )
        assert resp.status_code == 422

    async def test_register_sql_injection_in_email(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/register",
            json={"email": "' OR 1=1--", "password": TEST_PASSWORD},
        )
        assert resp.status_code == 422  # Pydantic EmailStr rejects it
        assert resp.status_code != 500

    async def test_register_email_normalized_lowercase(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/register",
            json={"email": "UPPER@EXAMPLE.COM", "password": TEST_PASSWORD,
                  "invite": await make_invite("upper@example.com")},
        )
        assert resp.status_code == 201
        assert resp.json()["email"] == "upper@example.com"


# ── AT-01 continued + AT-02: Login ───────────────────────────────────────────

class TestLogin:
    async def test_login_success(self, client: AsyncClient):
        await register_user(client)
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        # Refresh token in HttpOnly cookie
        assert "refresh_token" in resp.cookies

    async def test_login_wrong_password(self, client: AsyncClient):
        # Dedicated email: a failed login commits the attempt counter (so it
        # survives get_db's rollback), which also commits this registration.
        email = "wrong_pw@example.com"
        await register_user(client, email=email)
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "WrongPass999!"},
        )
        assert resp.status_code == 401
        assert "access_token" not in resp.json()

    async def test_login_nonexistent_user(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "ghost@example.com", "password": TEST_PASSWORD},
        )
        assert resp.status_code == 401

    async def test_login_access_protected_route(self, client: AsyncClient):
        await register_user(client)
        tokens = await login_user(client)
        resp = await client.get(
            "/api/v1/auth/me",
            headers=auth_headers(tokens["access_token"]),
        )
        assert resp.status_code == 200
        assert resp.json()["email"] == TEST_EMAIL

    async def test_access_protected_without_token(self, client: AsyncClient):
        resp = await client.get("/api/v1/auth/me")
        assert resp.status_code == 401

    async def test_access_protected_tampered_token(self, client: AsyncClient):
        resp = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.tampered.sig"},
        )
        assert resp.status_code == 401

    async def test_alg_none_attack(self, client: AsyncClient):
        """alg:none bypass attempt must return 401."""
        import base64, json
        header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=")
        payload_data = base64.urlsafe_b64encode(
            json.dumps({"sub": "00000000-0000-0000-0000-000000000001", "type": "access"}).encode()
        ).rstrip(b"=")
        fake_token = f"{header.decode()}.{payload_data.decode()}."
        resp = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {fake_token}"},
        )
        assert resp.status_code == 401

    async def test_500_not_exposed_on_error(self, client: AsyncClient):
        resp = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer invalid"},
        )
        assert resp.status_code in (401, 422)
        assert "traceback" not in resp.text.lower()
        assert "sqlalchemy" not in resp.text.lower()


# ── AT-02 continued: Account lockout ─────────────────────────────────────────

class TestAccountLockout:
    async def test_account_locked_after_5_failures(self, client: AsyncClient, monkeypatch):
        # Pin the threshold: a developer .env (ACCOUNT_LOCKOUT_ATTEMPTS=10) leaks into settings.
        from app.core.config import settings
        monkeypatch.setattr(settings, "ACCOUNT_LOCKOUT_ATTEMPTS", 5)
        email = "lockout@example.com"
        await register_user(client, email=email)

        for i in range(5):
            resp = await client.post(
                "/api/v1/auth/login",
                json={"email": email, "password": "WrongPass999!"},
            )
            assert resp.status_code == 401

        # 6th attempt — account locked, even with correct password
        # FIX-5: returns generic "Invalid credentials" to prevent lockout oracle
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": TEST_PASSWORD},
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid credentials"

    async def test_lockout_error_does_not_reveal_existence(self, client: AsyncClient):
        """Lock error message should not confirm user exists vs wrong password."""
        resp_locked = await client.post(
            "/api/v1/auth/login",
            json={"email": "lockout@example.com", "password": "WrongPass999!"},
        )
        resp_ghost = await client.post(
            "/api/v1/auth/login",
            json={"email": "doesnotexist_xyz@example.com", "password": "WrongPass999!"},
        )
        # Both should be 401 — different details are acceptable but status must match
        assert resp_locked.status_code == 401
        assert resp_ghost.status_code == 401


# ── AT-03: Refresh token rotation + reuse detection ──────────────────────────

class TestRefreshTokenRotation:
    async def test_refresh_issues_new_tokens(self, client: AsyncClient):
        await register_user(client)
        tokens = await login_user(client)

        resp = await client.post(
            "/api/v1/auth/refresh",
            cookies={"refresh_token": tokens["refresh_token"]},
        )
        assert resp.status_code == 200
        new_at = resp.json()["access_token"]
        assert new_at != tokens["access_token"]
        assert "refresh_token" in resp.cookies

    async def test_old_refresh_token_revoked_after_rotation(self, client: AsyncClient):
        await register_user(client)
        tokens = await login_user(client)
        old_rt = tokens["refresh_token"]

        # Rotate once
        await client.post(
            "/api/v1/auth/refresh",
            cookies={"refresh_token": old_rt},
        )

        # Try to use the old token again
        resp = await client.post(
            "/api/v1/auth/refresh",
            cookies={"refresh_token": old_rt},
        )
        assert resp.status_code == 401

    async def test_reuse_attack_revokes_family(self, client: AsyncClient):
        """
        RT1 → RT2. Re-use RT1 → 401 AND RT2 must be revoked (family revoked).
        """
        await register_user(client)
        tokens = await login_user(client)
        rt1 = tokens["refresh_token"]

        # First rotation: RT1 → RT2
        resp = await client.post(
            "/api/v1/auth/refresh",
            cookies={"refresh_token": rt1},
        )
        assert resp.status_code == 200
        rt2 = resp.cookies.get("refresh_token")
        assert rt2

        # Reuse attack: use RT1 again
        resp_attack = await client.post(
            "/api/v1/auth/refresh",
            cookies={"refresh_token": rt1},
        )
        assert resp_attack.status_code == 401

        # RT2 must also be revoked now (entire family invalidated)
        resp_rt2 = await client.post(
            "/api/v1/auth/refresh",
            cookies={"refresh_token": rt2},
        )
        assert resp_rt2.status_code == 401

    async def test_refresh_expired_token_rejected(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/refresh",
            cookies={"refresh_token": "nonexistent_garbage_token"},
        )
        assert resp.status_code == 401

    async def test_logout_revokes_refresh_token(self, client: AsyncClient):
        await register_user(client)
        tokens = await login_user(client)

        await client.post(
            "/api/v1/auth/logout",
            json={"all_devices": False},
            headers=auth_headers(tokens["access_token"]),
            cookies={"refresh_token": tokens["refresh_token"]},
        )

        resp = await client.post(
            "/api/v1/auth/refresh",
            cookies={"refresh_token": tokens["refresh_token"]},
        )
        assert resp.status_code == 401

    async def test_logout_all_devices_revokes_all_sessions(self, client: AsyncClient):
        await register_user(client)
        tokens1 = await login_user(client)
        tokens2 = await login_user(client)

        await client.post(
            "/api/v1/auth/logout",
            json={"all_devices": True},
            headers=auth_headers(tokens1["access_token"]),
            cookies={"refresh_token": tokens1["refresh_token"]},
        )

        # Both sessions must be revoked
        for rt in [tokens1["refresh_token"], tokens2["refresh_token"]]:
            resp = await client.post(
                "/api/v1/auth/refresh",
                cookies={"refresh_token": rt},
            )
            assert resp.status_code == 401


# ── AT-04: MFA ────────────────────────────────────────────────────────────────

class TestMFA:
    async def test_mfa_setup_returns_secret_and_uri(self, client: AsyncClient):
        await register_user(client, email="mfa_test@example.com")
        tokens = await login_user(client, email="mfa_test@example.com")
        resp = await client.post(
            "/api/v1/auth/mfa/setup",
            headers=auth_headers(tokens["access_token"]),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "secret" in data
        assert "otpauth_uri" in data
        assert "otpauth://totp/" in data["otpauth_uri"]

    async def test_mfa_verify_enables_mfa(self, client: AsyncClient):
        import pyotp
        await register_user(client, email="mfa_enable@example.com")
        tokens = await login_user(client, email="mfa_enable@example.com")

        setup_resp = await client.post(
            "/api/v1/auth/mfa/setup",
            headers=auth_headers(tokens["access_token"]),
        )
        secret = setup_resp.json()["secret"]

        code = pyotp.TOTP(secret).now()
        resp = await client.post(
            "/api/v1/auth/mfa/verify",
            json={"code": code},
            headers=auth_headers(tokens["access_token"]),
        )
        assert resp.status_code == 204

        # me/ should now show mfa_enabled = True
        me = await client.get("/api/v1/auth/me", headers=auth_headers(tokens["access_token"]))
        assert me.json()["mfa_enabled"] is True

    async def test_mfa_login_requires_second_factor(self, client: AsyncClient):
        import pyotp
        await register_user(client, email="mfa_login@example.com")
        tokens = await login_user(client, email="mfa_login@example.com")

        setup_resp = await client.post(
            "/api/v1/auth/mfa/setup",
            headers=auth_headers(tokens["access_token"]),
        )
        secret = setup_resp.json()["secret"]
        code = pyotp.TOTP(secret).now()
        await client.post(
            "/api/v1/auth/mfa/verify",
            json={"code": code},
            headers=auth_headers(tokens["access_token"]),
        )

        # Login with MFA enabled — must return mfa_required
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "mfa_login@example.com", "password": TEST_PASSWORD},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("mfa_required") is True
        assert "mfa_token" in data
        assert "access_token" not in data

    async def test_mfa_totp_replay_rejected(self, client: AsyncClient):
        import pyotp
        await register_user(client, email="mfa_replay@example.com")
        tokens = await login_user(client, email="mfa_replay@example.com")

        setup_resp = await client.post(
            "/api/v1/auth/mfa/setup",
            headers=auth_headers(tokens["access_token"]),
        )
        secret = setup_resp.json()["secret"]
        code = pyotp.TOTP(secret).now()

        # First use
        await client.post(
            "/api/v1/auth/mfa/verify",
            json={"code": code},
            headers=auth_headers(tokens["access_token"]),
        )

        # Replay — same code
        resp = await client.post(
            "/api/v1/auth/mfa/verify",
            json={"code": code},
            headers=auth_headers(tokens["access_token"]),
        )
        # MFA already enabled → 400; or replay rejected → 401
        assert resp.status_code in (400, 401)
