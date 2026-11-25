import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import pyotp
from fastapi import HTTPException, status
from jwt import PyJWTError as JWTError
from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.crypto import decrypt, encrypt
from app.core.logging import get_logger
from app.core.security import (
    create_access_token,
    create_mfa_token,
    decode_mfa_token,
    generate_refresh_token,
    hash_password,
    hash_refresh_token,
    needs_rehash,
    verify_password,
)
from app.db.models.audit import AuditLog
from app.db.models.auth_tokens import RefreshToken
from app.db.models.organization import OrganizationMember
from app.db.models.user import User

logger = get_logger("mailox.auth")

LOCAL_USER_EMAIL = "local@mailox.localhost"

_SENTINEL_HASH = hash_password("timing_prevention_sentinel_do_not_use")

_INVALID_CREDENTIALS = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Invalid credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


class AuthService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def register(
        self, email: str, password: str, full_name: Optional[str] = None,
        invite: Optional[str] = None, bootstrap_allowed: bool = False,
    ) -> User:
        # Local import: access_service imports email_service, which this module must not need at import time
        from app.services.access_service import AccessService

        email = email.lower().strip()
        access = AccessService(self.db)
        make_admin, invite_row = await access.authorize_registration(
            email, invite, bootstrap_allowed=bootstrap_allowed,
        )

        result = await self.db.execute(select(User).where(User.email == email))
        if result.scalar_one_or_none():
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

        user = User(
            email=email,
            password_hash=hash_password(password),
            full_name=full_name.strip() if full_name else None,
            is_platform_admin=make_admin,
        )
        self.db.add(user)
        if invite_row is not None:
            await access.consume_invite(invite_row)
        await self.db.flush()
        if make_admin:
            logger.info("auth.first_user_is_platform_admin", user_id=str(user.id))
        return user

    async def local_session(self, ip: Optional[str], user_agent: Optional[str]) -> dict:
        """Self-hosted edition: a session without any login.

        The tool runs on the operator's machine, so there are no accounts to manage.
        The session belongs to the instance owner: the earliest active platform admin,
        else the earliest active account (existing installs keep their data), else a
        local account created on first launch, with a workspace.
        """
        from app.services.organization_service import OrganizationService

        user = (await self.db.execute(
            select(User).where(User.is_active == True, User.is_platform_admin == True)  # noqa: E712
            .order_by(User.created_at).limit(1)
        )).scalar_one_or_none()
        if user is None:
            user = (await self.db.execute(
                select(User).where(User.is_active == True).order_by(User.created_at).limit(1)  # noqa: E712
            )).scalar_one_or_none()
        if user is None:
            user = User(
                email=LOCAL_USER_EMAIL,
                # Unusable password: nobody signs in to this account, the session is local
                password_hash=hash_password(uuid.uuid4().hex + uuid.uuid4().hex),
                full_name="Local",
            )
            self.db.add(user)
            await self.db.flush()
        user.is_platform_admin = True

        has_org = (await self.db.execute(
            select(OrganizationMember.id).where(
                OrganizationMember.user_id == user.id, OrganizationMember.is_active == True  # noqa: E712
            ).limit(1)
        )).scalar_one_or_none()
        if has_org is None:
            slug = "local-" + uuid.uuid4().hex[:6]
            await OrganizationService(self.db).create_organization("Local workspace", slug, user)

        return await self._create_session(user, ip=ip, user_agent=user_agent)

    async def login(
        self,
        email: str,
        password: str,
        ip: Optional[str],
        user_agent: Optional[str],
    ) -> dict:
        email = email.lower().strip()
        result = await self.db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()

        # Always run verify to prevent timing oracle (user existence disclosure)
        _candidate_hash = user.password_hash if user else _SENTINEL_HASH

        if not verify_password(password, _candidate_hash) or user is None:
            if user is not None:
                await self._record_failed_login(user)
            raise _INVALID_CREDENTIALS

        # Check lockout AFTER verify (prevents lockout timing oracle)
        if user.locked_until and user.locked_until > datetime.now(timezone.utc):
            raise _INVALID_CREDENTIALS

        if not user.is_active:
            raise _INVALID_CREDENTIALS

        # Reset lockout state
        user.failed_login_attempts = 0
        user.locked_until = None

        # Upgrade hash if Argon2 params changed
        if needs_rehash(user.password_hash):
            user.password_hash = hash_password(password)

        await self.db.flush()

        if user.mfa_enabled:
            mfa_token = create_mfa_token(user.id)
            await self._audit("auth.mfa_required", user_id=user.id, ip=ip)
            return {"mfa_required": True, "mfa_token": mfa_token}

        session = await self._create_session(user, ip, user_agent)
        await self._audit("auth.login", user_id=user.id, ip=ip)
        return session

    async def _record_failed_login(self, user: User) -> None:
        # The counter must be committed: the caller raises 401 right after and
        # get_db() rolls the request session back, which would discard it and
        # make lockout unreachable. The commit must not carry anything else.
        # login() only reads before calling this, so the request session holds no
        # other change; if some ORM change is pending anyway, the counter goes
        # through a dedicated session instead and the request session is left
        # untouched (it will be rolled back by get_db()).
        unrelated = [o for o in (*self.db.new, *self.db.dirty, *self.db.deleted) if o is not user]
        if unrelated:
            from app.db import session as _db_session
            logger.warning("auth.failed_login.unrelated_pending_changes", count=len(unrelated))
            async with _db_session.AsyncSessionLocal() as s:
                await self._bump_failed_login(s, user.id)
                await s.commit()
            return
        await self._bump_failed_login(self.db, user.id)
        await self.db.commit()
        # Core UPDATEs bypass the identity map: reload the counters
        await self.db.refresh(user, attribute_names=["failed_login_attempts", "locked_until"])

    @staticmethod
    async def _bump_failed_login(db: AsyncSession, user_id: uuid.UUID) -> None:
        now = datetime.now(timezone.utc)
        # An expired lock starts a fresh window: without this reset, a single
        # wrong attempt after expiry would re-lock the account (targeted DoS).
        await db.execute(
            update(User)
            .where(User.id == user_id, User.locked_until.is_not(None), User.locked_until <= now)
            .values(failed_login_attempts=0, locked_until=None)
            .execution_options(synchronize_session=False)
        )
        attempts = (await db.execute(
            update(User)
            .where(User.id == user_id)
            .values(failed_login_attempts=User.failed_login_attempts + 1)
            .returning(User.failed_login_attempts)
            .execution_options(synchronize_session=False)
        )).scalar_one_or_none()
        if attempts is not None and attempts >= settings.ACCOUNT_LOCKOUT_ATTEMPTS:
            await db.execute(
                update(User)
                .where(User.id == user_id)
                .values(locked_until=now + timedelta(minutes=settings.ACCOUNT_LOCKOUT_MINUTES))
                .execution_options(synchronize_session=False)
            )
            logger.warning("auth.account_locked", user_id=str(user_id))

    async def _create_session(
        self,
        user: User,
        ip: Optional[str],
        user_agent: Optional[str],
    ) -> dict:
        result = await self.db.execute(
            select(OrganizationMember)
            .where(
                OrganizationMember.user_id == user.id,
                OrganizationMember.is_active == True,
            )
            .limit(1)
        )
        membership = result.scalar_one_or_none()
        org_id = membership.org_id if membership else None
        role = (
            membership.role.value
            if membership
            else ("platform_admin" if user.is_platform_admin else "none")
        )

        access_token = create_access_token(user.id, org_id, role)
        raw_rt, rt_hash = generate_refresh_token()
        family_id = uuid.uuid4()

        rt = RefreshToken(
            user_id=user.id,
            token_hash=rt_hash,
            family_id=family_id,
            expires_at=datetime.now(timezone.utc)
            + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
            created_at=datetime.now(timezone.utc),
            ip_address=ip,
            user_agent=(user_agent[:512] if user_agent else None),
        )
        self.db.add(rt)
        await self.db.flush()

        return {"access_token": access_token, "refresh_token": raw_rt}

    async def refresh_tokens(
        self,
        refresh_token: str,
        ip: Optional[str],
        user_agent: Optional[str],
    ) -> dict:
        token_hash = hash_refresh_token(refresh_token)

        result = await self.db.execute(
            select(RefreshToken)
            .where(RefreshToken.token_hash == token_hash)
            .with_for_update()
        )
        rt = result.scalar_one_or_none()

        if rt is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
            )

        if rt.is_revoked:
            # Token reuse attack: revoke entire family to force re-login
            await self.db.execute(
                update(RefreshToken)
                .where(RefreshToken.family_id == rt.family_id)
                .values(revoked_at=datetime.now(timezone.utc))
            )
            logger.warning(
                "auth.refresh_token_reuse",
                family_id=str(rt.family_id),
                user_id=str(rt.user_id),
                ip=ip,
            )
            await self._audit(
                "auth.token_reuse_attack",
                user_id=rt.user_id,
                ip=ip,
                details={"family_id": str(rt.family_id)},
            )
            # Commit, not flush: get_db() rolls back on the 401 below, which
            # would undo the family revocation and drop the audit event.
            await self.db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token reuse detected. All sessions revoked.",
            )

        if rt.is_expired:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired"
            )

        # Revoke the consumed token
        rt.revoked_at = datetime.now(timezone.utc)

        user_result = await self.db.execute(select(User).where(User.id == rt.user_id))
        user = user_result.scalar_one_or_none()
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found"
            )

        # Issue new refresh token in the same family
        raw_new, new_hash = generate_refresh_token()
        new_rt = RefreshToken(
            user_id=user.id,
            token_hash=new_hash,
            family_id=rt.family_id,
            expires_at=datetime.now(timezone.utc)
            + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
            created_at=datetime.now(timezone.utc),
            ip_address=ip,
            user_agent=(user_agent[:512] if user_agent else None),
        )
        self.db.add(new_rt)

        # Recompute org/role (membership may have changed)
        m_result = await self.db.execute(
            select(OrganizationMember)
            .where(
                OrganizationMember.user_id == user.id,
                OrganizationMember.is_active == True,
            )
            .limit(1)
        )
        membership = m_result.scalar_one_or_none()
        org_id = membership.org_id if membership else None
        role = (
            membership.role.value
            if membership
            else ("platform_admin" if user.is_platform_admin else "none")
        )

        access_token = create_access_token(user.id, org_id, role)
        await self.db.flush()

        return {"access_token": access_token, "refresh_token": raw_new}

    async def revoke_refresh_token(self, refresh_token: str) -> None:
        token_hash = hash_refresh_token(refresh_token)
        await self.db.execute(
            update(RefreshToken)
            .where(
                RefreshToken.token_hash == token_hash,
                RefreshToken.revoked_at.is_(None),
            )
            .values(revoked_at=datetime.now(timezone.utc))
        )

    async def list_sessions(self, user_id: uuid.UUID) -> list:
        from sqlalchemy import select
        now = datetime.now(timezone.utc)
        result = await self.db.execute(
            select(RefreshToken).where(
                RefreshToken.user_id == user_id,
                RefreshToken.revoked_at.is_(None),
                RefreshToken.expires_at > now,
            ).order_by(RefreshToken.created_at.desc())
        )
        return result.scalars().all()

    async def revoke_session(self, user_id: uuid.UUID, session_id: uuid.UUID) -> bool:
        from sqlalchemy import select
        result = await self.db.execute(
            select(RefreshToken).where(
                RefreshToken.id == session_id,
                RefreshToken.user_id == user_id,
                RefreshToken.revoked_at.is_(None),
            )
        )
        token = result.scalar_one_or_none()
        if not token:
            return False
        token.revoked_at = datetime.now(timezone.utc)
        await self.db.flush()
        return True

    async def revoke_all_sessions(self, user_id: uuid.UUID) -> None:
        await self.db.execute(
            update(RefreshToken)
            .where(
                RefreshToken.user_id == user_id,
                RefreshToken.revoked_at.is_(None),
            )
            .values(revoked_at=datetime.now(timezone.utc))
        )

    @staticmethod
    def _generate_backup_codes(n: int = 8) -> list[str]:
        import secrets as _secrets
        return [_secrets.token_hex(5).upper() for _ in range(n)]

    async def setup_mfa(self, user: User) -> dict:
        if user.mfa_enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="MFA already enabled"
            )
        import json as _json
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        otpauth_uri = totp.provisioning_uri(user.email, issuer_name=settings.MFA_ISSUER)
        backup_codes = self._generate_backup_codes()
        user.mfa_secret_encrypted = encrypt(secret.encode("utf-8"), purpose="mfa_secrets")
        user.mfa_backup_codes_encrypted = encrypt(
            _json.dumps(backup_codes).encode("utf-8"), purpose="mfa_secrets"
        )
        await self.db.flush()
        return {"secret": secret, "otpauth_uri": otpauth_uri, "backup_codes": backup_codes}

    async def verify_and_enable_mfa(self, user: User, code: str) -> None:
        if not user.mfa_secret_encrypted:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="MFA setup not initiated"
            )
        secret = decrypt(user.mfa_secret_encrypted, purpose="mfa_secrets").decode("utf-8")
        totp = pyotp.TOTP(secret)

        if not totp.verify(code, valid_window=1):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid TOTP code")

        totp_result = await self.db.execute(
            update(User)
            .where(
                User.id == user.id,
                or_(User.mfa_last_used_totp.is_(None), User.mfa_last_used_totp != code),
            )
            .values(mfa_enabled=True, mfa_last_used_totp=code)
            .returning(User.id)
        )
        if not totp_result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="TOTP code already used"
            )
        await self.db.refresh(user)

    async def authenticate_mfa(
        self,
        mfa_token: str,
        code: str,
        ip: Optional[str],
        user_agent: Optional[str],
    ) -> dict:
        try:
            payload = decode_mfa_token(mfa_token)
            user_id = uuid.UUID(payload["sub"])
            jti = str(payload["jti"])
            if not jti:
                raise ValueError("Missing jti")
        except (JWTError, ValueError, KeyError, TypeError):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA token"
            )

        # Single-use mfa_token: refused once consumed (success) or burned (too many failures)
        await self._check_mfa_token_usable(jti)

        result = await self.db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()

        if not user or not user.mfa_enabled or not user.mfa_secret_encrypted:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid request"
            )

        await self._check_mfa_failures(user.id)

        secret = decrypt(user.mfa_secret_encrypted, purpose="mfa_secrets").decode("utf-8")
        totp = pyotp.TOTP(secret)
        used_backup = False

        if not totp.verify(code, valid_window=1):
            # Try backup codes (single-use; consumed on match)
            if not user.mfa_backup_codes_encrypted:
                await self._record_mfa_failure(user.id, jti)
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid TOTP code")
            import hmac as _hmac
            import json as _json
            backup_codes: list[str] = _json.loads(
                decrypt(user.mfa_backup_codes_encrypted, purpose="mfa_secrets").decode("utf-8")
            )
            normalized = code.replace("-", "").upper().encode("utf-8")
            # Constant-time match against every stored code (no early exit)
            matched: Optional[str] = None
            for candidate in backup_codes:
                if _hmac.compare_digest(candidate.encode("utf-8"), normalized):
                    matched = candidate
            if matched is None:
                await self._record_mfa_failure(user.id, jti)
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid TOTP code")
            # Burn the mfa_token before consuming the backup code: two concurrent
            # requests with the same token cannot both succeed.
            await self._consume_mfa_token(jti)
            backup_codes.remove(matched)
            user.mfa_backup_codes_encrypted = encrypt(
                _json.dumps(backup_codes).encode("utf-8"), purpose="mfa_secrets"
            )
            await self.db.flush()
            used_backup = True

        if not used_backup:
            await self._consume_mfa_token(jti)
            mfa_result = await self.db.execute(
                update(User)
                .where(
                    User.id == user.id,
                    or_(User.mfa_last_used_totp.is_(None), User.mfa_last_used_totp != code),
                )
                .values(mfa_last_used_totp=code)
                .returning(User.id)
            )
            if not mfa_result.scalar_one_or_none():
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail="TOTP code already used"
                )
        await self.db.refresh(user)
        await self._clear_mfa_failures(user.id)

        session = await self._create_session(user, ip, user_agent)
        await self._audit("auth.mfa_login", user_id=user.id, ip=ip)
        return session

    # Per-account MFA failure counter (Redis). The /mfa/authenticate rate limit
    # is per IP only, so without this an attacker rotating IPs could brute-force
    # the TOTP once the password is known. Fail-secure on Redis errors, like the
    # rate limiter.
    @staticmethod
    def _mfa_fail_key(user_id: uuid.UUID) -> str:
        return f"rl:mfa:{user_id}"

    async def _check_mfa_failures(self, user_id: uuid.UUID) -> None:
        from app.core.redis_client import get_redis
        try:
            raw = await get_redis().get(self._mfa_fail_key(user_id))
        except Exception as exc:
            logger.error("auth.mfa_counter.redis_error", error=type(exc).__name__)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Service temporarily unavailable",
                headers={"Retry-After": "30"},
            )
        if raw is not None and int(raw) >= settings.ACCOUNT_LOCKOUT_ATTEMPTS:
            logger.warning("auth.mfa_locked", user_id=str(user_id))
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed MFA attempts. Try again later.",
                headers={"Retry-After": str(settings.ACCOUNT_LOCKOUT_MINUTES * 60)},
            )

    # mfa_token single use. The token lives 5 min; keys outlive it slightly.
    _MFA_TOKEN_TTL_SECONDS = 6 * 60
    # Wrong codes tolerated on one mfa_token before it is burned (the per-account
    # counter above still applies across tokens).
    _MFA_TOKEN_MAX_FAILURES = 3

    @staticmethod
    def _mfa_used_key(jti: str) -> str:
        return f"mfa:used:{jti}"

    @staticmethod
    def _mfa_token_fail_key(jti: str) -> str:
        return f"rl:mfa_token:{jti}"

    @staticmethod
    def _redis_unavailable() -> HTTPException:
        return HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable",
            headers={"Retry-After": "30"},
        )

    async def _check_mfa_token_usable(self, jti: str) -> None:
        from app.core.redis_client import get_redis
        try:
            used = await get_redis().exists(self._mfa_used_key(jti))
        except Exception as exc:
            logger.error("auth.mfa_token.redis_error", op="check", error=type(exc).__name__)
            raise self._redis_unavailable()
        if used:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA token"
            )

    async def _consume_mfa_token(self, jti: str) -> None:
        """Atomically mark the mfa_token as used (SET NX). Fail-secure."""
        from app.core.redis_client import get_redis
        try:
            first = await get_redis().set(
                self._mfa_used_key(jti), "1", nx=True, ex=self._MFA_TOKEN_TTL_SECONDS
            )
        except Exception as exc:
            logger.error("auth.mfa_token.redis_error", op="consume", error=type(exc).__name__)
            raise self._redis_unavailable()
        if not first:
            logger.warning("auth.mfa_token.replay", jti=jti)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA token"
            )

    async def _record_mfa_failure(self, user_id: uuid.UUID, jti: Optional[str] = None) -> None:
        from app.core.redis_client import get_redis
        key = self._mfa_fail_key(user_id)
        try:
            redis = get_redis()
            count = await redis.incr(key)
            if count == 1:
                await redis.expire(key, settings.ACCOUNT_LOCKOUT_MINUTES * 60)
            if jti:
                tok_key = self._mfa_token_fail_key(jti)
                tok_count = await redis.incr(tok_key)
                if tok_count == 1:
                    await redis.expire(tok_key, self._MFA_TOKEN_TTL_SECONDS)
                if tok_count >= self._MFA_TOKEN_MAX_FAILURES:
                    await redis.set(self._mfa_used_key(jti), "burned", ex=self._MFA_TOKEN_TTL_SECONDS)
                    logger.warning("auth.mfa_token.burned", user_id=str(user_id))
        except Exception as exc:
            # The caller still answers 401; the read side (_check_*) stays fail-secure.
            logger.error(
                "auth.mfa_counter.redis_write_failed",
                user_id=str(user_id), error=type(exc).__name__, detail=str(exc)[:200],
            )

    async def _clear_mfa_failures(self, user_id: uuid.UUID) -> None:
        from app.core.redis_client import get_redis
        try:
            await get_redis().delete(self._mfa_fail_key(user_id))
        except Exception as exc:
            logger.error("auth.mfa_counter.redis_error", error=type(exc).__name__)

    async def update_me(self, user: User, full_name: Optional[str]) -> User:
        user.full_name = full_name
        await self.db.flush()
        await self.db.refresh(user)
        return user

    @staticmethod
    def _pw_reset_key(token: str) -> str:
        # Only a hash of the token sits in Redis: a Redis dump does not yield usable links
        import hashlib as _hashlib
        return "pw_reset:" + _hashlib.sha256(token.encode("utf-8")).hexdigest()

    async def forgot_password(self, email: str, ip: Optional[str] = None) -> None:
        """Stores a reset token in Redis (TTL 900s). Never reveals if email exists.

        The caller always answers 204: any internal failure on the "account exists"
        branch (Redis, mail delivery) is logged and swallowed so the response cannot
        be used as an account-enumeration oracle.
        """
        import secrets as _secrets
        from app.core.redis_client import get_redis

        email = email.lower().strip()
        result = await self.db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()
        if not (user and user.is_active):
            return
        try:
            token = _secrets.token_urlsafe(32)
            await get_redis().setex(self._pw_reset_key(token), 900, str(user.id))
            await self._audit(
                "auth.forgot_password",
                user_id=user.id,
                ip=ip,
                details={"email": email},
            )
            logger.info("auth.forgot_password.token_issued", user_id=str(user.id))
            from app.services.email_service import send_password_reset_email
            await send_password_reset_email(to=email, token=token)
        except Exception as exc:
            logger.error("auth.forgot_password.failed", user_id=str(user.id), error=type(exc).__name__)

    async def reset_password(self, token: str, new_password: str, ip: Optional[str] = None) -> None:
        from app.core.redis_client import get_redis
        redis = get_redis()
        # Atomic read+delete (MULTI/EXEC, i.e. GETDEL semantics but also on Redis < 6.2):
        # two concurrent requests cannot both consume the same token.
        async with redis.pipeline(transaction=True) as pipe:
            pipe.get(self._pw_reset_key(token))
            pipe.delete(self._pw_reset_key(token))
            raw, _ = await pipe.execute()
        if not raw:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token",
            )
        try:
            user_id = uuid.UUID(raw.decode() if isinstance(raw, bytes) else raw)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token")

        result = await self.db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        if not user or not user.is_active:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User not found")

        user.password_hash = hash_password(new_password)
        user.failed_login_attempts = 0
        user.locked_until = None
        # Revoke all refresh tokens (force re-login on all devices)
        await self.db.execute(
            update(RefreshToken)
            .where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=datetime.now(timezone.utc))
        )
        await self.db.flush()
        await self._audit("auth.password_reset", user_id=user.id, ip=ip)
        logger.info("auth.password_reset.success", user_id=str(user.id))

    async def _audit(
        self,
        action: str,
        user_id: Optional[uuid.UUID] = None,
        org_id: Optional[uuid.UUID] = None,
        ip: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[dict] = None,
    ) -> None:
        log_entry = AuditLog(
            id=uuid.uuid4(),
            org_id=org_id,
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip,
            created_at=datetime.now(timezone.utc),
        )
        self.db.add(log_entry)
        await self.db.flush()
