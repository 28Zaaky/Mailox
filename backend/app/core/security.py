import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
import jwt  # PyJWT

from app.core.config import settings

# Argon2id — OWASP recommended (prod) vs fast (tests)
import os as _os
_testing = _os.environ.get("TESTING", "").lower() in ("1", "true", "yes")
_ph = PasswordHasher(
    time_cost=1 if _testing else 2,
    memory_cost=8192 if _testing else 65536,  # 8MB tests, 64MB prod
    parallelism=1 if _testing else 2,
    hash_len=32,
    salt_len=16,
)
if _testing:
    import warnings
    warnings.warn(
        "TESTING mode active: Argon2 work factor reduced. Never use in production.",
        RuntimeWarning,
        stacklevel=1,
    )

ALGORITHM = "HS256"
# Never allow algorithm negotiation — explicit list only
_ALLOWED_ALGORITHMS = ["HS256"]
# Every token we issue carries these; a token without them is rejected (PyJWT
# then raises MissingRequiredClaimError, a PyJWTError -> 401).
_REQUIRED_CLAIMS = ["exp", "iat", "sub", "jti"]


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return _ph.verify(hashed, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(hashed: str) -> bool:
    return _ph.check_needs_rehash(hashed)


def create_access_token(
    user_id: uuid.UUID,
    org_id: Optional[uuid.UUID],
    role: str,
) -> str:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),
        "org_id": str(org_id) if org_id else None,
        "role": role,
        "jti": str(uuid.uuid4()),
        "type": "access",
        "iat": now,
        "exp": expire,
    }
    return jwt.encode(payload, settings.SECRET_KEY.get_secret_value(), algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    payload = jwt.decode(
        token,
        settings.SECRET_KEY.get_secret_value(),
        algorithms=_ALLOWED_ALGORITHMS,
        options={"require": _REQUIRED_CLAIMS},
    )
    if payload.get("type") != "access":
        raise ValueError("Wrong token type")
    return payload


def create_mfa_token(user_id: uuid.UUID) -> str:
    """Short-lived token (5 min) used only to complete MFA after first factor."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "type": "mfa_pending",
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + timedelta(minutes=5),
    }
    return jwt.encode(payload, settings.SECRET_KEY.get_secret_value(), algorithm=ALGORITHM)


def decode_mfa_token(token: str) -> dict:
    payload = jwt.decode(
        token,
        settings.SECRET_KEY.get_secret_value(),
        algorithms=_ALLOWED_ALGORITHMS,
        options={"require": _REQUIRED_CLAIMS},
    )
    if payload.get("type") != "mfa_pending":
        raise ValueError("Wrong token type")
    return payload


def generate_refresh_token() -> tuple[str, str]:
    """
    Returns (raw_token, token_hash).
    Store ONLY the hash. Send the raw token to the client.
    """
    raw = secrets.token_urlsafe(32)
    token_hash = _hash_token(raw)
    return raw, token_hash


def hash_refresh_token(raw: str) -> str:
    return _hash_token(raw)


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def secure_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
