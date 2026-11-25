import ipaddress
from typing import Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, rate_limit_auth, rate_limit_refresh
from app.core.config import settings
from app.core.rate_limiter import check_rate_limit
from app.db.models.user import User
from app.db.session import get_db
import uuid as _uuid

from app.schemas.auth import (
    ForgotPasswordRequest,
    LoginRequest,
    LogoutRequest,
    MFAAuthRequest,
    MFARequiredResponse,
    MFASetupResponse,
    MFAVerifyRequest,
    RegisterRequest,
    ResetPasswordRequest,
    SessionResponse,
    TokenResponse,
    UpdateMeRequest,
    UserResponse,
)
from app.services.auth_service import AuthService

logger = structlog.get_logger("mailox.auth")

router = APIRouter(prefix="/auth", tags=["auth"])

_REFRESH_COOKIE = "refresh_token"
_COOKIE_PATH = "/api/v1/auth"
_COOKIE_MAX_AGE = 30 * 24 * 60 * 60  # 30 days in seconds


def _set_refresh_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=_REFRESH_COOKIE,
        value=token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=_COOKIE_MAX_AGE,
        path=_COOKIE_PATH,
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(key=_REFRESH_COOKIE, path=_COOKIE_PATH)


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(rate_limit_auth)])
async def register(
    body: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    service = AuthService(db)
    # The first account of a self-hosted instance becomes platform admin: only
    # hand that out to a request coming from the host itself (same strict check
    # as /auth/local-session), never to whoever reaches the port first.
    user = await service.register(
        body.email, body.password, full_name=body.full_name, invite=body.invite,
        bootstrap_allowed=_request_is_local(request),
    )
    await service._audit(
        "auth.register",
        user_id=user.id,
        ip=request.client.host if request.client else None,
    )
    return UserResponse.model_validate(user)


@router.post("/login", dependencies=[Depends(rate_limit_auth)])
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    service = AuthService(db)
    result = await service.login(
        email=body.email,
        password=body.password,
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    if result.get("mfa_required"):
        return MFARequiredResponse(mfa_token=result["mfa_token"])

    _set_refresh_cookie(response, result["refresh_token"])
    from app.core.config import settings
    return TokenResponse(
        access_token=result["access_token"],
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


_FORWARDING_HEADERS = ("x-forwarded-for", "forwarded", "x-real-ip")
_LOOPBACK_V4 = ipaddress.ip_network("127.0.0.0/8")
_LOOPBACK_V6 = ipaddress.ip_address("::1")


def _parse_ip(value: Optional[str]) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        addr = ipaddress.ip_address((value or "").strip())
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _is_strict_loopback(addr: Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]) -> bool:
    if addr is None:
        return False
    if isinstance(addr, ipaddress.IPv4Address):
        return addr in _LOOPBACK_V4
    return addr == _LOOPBACK_V6



def _forwarded_addresses(request: Request) -> list[str]:
    """Every client address announced by X-Forwarded-For / X-Real-IP / Forwarded, raw.

    Entries that are not plain addresses (Forwarded obfuscated identifiers,
    "unknown", garbage) are kept as-is: they fail to parse later, so such a
    request is never treated as local.
    """
    values: list[str] = []
    for raw in request.headers.getlist("x-forwarded-for"):
        values += [p.strip() for p in raw.split(",") if p.strip()]
    for raw in request.headers.getlist("x-real-ip"):
        if raw.strip():
            values.append(raw.strip())
    for raw in request.headers.getlist("forwarded"):
        for element in raw.split(","):
            for pair in element.split(";"):
                key, _, val = pair.strip().partition("=")
                if key.strip().lower() == "for":
                    values.append(val.strip().strip('"'))
    return values


def _strip_port(value: str) -> str:
    """'[::1]:5173' -> '::1', '127.0.0.1:5173' -> '127.0.0.1', '::1' unchanged."""
    if value.startswith("["):
        return value[1:].split("]", 1)[0]
    if value.count(":") == 1:
        return value.split(":", 1)[0]
    return value


def _request_is_local(request: Request) -> bool:
    """True only for a request provably sent from this machine.

    - TCP peer not loopback -> False, whatever the headers say (no header trust:
      a remote client can write any X-Forwarded-For it wants).
    - TCP peer loopback, no forwarding header -> direct local client -> True.
    - TCP peer loopback with forwarding headers -> a local reverse proxy (e.g. the
      Vite dev server with xfwd) relayed it: True only if EVERY announced address
      is loopback. A LAN client going through `vite --host` shows up as
      127.0.0.1 at the TCP level but carries its real address in X-Forwarded-For.

    TRUSTED_PROXY_COUNT is deliberately not used here: it only drives the
    rate-limit key, where a wrong guess is not a privilege escalation.
    """
    peer = request.client.host if request.client else None
    if not _is_strict_loopback(_parse_ip(peer)):
        return False
    announced = _forwarded_addresses(request)
    if not any(request.headers.get(h) is not None for h in _FORWARDING_HEADERS):
        return True
    if not announced:
        # Header present but empty / without any "for=": cannot vouch for the client
        return False
    return all(_is_strict_loopback(_parse_ip(_strip_port(a))) for a in announced)


@router.post("/local-session", response_model=TokenResponse)
async def local_session(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Self-hosted edition only: open a session without credentials.

    Disabled unless LOCAL_SESSION_ENABLED=true (404, as if the route did not exist).
    When enabled, only a strict loopback client (127.0.0.0/8, ::1) is accepted.
    """
    if settings.IS_SAAS or not settings.LOCAL_SESSION_ENABLED:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    await check_rate_limit(
        request,
        route_category="local_session",
        limit=settings.RATE_LIMIT_AUTH_RPM,
        window_seconds=60,
    )
    client_ip = request.client.host if request.client else None
    if not _request_is_local(request):
        logger.warning(
            "auth.local_session.rejected",
            peer=client_ip,
            forwarded_for=request.headers.get("x-forwarded-for"),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Local session is only available from this machine (loopback).",
        )
    result = await AuthService(db).local_session(
        ip=client_ip,
        user_agent=request.headers.get("user-agent"),
    )
    _set_refresh_cookie(response, result["refresh_token"])
    return TokenResponse(
        access_token=result["access_token"],
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/refresh", response_model=TokenResponse, dependencies=[Depends(rate_limit_refresh)])
async def refresh(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    raw_rt = request.cookies.get(_REFRESH_COOKIE)
    if not raw_rt:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token provided",
        )

    service = AuthService(db)
    result = await service.refresh_tokens(
        refresh_token=raw_rt,
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    _set_refresh_cookie(response, result["refresh_token"])
    from app.core.config import settings
    return TokenResponse(
        access_token=result["access_token"],
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    body: LogoutRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    service = AuthService(db)

    if body.all_devices:
        await service.revoke_all_sessions(current_user.id)
    else:
        raw_rt = request.cookies.get(_REFRESH_COOKIE)
        if raw_rt:
            await service.revoke_refresh_token(raw_rt)

    await service._audit(
        "auth.logout",
        user_id=current_user.id,
        ip=request.client.host if request.client else None,
        details={"all_devices": body.all_devices},
    )
    _clear_refresh_cookie(response)


@router.get("/sessions", response_model=list[SessionResponse])
async def list_sessions(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[SessionResponse]:
    service = AuthService(db)
    sessions = await service.list_sessions(current_user.id)
    return [SessionResponse.model_validate(s) for s in sessions]


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_session(
    session_id: _uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    service = AuthService(db)
    ok = await service.revoke_session(current_user.id, session_id)
    if not ok:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")


@router.post("/mfa/setup", response_model=MFASetupResponse)
async def mfa_setup(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MFASetupResponse:
    service = AuthService(db)
    result = await service.setup_mfa(current_user)
    return MFASetupResponse(**result)


@router.post("/mfa/verify", status_code=status.HTTP_204_NO_CONTENT,
             dependencies=[Depends(rate_limit_auth)])
async def mfa_verify(
    body: MFAVerifyRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    service = AuthService(db)
    await service.verify_and_enable_mfa(current_user, body.code)


@router.post("/mfa/authenticate", dependencies=[Depends(rate_limit_auth)])
async def mfa_authenticate(
    body: MFAAuthRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    service = AuthService(db)
    result = await service.authenticate_mfa(
        mfa_token=body.mfa_token,
        code=body.code,
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    _set_refresh_cookie(response, result["refresh_token"])
    from app.core.config import settings
    return TokenResponse(
        access_token=result["access_token"],
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.get("/me", response_model=UserResponse)
async def me(current_user: User = Depends(get_current_user)) -> UserResponse:
    return UserResponse.model_validate(current_user)


@router.patch("/me", response_model=UserResponse)
async def update_me(
    body: UpdateMeRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    service = AuthService(db)
    user = await service.update_me(current_user, body.full_name)
    await service._audit(
        "auth.update_me",
        user_id=user.id,
        ip=request.client.host if request.client else None,
        details={"fields": ["full_name"]},
    )
    return UserResponse.model_validate(user)


@router.post("/forgot-password", status_code=status.HTTP_204_NO_CONTENT,
             dependencies=[Depends(rate_limit_auth)])
async def forgot_password(
    body: ForgotPasswordRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> None:
    service = AuthService(db)
    await service.forgot_password(
        email=body.email,
        ip=request.client.host if request.client else None,
    )


@router.post("/reset-password", status_code=status.HTTP_204_NO_CONTENT,
             dependencies=[Depends(rate_limit_auth)])
async def reset_password(
    body: ResetPasswordRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> None:
    service = AuthService(db)
    await service.reset_password(
        token=body.token,
        new_password=body.new_password,
        ip=request.client.host if request.client else None,
    )
