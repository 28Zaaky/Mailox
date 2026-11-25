import uuid
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp, Receive, Scope, Send

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.logging import configure_logging

logger = structlog.get_logger("mailox.main")


_SECURITY_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"strict-origin-when-cross-origin"),
    (b"permissions-policy", b"geolocation=(), microphone=(), camera=()"),
    (b"strict-transport-security", b"max-age=63072000; includeSubDomains"),
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
    (b"x-xss-protection", b"0"),
]


class SecurityHeadersMiddleware:
    """Pure ASGI middleware — avoids BaseHTTPMiddleware's anyio deadlock."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: dict) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend(_SECURITY_HEADERS)
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging(debug=settings.DEBUG)
    logger.info("startup", app=settings.APP_NAME, version=settings.APP_VERSION)
    yield
    logger.info("shutdown")


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        openapi_url=f"{settings.API_V1_PREFIX}/openapi.json" if settings.DEBUG else None,
        docs_url=f"{settings.API_V1_PREFIX}/docs" if settings.DEBUG else None,
        redoc_url=None,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Requested-With", "Idempotency-Key"],
        expose_headers=["X-Request-ID"],
        max_age=600,
    )
    app.add_middleware(SecurityHeadersMiddleware)
    if settings.ALLOWED_HOSTS != "*":
        allowed_hosts = [h.strip() for h in settings.ALLOWED_HOSTS.split(",") if h.strip()]
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception):
        correlation_id = str(uuid.uuid4())
        logger.error(
            "unhandled_exception",
            correlation_id=correlation_id,
            path=request.url.path,
            method=request.method,
            exc_info=exc,
        )
        # Never expose internal details to clients
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "correlation_id": correlation_id},
        )

    app.include_router(api_router, prefix=settings.API_V1_PREFIX)

    return app


app = create_app()
