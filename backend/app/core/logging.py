import logging
import re
from typing import Any

import structlog

_SENSITIVE_KEYS = frozenset({
    "password", "passwd", "secret", "token", "key", "credential",
    "authorization", "cookie", "refresh_token", "access_token",
    "mfa_secret", "api_key", "private_key", "passphrase",
    "email", "username", "ip_address", "user_agent",
    "database_url", "redis_url", "connection_string", "dsn",
})

_SENSITIVE_PATTERN = re.compile(
    r'(?i)(password|passwd|secret|token|key|credential|authorization)["\s:=]+\S+',
)


def _scrub_sensitive_processor(
    logger: Any, method: str, event_dict: dict
) -> dict:
    """Strip sensitive values from structured log events."""
    for key in list(event_dict.keys()):
        if key.lower() in _SENSITIVE_KEYS:
            event_dict[key] = "***REDACTED***"
    # Also scrub string values containing sensitive patterns
    for key, value in event_dict.items():
        if isinstance(value, str) and _SENSITIVE_PATTERN.search(value):
            event_dict[key] = _SENSITIVE_PATTERN.sub(
                lambda m: m.group(0).split("=")[0] + "=***REDACTED***", value
            )
    return event_dict


def configure_logging(debug: bool = False) -> None:
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            _scrub_sensitive_processor,
            structlog.dev.ConsoleRenderer() if debug else structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.BoundLogger,
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(message)s",
    )


def get_logger(name: str = "mailox") -> structlog.BoundLogger:
    return structlog.get_logger(name)
