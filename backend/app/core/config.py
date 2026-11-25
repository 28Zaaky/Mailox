from typing import List, Literal, Optional
from pydantic import Field, SecretStr, computed_field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        populate_by_name=True,
        # Unknown keys in .env (e.g. APP_ENV from an older template) must not crash
        # uvicorn/alembic/celery; known fields are still validated.
        extra="ignore",
    )

    # App
    APP_NAME: str = "MAILOX"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False
    API_V1_PREFIX: str = "/api/v1"

    # Edition
    # - "selfhosted": open-source install. All features, no access key, no domain
    #   verification. First admin via CLI, then invite-only.
    # - "saas": hosted service. Accounts are created only with a single-use invite issued
    #   by a platform admin, and a domain must be verified (DNS TXT) before it is scanned.
    MAILOX_EDITION: Literal["selfhosted", "saas"] = "saas"
    ALLOW_REGISTRATION: bool = False        # registration is invite-only
    # POST /auth/local-session opens a platform-admin session without credentials.
    # Only for self-hosted local tool mode. Never enable on SaaS.
    LOCAL_SESSION_ENABLED: bool = False
    ACCESS_INVITE_TTL_HOURS: int = 168      # saas: invite validity (7 days)
    ADMIN_NOTIFY_EMAIL: Optional[str] = None  # saas: receives new access requests
    SAAS_MAX_ORGS_PER_USER: int = 1         # saas: the daily scan quota is per org, so cap orgs per account
    DOMAIN_VERIFY_PREFIX: str = "mailox-verify="
    DOMAIN_VERIFY_RECHECK_DAYS: int = 30    # saas: re-read the TXT record when the last check is older

    @computed_field  # type: ignore[prop-decorator]
    @property
    def IS_SAAS(self) -> bool:
        return self.MAILOX_EDITION == "saas"

    # Security — all required, minimum 32 chars
    SECRET_KEY: SecretStr
    REFRESH_SECRET_KEY: SecretStr
    MASTER_ENCRYPTION_KEY: SecretStr

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30

    # Database
    DATABASE_URL: str
    DATABASE_URL_SYNC: str

    # Redis
    REDIS_URL: str

    # Rate limiting
    RATE_LIMIT_AUTH_RPM: int = 10
    ACCOUNT_LOCKOUT_ATTEMPTS: int = 5
    ACCOUNT_LOCKOUT_MINUTES: int = 15

    # Trusted hosts — comma-separated, "*" to allow all (default for dev/test)
    ALLOWED_HOSTS: str = Field("*", alias="ALLOWED_HOSTS")

    # CORS — stored as plain str, exposed as List[str] via computed_field.
    # Env var: ALLOWED_ORIGINS=http://localhost:5173,http://localhost:3000
    # pydantic-settings would try to JSON-decode a List[str] field, so we use str.
    ALLOWED_ORIGINS_CSV: str = Field("", alias="ALLOWED_ORIGINS")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def ALLOWED_ORIGINS(self) -> List[str]:
        if not self.ALLOWED_ORIGINS_CSV:
            return []
        return [o.strip() for o in self.ALLOWED_ORIGINS_CSV.split(",") if o.strip()]

    # MFA
    MFA_ISSUER: str = "MAILOX"

    # Celery / workers
    CELERY_BROKER_URL: str
    CELERY_RESULT_BACKEND: str
    SCAN_TASK_TIMEOUT_SECONDS: int = 120
    SCAN_TASK_MAX_RETRIES: int = 2
    SCAN_TASK_RETRY_COUNTDOWN: int = 30
    # Max concurrent scans per worker process
    WORKER_CONCURRENCY: int = 4
    # Stalled scan recovery: scans stuck in RUNNING for > N seconds are re-queued
    SCAN_STALL_TIMEOUT_SECONDS: int = 180
    # Worker lease / heartbeat
    WORKER_LEASE_DURATION_SECONDS: int = 90
    WORKER_HEARTBEAT_INTERVAL_SECONDS: int = 30
    OUTBOX_DISPATCH_LOCK_SECONDS: int = 60
    SCAN_MAX_FINDINGS_PER_RUN: int = 500
    SCAN_MAX_TOTAL_ATTEMPTS: int = 10

    # SSE streaming
    SSE_POLL_INTERVAL: float = 2.0   # seconds between DB polls
    SSE_MAX_EVENTS: int = 500        # safety cap per connection
    # Distributed SSE lease settings
    SSE_MAX_PER_ORG: int = 20        # max SSE connections per org (across all instances)
    SSE_MAX_GLOBAL: int = 200        # max SSE connections total (across all instances)
    SSE_LEASE_TTL_SECONDS: int = 90  # lease expires if no heartbeat for this long
    SSE_HEARTBEAT_INTERVAL_SECONDS: float = 20.0  # how often to renew the lease
    SSE_REAUTH_INTERVAL_SECONDS: float = 30.0     # how often to re-validate auth

    # Rate limiting
    # Number of trusted reverse proxies in front of the app.
    # 0 = direct connection (use request.client.host)
    # N = take Nth-from-right IP in X-Forwarded-For
    TRUSTED_PROXY_COUNT: int = 0

    # Webmail engine
    WEBMAIL_REQUEST_TIMEOUT: float = 10.0   # seconds per HTTP probe
    WEBMAIL_MAX_SUBDOMAINS: int = 5         # max subdomains to probe
    WEBMAIL_FOLLOW_REDIRECTS: int = 3       # max redirect hops per probe

    # Vulnerability Intelligence
    NVD_API_KEY: Optional[str] = None       # optional NVD API key (higher rate limits)
    GITHUB_TOKEN: Optional[str] = None      # GitHub code search (5000 req/h with token)
    INTELX_API_KEY: Optional[str] = None    # IntelligenceX API key
    CVE_CACHE_TTL_SECONDS: int = 3600       # CVE lookup cache TTL
    INTEL_SYNC_ENABLED: bool = True
    INTEL_SYNC_INTERVAL_HOURS: int = 24

    # Email — SMTP transactional (optional; if unset, reset links log to stdout in dev)
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[SecretStr] = None
    SMTP_FROM: str = "mailox@localhost"
    SMTP_USE_TLS: bool = True
    FRONTEND_URL: str = "http://localhost:5173"

    # Web Pentest engine — Option B active injection (opt-in; default OFF)
    WEB_ACTIVE_PROBE_ENABLED: bool = False
    WEB_PROBE_RATE_LIMIT_SECONDS: float = 0.5   # delay between injection attempts
    WEB_PROBE_MAX_PARAMS: int = 20              # max params to test per page
    WEB_PROBE_CRAWL_DEPTH: int = 1             # 0=main only, 1=main+linked forms

    # Credential probes (opt-in only; default OFF)
    # Must be explicitly enabled per deployment. Never enable in production without
    # written authorization from the target domain owner.
    CRED_PROBE_ENABLED: bool = False
    CRED_PROBE_RATE_LIMIT_SECONDS: float = 2.0   # delay between each attempt
    CRED_PROBE_MAX_ATTEMPTS: int = 10             # hard cap per protocol per host
    CRED_PROBE_SMTP_PORT: int = 587               # submission port for auth test
    CRED_PROBE_IMAP_PORT: int = 993               # IMAPS port for auth test

    # Canary probes (open relay, spoofing PoC)
    # Set to an address YOU control to receive canary test messages.
    # If unset, relay/spoofing probes are skipped.
    CANARY_EMAIL: Optional[str] = None
    CANARY_SMTP_TIMEOUT: float = 15.0

    # Secrets engine
    SECRET_SCAN_MAX_FILE_SIZE_MB: int = 10  # max individual file size to scan
    SECRET_SCAN_MAX_FILES: int = 50         # max files in an uploaded archive
    SECRET_SCAN_MAX_ARCHIVE_SIZE_MB: int = 50  # bomb guard: total uncompressed size

    @field_validator("SECRET_KEY", "REFRESH_SECRET_KEY", "MASTER_ENCRYPTION_KEY", mode="before")
    @classmethod
    def validate_key_strength(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("Key must be at least 32 characters")
        # Reject placeholders shipped in .env.example / .env.selfhosted and
        # trivially low-entropy values (e.g. "a" * 32).
        if "change" in v.lower():
            raise ValueError("Key still holds a placeholder value: generate a real key")
        if len(set(v)) < 10:
            raise ValueError("Key has too little entropy: generate a real key")
        return v

    @model_validator(mode="after")
    def validate_distinct_keys(self) -> "Settings":
        keys = [
            self.SECRET_KEY.get_secret_value(),
            self.REFRESH_SECRET_KEY.get_secret_value(),
            self.MASTER_ENCRYPTION_KEY.get_secret_value(),
        ]
        if len(set(keys)) < 3:
            raise ValueError(
                "SECRET_KEY, REFRESH_SECRET_KEY, MASTER_ENCRYPTION_KEY must all be distinct"
            )
        return self

    @model_validator(mode="after")
    def validate_cors_not_wildcard(self) -> "Settings":
        origins = self.ALLOWED_ORIGINS
        if not self.DEBUG and not origins:
            raise ValueError("ALLOWED_ORIGINS must be set in production")
        if any("*" in o for o in origins):
            raise ValueError("Wildcard CORS origin not allowed")
        return self

    @model_validator(mode="after")
    def validate_allowed_hosts_saas(self) -> "Settings":
        # SaaS production must pin the Host header (reset/invite links, cache keys).
        if self.IS_SAAS and not self.DEBUG:
            hosts = [h.strip() for h in self.ALLOWED_HOSTS.split(",") if h.strip()]
            if not hosts or any("*" == h for h in hosts):
                raise ValueError(
                    "ALLOWED_HOSTS must list explicit host names when MAILOX_EDITION=saas "
                    "and DEBUG=false (wildcard '*' is not allowed)"
                )
        return self


settings = Settings()

# Public project URL, used in the User-Agent of every outbound scanner request
# so a target's operator can identify the tool.
PROJECT_URL = "https://github.com/28Zaaky/Mailox"
SCANNER_USER_AGENT = f"MAILOX/{settings.APP_VERSION} (+{PROJECT_URL})"
