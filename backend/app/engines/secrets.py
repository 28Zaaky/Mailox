"""
SecretsEngine — Module 07: SMTP Credential Exposure Detection.

Scans uploaded files/archives for exposed SMTP credentials, mail API keys,
and related secrets using regex pattern matching + context scoring.

HARD CONSTRAINTS:
- Never attempt SMTP connection with detected credentials
- Never store or display secrets in plaintext — masked values only
- Zip Slip protection on all archive extraction
- Decompression bomb guard: abort if uncompressed size > MAX_ARCHIVE_SIZE_MB
- No secrets in logs, no secrets in Finding evidence fields
"""
import asyncio
import io
import os
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Optional

import structlog

from app.core.config import SCANNER_USER_AGENT
from app.engines.base import BaseEngine, EngineResult
from app.schemas.findings import Evidence, EvidenceType, Finding, RiskLevel

logger = structlog.get_logger("mailox.engines.secrets")

# ---------------------------------------------------------------------------
# Detection patterns
# Format: (rule_id, secret_type_str, compiled_regex, base_confidence, risk)
# Groups must be named: `prefix` (key name) and `secret` (the actual value)
# ---------------------------------------------------------------------------
_PATTERNS: list[tuple[str, str, re.Pattern, float, str]] = [
    # SMTP DSN / connection string
    (
        "SMTP-DSN",
        "smtp_dsn",
        re.compile(
            r'(?P<prefix>smtp[s]?://[^:]*:)(?P<secret>[^@\s"\']{6,})',
            re.IGNORECASE,
        ),
        0.9,
        "high",
    ),
    # SMTP explicit password variable
    (
        "SMTP-PWD-VAR",
        "smtp_password",
        re.compile(
            r'(?P<prefix>(?:SMTP|MAIL)_(?:PASS(?:WORD)?|PWD|SECRET)\s*[=:]\s*["\']?)(?P<secret>[^"\'\s\r\n]{6,})',
            re.IGNORECASE,
        ),
        0.85,
        "high",
    ),
    # Generic password/secret assignment near mail context
    (
        "MAIL-SECRET-VAR",
        "generic_password",
        re.compile(
            r'(?P<prefix>(?:mail|email|smtp)[\w_]*(?:pass(?:word)?|secret|key|token|pwd)\s*[=:]\s*["\']?)(?P<secret>[^"\'\s\r\n]{8,})',
            re.IGNORECASE,
        ),
        0.7,
        "high",
    ),
    # SendGrid / Mailgun / Postmark / Mailchimp API keys
    (
        "SENDGRID-KEY",
        "mail_api_key",
        re.compile(
            r'(?P<prefix>SG\.)(?P<secret>[A-Za-z0-9_\-]{20,})',
        ),
        0.95,
        "critical",
    ),
    (
        "MAILGUN-KEY",
        "mail_api_key",
        re.compile(
            r'(?P<prefix>key-)(?P<secret>[a-f0-9]{32})',
            re.IGNORECASE,
        ),
        0.85,
        "high",
    ),
    (
        "POSTMARK-KEY",
        "mail_api_key",
        re.compile(
            r'(?P<prefix>(?:POSTMARK_API(?:_TOKEN)?|postmark[_-]?(?:api|token))\s*[=:]\s*["\']?)(?P<secret>[a-f0-9\-]{30,})',
            re.IGNORECASE,
        ),
        0.85,
        "high",
    ),
    # Generic API key assignment
    (
        "GENERIC-API-KEY",
        "mail_api_key",
        re.compile(
            r'(?P<prefix>(?:api[_-]?key|apikey|api_token)\s*[=:]\s*["\']?)(?P<secret>[A-Za-z0-9_\-]{20,})',
            re.IGNORECASE,
        ),
        0.5,
        "medium",
    ),
    # OAuth bearer token in config
    (
        "OAUTH-TOKEN",
        "oauth_token",
        re.compile(
            r'(?P<prefix>(?:access[_-]?token|bearer[_-]?token|oauth[_-]?token)\s*[=:]\s*["\']?)(?P<secret>[A-Za-z0-9_\-\.]{20,})',
            re.IGNORECASE,
        ),
        0.65,
        "high",
    ),
    # SMTP username (lower confidence, common false positives)
    (
        "SMTP-USER",
        "smtp_username",
        re.compile(
            r'(?P<prefix>(?:SMTP|MAIL)_(?:USER(?:NAME)?|FROM|LOGIN)\s*[=:]\s*["\']?)(?P<secret>[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})',
            re.IGNORECASE,
        ),
        0.7,
        "low",
    ),
]

# File extensions worth scanning for secrets
_TEXT_EXTENSIONS = {
    ".env", ".cfg", ".conf", ".config", ".ini", ".yaml", ".yml",
    ".json", ".toml", ".xml", ".properties", ".sh", ".bash",
    ".py", ".rb", ".php", ".js", ".ts", ".go", ".java", ".cs",
    ".txt", ".log", ".bak", ".backup", ".sql",
}

# Context keywords that increase confidence when found in nearby lines
_CONTEXT_BOOSTERS = [
    r'smtp', r'mail', r'email', r'sendgrid', r'mailgun', r'postmark',
    r'ses', r'aws', r'google', r'oauth', r'credentials', r'secret',
]

_RISK_MAP = {
    "critical": RiskLevel.CRITICAL,
    "high": RiskLevel.HIGH,
    "medium": RiskLevel.MEDIUM,
    "low": RiskLevel.LOW,
}


@dataclass
class SecretHit:
    rule_id: str
    secret_type: str
    masked_value: str
    line_number: int
    context_snippet: str     # surrounding lines, secrets masked
    confidence: float
    risk: str
    source_path: str


def _mask_secret(secret: str) -> str:
    """
    Return a masked version: first 2 chars + *** + last 2 chars.
    For short values (< 6 chars): full mask.
    """
    if len(secret) < 6:
        return "***"
    return secret[:2] + "***" + secret[-2:]


def _mask_line(line: str) -> str:
    """Apply all patterns to a line, masking any secret group found."""
    masked = line
    for _, _, pattern, _, _ in _PATTERNS:
        masked = pattern.sub(lambda m: m.group("prefix") + "***MASKED***", masked)
    return masked


_HIBP_BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches"
# Every outbound request identifies itself as MAILOX — never impersonate a
# crawler or browser (the DDG scraper used to send a Googlebot UA).
_MAILOX_USER_AGENT = SCANNER_USER_AGENT
_HIBP_USER_AGENT = _MAILOX_USER_AGENT

# DataClasses that indicate credential/password exposure → higher severity
_CRED_DATA_CLASSES = {
    "Passwords", "Password hints", "Password strengths",
    "Auth tokens", "Security questions and answers",
}


def _breach_risk(data_classes: list[str], pwn_count: int) -> tuple[str, float]:
    """Return (risk_level, confidence) for a breach based on its data classes."""
    has_creds = bool(set(data_classes) & _CRED_DATA_CLASSES)
    if has_creds and pwn_count >= 100_000:
        return "critical", 0.95
    if has_creds:
        return "high", 0.90
    if pwn_count >= 1_000_000:
        return "high", 0.85
    return "medium", 0.75


@dataclass
class _SourceOutcome:
    """Result of one external credential-exposure source."""
    status: str = "ok"            # ok | no_results | skipped: … | error: …
    findings: list[Finding] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


class SecretsEngine(BaseEngine):
    """
    Credential exposure engine.

    Domain pipeline (_run): queries HIBP for breaches tied to the target domain.
    File scanning: scan_bytes() / scan_archive() for manual uploads via /secrets/scan.
    """
    name: str = "secrets"
    default_timeout: float = 30.0

    def __init__(self, timeout: Optional[float] = None) -> None:
        super().__init__(timeout)

    # ── Domain pipeline ───────────────────────────────────────────────────────
    #
    # Each external source runs in its own coroutine and returns a
    # _SourceOutcome. They are gathered with return_exceptions=True so a
    # failing / empty source (HIBP 404, GitHub 403, IntelX down…) never stops
    # the others. Per-source status lands in result.metadata["source_status"].

    def _client(self, **kwargs):
        import httpx

        headers = {"User-Agent": _MAILOX_USER_AGENT}
        headers.update(kwargs.pop("headers", {}) or {})
        transport = getattr(self, "_transport", None)  # injectable for tests
        if transport is not None:
            kwargs["transport"] = transport
        return httpx.AsyncClient(headers=headers, **kwargs)

    async def _run(self, domain: str) -> EngineResult:
        result = EngineResult(engine=self.name, domain=domain)

        sources = [
            ("hibp", self._source_hibp),
            ("github", self._source_github),
            ("pastebin", self._source_pastebin),
            ("intelx", self._source_intelx),
            ("dork", self._source_dork),
        ]
        outcomes = await asyncio.gather(
            *(fn(domain) for _, fn in sources), return_exceptions=True
        )

        source_status: dict[str, str] = {}
        failed: list[str] = []
        for (name, _), outcome in zip(sources, outcomes):
            if isinstance(outcome, BaseException):
                status = f"error: {type(outcome).__name__}"
                self.logger.warning(
                    "secrets_source_failed", source=name, domain=domain,
                    error=type(outcome).__name__,
                )
                failed.append(name)
            else:
                status = outcome.status
                result.metadata.update(outcome.metadata)
                for f in outcome.findings:
                    result.add_finding(f)
                if status.startswith("error"):
                    self.logger.warning(
                        "secrets_source_failed", source=name, domain=domain, status=status,
                    )
                    failed.append(name)
            source_status[name] = status

        result.metadata["source_status"] = source_status
        attempted = [n for n, s in source_status.items() if not s.startswith("skipped")]
        if attempted and len(failed) == len(attempted):
            # Only an engine-level error when no source produced a usable answer.
            result.error = "All credential-exposure sources failed: " + ", ".join(
                f"{n} ({source_status[n]})" for n in failed
            )
        return result

    async def _source_hibp(self, domain: str) -> "_SourceOutcome":
        out = _SourceOutcome()
        async with self._client(timeout=15.0, follow_redirects=False) as client:
            resp = await client.get(_HIBP_BREACHES_URL, params={"domain": domain})

        if resp.status_code == 404:
            # HIBP returns 404 when no breaches are known — not an error
            out.metadata["hibp_breaches"] = 0
            out.status = "no_results"
            return out
        if resp.status_code != 200:
            out.status = f"error: HTTP {resp.status_code}"
            return out

        breaches: list[dict] = resp.json()
        out.metadata["hibp_breaches"] = len(breaches)
        out.status = "ok" if breaches else "no_results"

        for breach in breaches:
            name: str = breach.get("Name", "Unknown")
            pwn_count: int = breach.get("PwnCount", 0)
            breach_date: str = breach.get("BreachDate", "unknown")
            data_classes: list[str] = breach.get("DataClasses", [])
            is_verified: bool = breach.get("IsVerified", False)
            is_sensitive: bool = breach.get("IsSensitive", False)

            risk_str, confidence = _breach_risk(data_classes, pwn_count)
            if not is_verified:
                confidence *= 0.7

            risk_level = _RISK_MAP.get(risk_str, RiskLevel.MEDIUM)

            dc_str = ", ".join(data_classes[:8])
            if len(data_classes) > 8:
                dc_str += f" (+{len(data_classes) - 8} more)"

            title = f"Domain found in '{name}' data breach"
            if is_sensitive:
                title += " (sensitive)"

            out.findings.append(self._make_finding(
                check_id=f"SE-BREACH-{name.upper().replace(' ', '-')}",
                title=title,
                description=(
                    f"The domain '{domain}' appears in the '{name}' data breach "
                    f"({breach_date}). {pwn_count:,} accounts were compromised. "
                    f"Exposed data classes: {dc_str}."
                ),
                risk_level=risk_level,
                confidence=round(confidence, 2),
                evidence=[Evidence(
                    type=EvidenceType.EXTERNAL_RECORD,
                    observed_value=f"{name} breach — {pwn_count:,} accounts",
                    source="haveibeenpwned.com",
                    technical_details={
                        "breach_name": name,
                        "breach_date": breach_date,
                        "pwn_count": pwn_count,
                        "data_classes": data_classes,
                        "is_verified": is_verified,
                        "is_sensitive": is_sensitive,
                    },
                )],
                remediation=(
                    "Force password resets for all accounts associated with this domain. "
                    "Enable MFA across all services. "
                    "Audit for credential reuse and rotate any exposed API keys or SMTP passwords."
                ),
                affected_asset=domain,
                business_impact=(
                    "Exposed credentials can be used for account takeover, "
                    "phishing, and email infrastructure abuse."
                ),
                references=[
                    f"https://haveibeenpwned.com/PwnedWebsites#{name}",
                    "https://owasp.org/www-community/controls/Credential_Stuffing_Prevention_Cheat_Sheet",
                ],
            ))
        return out

    async def _source_github(self, domain: str) -> "_SourceOutcome":
        """GitHub public code search — domain + credential keywords."""
        from app.core.config import settings as _cfg

        out = _SourceOutcome()
        queries = [
            f'"{domain}" password smtp',
            f'"{domain}" MAIL_PASSWORD',
            f'"{domain}" EMAIL_HOST_PASSWORD',
        ]
        hits: list[dict] = []
        token = getattr(self, "_github_token", None) or getattr(_cfg, "GITHUB_TOKEN", None)
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"

        errors: list[str] = []
        async with self._client(timeout=10.0, headers=headers) as client:
            for q in queries:
                try:
                    resp = await client.get(
                        "https://api.github.com/search/code",
                        params={"q": q, "per_page": 5},
                    )
                except Exception as exc:
                    self.logger.debug("github_query_failed", domain=domain, error=type(exc).__name__)
                    errors.append(type(exc).__name__)
                    continue
                if resp.status_code == 200:
                    data = resp.json()
                    total = data.get("total_count", 0)
                    if total > 0:
                        for item in data.get("items", [])[:3]:
                            hits.append({
                                "query": q,
                                "repo": item.get("repository", {}).get("full_name", ""),
                                "path": item.get("path", ""),
                                "url": item.get("html_url", ""),
                                "total_matches": total,
                            })
                elif resp.status_code in (401, 403, 429):
                    # Code search requires auth; unauthenticated calls get 401/403.
                    out.metadata["github_rate_limited"] = resp.status_code in (403, 429)
                    errors.append(f"HTTP {resp.status_code}")
                    break
                else:
                    errors.append(f"HTTP {resp.status_code}")
                await asyncio.sleep(1.5)

        out.metadata["github_hits"] = len(hits)
        if hits:
            out.status = "ok"
        elif errors:
            out.status = f"error: {errors[0]}"
        else:
            out.status = "no_results"

        if hits:
            repos = list({h["repo"] for h in hits})[:5]
            out.findings.append(Finding(
                engine=self.name,
                check_id="SE-GITHUB-LEAK",
                title=f"Domain credentials potentially exposed on GitHub ({len(hits)} result(s))",
                description=(
                    f"GitHub code search found {len(hits)} public result(s) matching '{domain}' "
                    f"combined with credential-related keywords. "
                    f"Repositories: {', '.join(repos)}. "
                    "Manual verification required — false positives possible."
                ),
                risk_level=RiskLevel.HIGH,
                confidence=0.55,
                evidence=[Evidence(
                    type=EvidenceType.EXTERNAL_RECORD,
                    observed_value=f"{len(hits)} GitHub matches across {len(repos)} repo(s)",
                    source="github.com/search/code",
                    technical_details={"hits": hits[:10]},
                )],
                remediation=(
                    "Review each linked GitHub result immediately.\n"
                    "If real credentials found: rotate them, revoke tokens, "
                    "request GitHub content removal, audit access logs."
                ),
                affected_asset=domain,
                business_impact=(
                    "Exposed SMTP credentials allow sending spam/phishing as your domain. "
                    "Exposed API keys allow unauthorized access to email infrastructure."
                ),
                references=["https://docs.github.com/en/rest/search/search#search-code"],
            ))
        return out

    async def _source_pastebin(self, domain: str) -> "_SourceOutcome":
        """Pastebin dump search via psbdmp.ws (free, no auth)."""
        out = _SourceOutcome()
        async with self._client(timeout=8.0) as client:
            resp = await client.get(f"https://psbdmp.ws/api/v3/search/{domain}")
        if resp.status_code != 200:
            out.status = f"error: HTTP {resp.status_code}"
            return out

        data = resp.json()
        count = data.get("count", 0) if isinstance(data, dict) else 0
        items = (data.get("data", []) if isinstance(data, dict) else [])[:5]
        out.metadata["pastebin_hits"] = count
        out.status = "ok" if count > 0 else "no_results"
        if count > 0:
            urls = [
                f"https://pastebin.com/{item.get('id', '')}"
                for item in items if item.get("id")
            ]
            out.findings.append(Finding(
                engine=self.name,
                check_id="SE-PASTE-LEAK",
                title=f"Domain found in {count} Pastebin paste(s)",
                description=(
                    f"psbdmp.ws found {count} Pastebin paste(s) referencing '{domain}'. "
                    "Pastes often contain leaked credentials, config dumps, or breach data. "
                    "Manual review required."
                ),
                risk_level=RiskLevel.HIGH,
                confidence=0.60,
                evidence=[Evidence(
                    type=EvidenceType.EXTERNAL_RECORD,
                    observed_value=f"{count} paste(s) found",
                    source="psbdmp.ws",
                    technical_details={"count": count, "sample_urls": urls},
                )],
                remediation=(
                    "Review each linked paste. If credentials found: rotate immediately. "
                    "Request removal via Pastebin abuse report."
                ),
                affected_asset=domain,
                business_impact=(
                    "Leaked credentials in pastes enable credential stuffing "
                    "and email infrastructure abuse."
                ),
                references=urls[:3],
            ))
        return out

    async def _source_intelx(self, domain: str) -> "_SourceOutcome":
        """IntelligenceX — requires INTELX_API_KEY."""
        from app.core.config import settings as _cfg

        out = _SourceOutcome()
        key = getattr(self, "_intelx_api_key", None) or getattr(_cfg, "INTELX_API_KEY", None)
        if not key:
            out.status = "skipped: no API key"
            return out

        base = "https://free.intelx.io"
        async with self._client(timeout=15.0, headers={"x-key": key}) as client:
            start = await client.post(
                f"{base}/intelligent/search",
                json={"term": domain, "maxresults": 10, "media": 0, "sort": 4, "terminate": []},
            )
            if start.status_code != 200:
                out.status = f"error: HTTP {start.status_code}"
                return out
            search_id = start.json().get("id", "")
            await asyncio.sleep(2.0)
            res = await client.get(
                f"{base}/intelligent/search/result",
                params={"id": search_id, "limit": 10, "offset": 0},
            )
        if res.status_code != 200:
            out.status = f"error: HTTP {res.status_code}"
            return out

        records = res.json().get("records", []) or []
        out.metadata["intelx_hits"] = len(records)
        out.status = "ok" if records else "no_results"
        if records:
            buckets = list({r.get("bucket", "unknown") for r in records[:10]})
            out.findings.append(Finding(
                engine=self.name,
                check_id="SE-INTELX-LEAK",
                title=f"Domain found in {len(records)} IntelX record(s)",
                description=(
                    f"IntelligenceX found {len(records)} record(s) containing '{domain}' "
                    f"across: {', '.join(buckets[:5])}. "
                    "May include leaked databases, pastes, and dark web content."
                ),
                risk_level=RiskLevel.HIGH,
                confidence=0.70,
                evidence=[Evidence(
                    type=EvidenceType.EXTERNAL_RECORD,
                    observed_value=f"{len(records)} IntelX record(s)",
                    source="intelx.io",
                    technical_details={"count": len(records), "buckets": buckets},
                )],
                remediation=(
                    "Review records on intelx.io. Rotate any exposed credentials. "
                    "File DMCA takedowns where applicable."
                ),
                affected_asset=domain,
                business_impact=(
                    "IntelX indexes breach dumps, dark web pastes, and leaked configs — "
                    "exposed data enables immediate credential abuse."
                ),
                references=["https://intelx.io/"],
            ))
        return out

    async def _source_dork(self, domain: str) -> "_SourceOutcome":
        """DuckDuckGo HTML dorking. Identifies itself honestly as MAILOX."""
        out = _SourceOutcome()
        dorks = [
            f'site:pastebin.com "{domain}" password',
            f'site:pastebin.com "{domain}" smtp',
            f'"{domain}" filetype:env smtp password',
        ]
        hits: list[dict] = []
        errors: list[str] = []
        async with self._client(
            timeout=10.0,
            headers={"Accept-Language": "en-US,en;q=0.9"},
            follow_redirects=True,
        ) as client:
            for dork in dorks:
                try:
                    resp = await client.get(
                        "https://html.duckduckgo.com/html/", params={"q": dork},
                    )
                except Exception as exc:
                    self.logger.debug("dork_query_failed", domain=domain, error=type(exc).__name__)
                    errors.append(type(exc).__name__)
                    continue
                if resp.status_code == 200:
                    n = len(re.findall(r'class="result__snippet"', resp.text))
                    if n > 0:
                        hits.append({"query": dork, "result_count": n})
                else:
                    errors.append(f"HTTP {resp.status_code}")
                await asyncio.sleep(1.0)

        out.metadata["dork_hits"] = len(hits)
        if hits:
            out.status = "ok"
        elif errors and len(errors) == len(dorks):
            out.status = f"error: {errors[0]}"
        else:
            out.status = "no_results"

        if hits:
            summary = "; ".join(f'"{h["query"]}" → {h["result_count"]} results' for h in hits)
            out.findings.append(Finding(
                engine=self.name,
                check_id="SE-DORK-LEAK",
                title=f"Domain credentials indexed publicly ({len(hits)} dork(s) hit)",
                description=(
                    f"DuckDuckGo dorking found public results for '{domain}' combined with "
                    f"credential keywords. Dorks: {summary}. "
                    "Manual verification required — false positives likely."
                ),
                risk_level=RiskLevel.HIGH,
                confidence=0.45,
                evidence=[Evidence(
                    type=EvidenceType.EXTERNAL_RECORD,
                    observed_value=f"{len(hits)} dork(s) returned results",
                    source="duckduckgo.com/html",
                    technical_details={"dork_hits": hits},
                )],
                remediation=(
                    "Search each dork manually to identify exposed files. "
                    "Rotate any credentials found. Request removal from site owners."
                ),
                affected_asset=domain,
                business_impact=(
                    "Publicly indexed credentials allow immediate exploitation by any threat actor."
                ),
                references=["https://www.exploit-db.com/google-hacking-database"],
            ))
        return out

    @staticmethod
    def _is_scannable(filename: str) -> bool:
        """True if the file should be scanned for secrets."""
        lower = filename.lower()
        ext = os.path.splitext(lower)[1]
        if ext in _TEXT_EXTENSIONS:
            return True
        # Dotfiles: .env, .env.local, .env.production, etc.
        basename = os.path.basename(lower)
        if basename == ".env" or basename.startswith(".env."):
            return True
        return False

    def scan_bytes(
        self,
        content: bytes,
        filename: str,
        max_size_mb: int = 10,
    ) -> list[SecretHit]:
        """
        Scan raw file bytes for secrets. Returns list of SecretHit (masked).
        """
        from app.core.config import settings
        effective_max = max_size_mb or settings.SECRET_SCAN_MAX_FILE_SIZE_MB

        if len(content) > effective_max * 1024 * 1024:
            self.logger.warning(
                "file_too_large",
                filename=filename,
                size_mb=len(content) / 1024 / 1024,
            )
            return []

        if not self._is_scannable(filename):
            return []

        try:
            text = content.decode("utf-8", errors="replace")
        except Exception:
            return []

        return self._scan_text(text, filename)

    def scan_archive(
        self,
        archive_bytes: bytes,
        archive_name: str,
        max_archive_mb: int = 50,
        max_files: int = 50,
        max_file_mb: int = 10,
    ) -> list[SecretHit]:
        """
        Scan a ZIP archive for secrets. Applies:
        - Zip Slip protection (no path traversal)
        - Decompression bomb guard (total uncompressed < max_archive_mb)
        - File count limit
        - Per-file size limit
        """
        from app.core.config import settings
        effective_max_archive = max_archive_mb or settings.SECRET_SCAN_MAX_ARCHIVE_SIZE_MB
        effective_max_files = max_files or settings.SECRET_SCAN_MAX_FILES
        effective_max_file = max_file_mb or settings.SECRET_SCAN_MAX_FILE_SIZE_MB

        hits: list[SecretHit] = []

        try:
            with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as zf:
                total_uncompressed = sum(i.file_size for i in zf.infolist())
                if total_uncompressed > effective_max_archive * 1024 * 1024:
                    self.logger.warning(
                        "archive_bomb_guard",
                        archive=archive_name,
                        uncompressed_mb=total_uncompressed / 1024 / 1024,
                    )
                    return []

                scanned = 0
                for info in zf.infolist():
                    if scanned >= effective_max_files:
                        break

                    # Zip Slip protection
                    safe_path = self._safe_path(info.filename)
                    if safe_path is None:
                        self.logger.warning("zip_slip_blocked", member=info.filename)
                        continue

                    if not self._is_scannable(info.filename):
                        continue

                    max_file_bytes = effective_max_file * 1024 * 1024

                    # Check declared size first (fast path for clearly oversized files).
                    # NOTE: file_size in the ZIP header can be forged — a bomb ZIP could
                    # declare file_size=100 while the actual uncompressed data is 1 GB.
                    # The streaming read below enforces the hard cap regardless.
                    if info.file_size > max_file_bytes:
                        continue

                    # Compression ratio sanity check (before decompression).
                    # Legitimate files rarely exceed 1000:1; higher ratios indicate a
                    # decompression bomb attempt.
                    if info.compress_size > 0:
                        declared_ratio = info.file_size / info.compress_size
                        if declared_ratio > 1000:
                            self.logger.warning(
                                "suspicious_compression_ratio",
                                member=info.filename,
                                ratio=round(declared_ratio, 1),
                            )
                            continue

                    # Streaming read with hard byte cap — prevents decompression bombs
                    # even when the ZIP central directory lies about file_size.
                    try:
                        with zf.open(info.filename) as fh:
                            content = fh.read(max_file_bytes + 1)
                        if len(content) > max_file_bytes:
                            self.logger.warning(
                                "zip_extraction_exceeds_limit",
                                member=info.filename,
                                limit_mb=effective_max_file,
                            )
                            continue
                    except Exception:
                        continue

                    file_hits = self.scan_bytes(content, info.filename, effective_max_file)
                    # Update source_path to include archive context
                    for hit in file_hits:
                        hit.source_path = f"{archive_name}::{hit.source_path}"
                    hits.extend(file_hits)
                    scanned += 1

        except zipfile.BadZipFile:
            self.logger.debug("bad_zip_file", archive=archive_name)
        except Exception as exc:
            self.logger.warning("archive_scan_error", archive=archive_name, error=type(exc).__name__)

        return hits

    def _safe_path(self, member_path: str) -> Optional[str]:
        """
        Zip Slip: return None if the path tries to escape the archive root.
        Normalize to forward slashes, check for '..' components.
        """
        normalized = member_path.replace("\\", "/").lstrip("/")
        try:
            parts = PurePosixPath(normalized).parts
        except Exception:
            return None
        if any(part == ".." for part in parts):
            return None
        return normalized

    def _scan_text(self, text: str, source_path: str) -> list[SecretHit]:
        lines = text.splitlines()
        hits: list[SecretHit] = []
        seen_secrets: set[str] = set()

        for line_no, line in enumerate(lines, start=1):
            for rule_id, secret_type, pattern, base_confidence, risk in _PATTERNS:
                for m in pattern.finditer(line):
                    secret = m.group("secret")

                    # Deduplicate by masked value within the same file
                    masked = _mask_secret(secret)
                    dedup_key = f"{rule_id}:{masked}"
                    if dedup_key in seen_secrets:
                        continue
                    seen_secrets.add(dedup_key)

                    confidence = self._score_confidence(
                        base_confidence, line_no, lines
                    )

                    context = self._extract_context(line_no, lines)

                    hits.append(SecretHit(
                        rule_id=rule_id,
                        secret_type=secret_type,
                        masked_value=masked,
                        line_number=line_no,
                        context_snippet=context,
                        confidence=round(confidence, 2),
                        risk=risk,
                        source_path=source_path,
                    ))

        return hits

    def _score_confidence(
        self,
        base: float,
        line_no: int,
        lines: list[str],
    ) -> float:
        """
        Adjust confidence based on context lines (±3 lines around the finding).
        Boosts for mail-related keywords in context.
        """
        start = max(0, line_no - 4)
        end = min(len(lines), line_no + 3)
        context_text = " ".join(lines[start:end]).lower()

        boost = 0.0
        for booster in _CONTEXT_BOOSTERS:
            if re.search(booster, context_text):
                boost += 0.05

        return min(1.0, base + boost)

    def _extract_context(self, line_no: int, lines: list[str]) -> str:
        """
        Return ±2 lines around the finding, with secrets masked.
        Never returns plaintext secrets.
        """
        start = max(0, line_no - 3)
        end = min(len(lines), line_no + 2)
        context_lines = []
        for i in range(start, end):
            prefix = ">> " if i == line_no - 1 else "   "
            masked_line = _mask_line(lines[i])
            context_lines.append(f"{prefix}{i + 1}: {masked_line[:200]}")
        return "\n".join(context_lines)

    def hits_to_findings(
        self,
        hits: list[SecretHit],
        domain: str,
        archive_name: str,
    ) -> list[Finding]:
        """Convert SecretHit list into Finding objects for API response."""
        findings = []
        for hit in hits:
            risk = _RISK_MAP.get(hit.risk, RiskLevel.HIGH)
            findings.append(self._make_finding(
                check_id=f"SE-{hit.rule_id}",
                title=f"Exposed {hit.secret_type.replace('_', ' ')} in {os.path.basename(hit.source_path)}",
                description=(
                    f"Pattern '{hit.rule_id}' detected a potential {hit.secret_type} "
                    f"at line {hit.line_number} in {hit.source_path}. "
                    f"Confidence: {hit.confidence:.0%}. "
                    "Secret value is masked — plaintext not stored."
                ),
                risk_level=risk,
                confidence=hit.confidence,
                evidence=[Evidence(
                    type=EvidenceType.FILE_CONTENT,
                    observed_value=f"[masked] {hit.masked_value}",
                    source=hit.source_path,
                    technical_details={
                        "rule_id": hit.rule_id,
                        "secret_type": hit.secret_type,
                        "masked_value": hit.masked_value,
                        "line_number": hit.line_number,
                        "context_snippet": hit.context_snippet,
                        "confidence": hit.confidence,
                    },
                )],
                remediation=(
                    "Revoke and rotate the exposed credential immediately. "
                    "Remove secrets from source files and use environment variables or a secrets manager. "
                    "Scan git history for prior commits containing the secret."
                ),
                affected_asset=hit.source_path,
                business_impact=(
                    "Exposed SMTP credentials allow sending mail as the domain owner, "
                    "enabling phishing, spam relay, and account takeover."
                ),
                references=[
                    "https://owasp.org/www-community/vulnerabilities/Hardcoded_Password",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
                ],
            ))
        return findings
