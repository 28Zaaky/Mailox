"""
Seed script: migrate static _LOCAL_CVE_DB into the cve_* tables.

Usage:
    cd backend
    python scripts/seed_cve_intel.py

Idempotent — uses INSERT ... ON CONFLICT DO NOTHING.
"""
import asyncio
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Bootstrap: add backend root to path and load .env
# ---------------------------------------------------------------------------
BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT))

try:
    from dotenv import load_dotenv
    load_dotenv(BACKEND_ROOT / ".env")
except ImportError:
    pass  # fall back to env already set

# ---------------------------------------------------------------------------
# DB setup — bypass app.db.session so we avoid importing settings globally
# ---------------------------------------------------------------------------
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.dialects.postgresql import insert as pg_insert

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://mailox:mailox_dev@localhost:5432/mailox",
)

engine = create_async_engine(DATABASE_URL, echo=False)
SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

# ---------------------------------------------------------------------------
# Import models after path setup
# ---------------------------------------------------------------------------
from app.db.models.cve_intel import (
    CveProduct, CveVulnerability, CveAffectedRange, CveSource, CveSyncStatus,
)

# ---------------------------------------------------------------------------
# Static CVE data — copied from vuln_intel._LOCAL_CVE_DB
# ---------------------------------------------------------------------------
_LOCAL_CVE_DB = {
    "roundcube": [
        {
            "cve_id": "CVE-2023-43770",
            "description": "Roundcube Webmail cross-site scripting (XSS) via crafted link reference in plain text email",
            "cvss_score": 6.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "severity": "MEDIUM",
            "affected_versions": ["< 1.4.14", ">=1.5.0, < 1.5.4", ">=1.6.0, < 1.6.3"],
            "published_date": "2023-09-22",
            "patched_versions": ["1.4.14", "1.5.4", "1.6.3"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-43770"],
            "in_cisa_kev": True,
            "exploit_available": True,
        },
        {
            "cve_id": "CVE-2024-37383",
            "description": "Roundcube Webmail XSS via SVG animate element (bypass of sanitizer)",
            "cvss_score": 6.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "severity": "MEDIUM",
            "affected_versions": ["< 1.5.7", ">=1.6.0, < 1.6.7"],
            "published_date": "2024-06-04",
            "patched_versions": ["1.5.7", "1.6.7"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-37383"],
            "in_cisa_kev": False,
            "exploit_available": True,
        },
        {
            "cve_id": "CVE-2024-42009",
            "description": "Roundcube Webmail XSS via POST requests to HTML compose pages",
            "cvss_score": 9.3,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
            "severity": "CRITICAL",
            "affected_versions": ["< 1.5.8", ">=1.6.0, < 1.6.8"],
            "published_date": "2024-08-05",
            "patched_versions": ["1.5.8", "1.6.8"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-42009"],
            "in_cisa_kev": False,
            "exploit_available": False,
        },
    ],
    "zimbra": [
        {
            "cve_id": "CVE-2023-37580",
            "description": "Zimbra Collaboration XSS in the Email Classic UI through crafted URL",
            "cvss_score": 6.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "severity": "MEDIUM",
            "affected_versions": [">=8.8.0, < 8.8.15.41", ">=9.0.0, < 9.0.0.34", ">=10.0.0, < 10.0.2"],
            "published_date": "2023-07-13",
            "patched_versions": ["8.8.15.41", "9.0.0.34", "10.0.2"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-37580"],
            "in_cisa_kev": True,
            "exploit_available": True,
        },
        {
            "cve_id": "CVE-2024-45519",
            "description": "Zimbra Collaboration postjournal service remote code execution via SMTP",
            "cvss_score": 10.0,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "severity": "CRITICAL",
            "affected_versions": [">=8.8.0, < 8.8.15.46", ">=9.0.0, < 9.0.0.41", ">=10.0.0, < 10.0.9", ">=10.1.0, < 10.1.1"],
            "published_date": "2024-10-02",
            "patched_versions": ["8.8.15.46", "9.0.0.41", "10.0.9", "10.1.1"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-45519"],
            "in_cisa_kev": True,
            "exploit_available": True,
        },
    ],
    "microsoft owa": [
        {
            "cve_id": "CVE-2021-26855",
            "description": "Microsoft Exchange Server SSRF vulnerability allowing pre-auth RCE (ProxyLogon)",
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "severity": "CRITICAL",
            "affected_versions": [">=15.0.1000.0, < 15.0.1497.26", ">=15.1.0, < 15.1.2106.13", ">=15.1.2176.0, < 15.1.2176.14", ">=15.2.0, < 15.2.792.13"],
            "published_date": "2021-03-02",
            "patched_versions": ["15.0.1497.26", "15.1.2106.13", "15.1.2176.14", "15.2.792.13"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-26855"],
            "in_cisa_kev": True,
            "exploit_available": True,
        },
        {
            "cve_id": "CVE-2022-41082",
            "description": "Microsoft Exchange Server RCE when PowerShell is accessible (ProxyNotShell)",
            "cvss_score": 8.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "severity": "HIGH",
            "affected_versions": [">=15.0.1000.0, < 15.0.1497.42", ">=15.1.0, < 15.1.2507.13", ">=15.2.0, < 15.2.986.36", ">=15.2.1118.0, < 15.2.1118.20"],
            "published_date": "2022-10-02",
            "patched_versions": ["15.0.1497.42", "15.1.2507.13", "15.2.986.36", "15.2.1118.20"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-41082"],
            "in_cisa_kev": True,
            "exploit_available": True,
        },
    ],
    "microsoft exchange": [
        {
            "cve_id": "CVE-2021-26855",
            "description": "Microsoft Exchange Server SSRF vulnerability (ProxyLogon)",
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "severity": "CRITICAL",
            "affected_versions": [">=15.0.1000.0, < 15.0.1497.26", ">=15.1.0, < 15.1.2106.13", ">=15.1.2176.0, < 15.1.2176.14", ">=15.2.0, < 15.2.792.13"],
            "published_date": "2021-03-02",
            "patched_versions": ["15.0.1497.26", "15.1.2106.13", "15.1.2176.14", "15.2.792.13"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-26855"],
            "in_cisa_kev": True,
            "exploit_available": True,
        },
        {
            "cve_id": "CVE-2022-41082",
            "description": "Microsoft Exchange Server RCE when PowerShell is accessible (ProxyNotShell)",
            "cvss_score": 8.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "severity": "HIGH",
            "affected_versions": [">=15.0.1000.0, < 15.0.1497.42", ">=15.1.0, < 15.1.2507.13", ">=15.2.0, < 15.2.986.36", ">=15.2.1118.0, < 15.2.1118.20"],
            "published_date": "2022-10-02",
            "patched_versions": ["15.0.1497.42", "15.1.2507.13", "15.2.986.36", "15.2.1118.20"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-41082"],
            "in_cisa_kev": True,
            "exploit_available": True,
        },
    ],
    "horde": [
        {
            "cve_id": "CVE-2022-30287",
            "description": "Horde Groupware Webmail Edition RCE via authenticated file manager",
            "cvss_score": 8.0,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H",
            "severity": "HIGH",
            "affected_versions": ["<= 5.2.22"],
            "published_date": "2022-05-10",
            "patched_versions": [],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-30287"],
            "in_cisa_kev": False,
            "exploit_available": True,
        },
    ],
    "postfix": [
        {
            "cve_id": "CVE-2023-51764",
            "description": "Postfix SMTP Smuggling — allows injection of spoofed email messages bypassing SPF alignment",
            "cvss_score": 5.3,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
            "severity": "MEDIUM",
            "affected_versions": ["< 3.8.4", "< 3.7.9", "< 3.6.13", "< 3.5.23"],
            "published_date": "2023-12-24",
            "patched_versions": ["3.5.23", "3.6.13", "3.7.9", "3.8.4"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-51764"],
            "in_cisa_kev": False,
            "exploit_available": True,
        },
        {
            "cve_id": "CVE-2021-33515",
            "description": "Postfix SMTP downgrade attack via plaintext injection in encrypted session",
            "cvss_score": 4.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
            "severity": "MEDIUM",
            "affected_versions": ["< 3.5.13", ">=3.6.0, < 3.6.4"],
            "published_date": "2021-07-02",
            "patched_versions": ["3.5.13", "3.6.4"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-33515"],
            "in_cisa_kev": False,
            "exploit_available": False,
        },
    ],
    "sendmail": [
        {
            "cve_id": "CVE-2023-51765",
            "description": "Sendmail SMTP Smuggling — allows spoofed email message injection bypassing SPF alignment",
            "cvss_score": 5.3,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
            "severity": "MEDIUM",
            "affected_versions": ["< 8.17.2"],
            "published_date": "2023-12-24",
            "patched_versions": ["8.17.2"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-51765"],
            "in_cisa_kev": False,
            "exploit_available": True,
        },
        {
            "cve_id": "CVE-2014-3956",
            "description": "Sendmail file descriptor leak allows local privilege escalation via SMTP daemon",
            "cvss_score": 4.4,
            "cvss_vector": "CVSS:2.0/AV:L/AC:M/Au:N/C:P/I:P/A:P",
            "severity": "MEDIUM",
            "affected_versions": ["< 8.14.9"],
            "published_date": "2014-06-05",
            "patched_versions": ["8.14.9"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2014-3956"],
            "in_cisa_kev": False,
            "exploit_available": False,
        },
    ],
    "dovecot": [
        {
            "cve_id": "CVE-2022-30550",
            "description": "Dovecot IMAP privilege escalation via shared user database with multiple auth mechanisms",
            "cvss_score": 8.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "severity": "HIGH",
            "affected_versions": [">=2.3.0, < 2.3.19.1"],
            "published_date": "2022-07-17",
            "patched_versions": ["2.3.19.1"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-30550"],
            "in_cisa_kev": False,
            "exploit_available": True,
        },
        {
            "cve_id": "CVE-2021-33515",
            "description": "Dovecot IMAP STARTTLS plaintext command injection",
            "cvss_score": 4.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
            "severity": "MEDIUM",
            "affected_versions": ["< 2.3.14"],
            "published_date": "2021-07-02",
            "patched_versions": ["2.3.14"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-33515"],
            "in_cisa_kev": False,
            "exploit_available": False,
        },
        {
            "cve_id": "CVE-2020-24386",
            "description": "Dovecot IMAP hibernation feature allows accessing other users' mail",
            "cvss_score": 6.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",
            "severity": "MEDIUM",
            "affected_versions": [">=2.3.7, < 2.3.13"],
            "published_date": "2021-01-04",
            "patched_versions": ["2.3.13"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-24386"],
            "in_cisa_kev": False,
            "exploit_available": False,
        },
        {
            "cve_id": "CVE-2019-11500",
            "description": "Dovecot and Pigeonhole IMAP/ManageSieve parser out-of-bounds write — unauthenticated pre-auth RCE",
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "severity": "CRITICAL",
            "affected_versions": ["< 2.2.36.4", ">=2.3.0, < 2.3.7.2"],
            "published_date": "2019-08-28",
            "patched_versions": ["2.2.36.4", "2.3.7.2"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-11500"],
            "in_cisa_kev": False,
            "exploit_available": False,
        },
    ],
    "exim": [
        {
            "cve_id": "CVE-2019-10149",
            "description": "Exim RCE via RCPT TO command — 'The Return of the WIZard'",
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "severity": "CRITICAL",
            "affected_versions": [">=4.87, < 4.92"],
            "published_date": "2019-06-05",
            "patched_versions": ["4.92"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-10149"],
            "in_cisa_kev": True,
            "exploit_available": True,
        },
        {
            "cve_id": "CVE-2020-28017",
            "description": "Exim heap-based buffer overflow in receive_add_recipient() — integer overflow allows RCE",
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "severity": "CRITICAL",
            "affected_versions": ["< 4.94.2"],
            "published_date": "2021-05-04",
            "patched_versions": ["4.94.2"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-28017"],
            "in_cisa_kev": False,
            "exploit_available": False,
        },
        {
            "cve_id": "CVE-2020-28020",
            "description": "Exim integer overflow in receive_add_recipient() — heap corruption (21Nails)",
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "severity": "CRITICAL",
            "affected_versions": ["< 4.94.2"],
            "published_date": "2021-05-04",
            "patched_versions": ["4.94.2"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-28020"],
            "in_cisa_kev": False,
            "exploit_available": False,
        },
        {
            "cve_id": "CVE-2020-28021",
            "description": "Exim new-line injection before contemporaneous EHLO — SMTP header injection",
            "cvss_score": 8.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "severity": "HIGH",
            "affected_versions": ["< 4.94.2"],
            "published_date": "2021-05-04",
            "patched_versions": ["4.94.2"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-28021"],
            "in_cisa_kev": False,
            "exploit_available": False,
        },
        {
            "cve_id": "CVE-2023-42115",
            "description": "Exim auth_spa_server() out-of-bounds write, exploitable pre-auth via NTLM",
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "severity": "CRITICAL",
            "affected_versions": ["< 4.96.1"],
            "published_date": "2023-10-02",
            "patched_versions": ["4.96.1"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-42115"],
            "in_cisa_kev": False,
            "exploit_available": False,
        },
        {
            "cve_id": "CVE-2023-42117",
            "description": "Exim improper neutralization of special elements in MTA routing — arbitrary command injection",
            "cvss_score": 8.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "severity": "HIGH",
            "affected_versions": ["< 4.96.1"],
            "published_date": "2023-10-02",
            "patched_versions": ["4.96.1"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-42117"],
            "in_cisa_kev": False,
            "exploit_available": False,
        },
        {
            "cve_id": "CVE-2024-39929",
            "description": "Exim misparse of multiline RFC 2231 header filename — bypasses extension-based attachment blocking",
            "cvss_score": 9.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
            "severity": "CRITICAL",
            "affected_versions": ["< 4.98"],
            "published_date": "2024-07-10",
            "patched_versions": ["4.98"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-39929"],
            "in_cisa_kev": False,
            "exploit_available": False,
        },
    ],
    "squirrelmail": [
        {
            "cve_id": "CVE-2017-7692",
            "description": "SquirrelMail 1.4.22 RCE via sendmail -C option when Sendmail is used as the mail backend",
            "cvss_score": 8.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "severity": "HIGH",
            "affected_versions": ["<= 1.4.22"],
            "published_date": "2017-04-20",
            "patched_versions": [],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-7692"],
            "in_cisa_kev": False,
            "exploit_available": True,
        },
        {
            "cve_id": "CVE-2020-14933",
            "description": "SquirrelMail 1.4.22 CSV injection via crafted email subject",
            "cvss_score": 8.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "severity": "HIGH",
            "affected_versions": ["<= 1.4.22"],
            "published_date": "2020-06-19",
            "patched_versions": [],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-14933"],
            "in_cisa_kev": False,
            "exploit_available": False,
        },
    ],
    "openssl": [
        {
            "cve_id": "CVE-2022-0778",
            "description": "OpenSSL infinite loop in BN_mod_sqrt() when parsing malformed certificates — remote DoS",
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "severity": "HIGH",
            "affected_versions": ["< 1.0.2zd", ">=1.1.1, < 1.1.1n", ">=3.0.0, < 3.0.2"],
            "published_date": "2022-03-15",
            "patched_versions": ["1.0.2zd", "1.1.1n", "3.0.2"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-0778"],
            "in_cisa_kev": False,
            "exploit_available": True,
        },
        {
            "cve_id": "CVE-2022-3786",
            "description": "OpenSSL X.509 email address buffer overflow in punycode decoding",
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "severity": "HIGH",
            "affected_versions": [">=3.0.0, < 3.0.7"],
            "published_date": "2022-11-01",
            "patched_versions": ["3.0.7"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-3786"],
            "in_cisa_kev": False,
            "exploit_available": False,
        },
        {
            "cve_id": "CVE-2023-0286",
            "description": "OpenSSL type confusion with X.400 GeneralName in X.509 — potential RCE",
            "cvss_score": 7.4,
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H",
            "severity": "HIGH",
            "affected_versions": ["< 1.0.2zg", ">=1.1.1, < 1.1.1t", ">=3.0.0, < 3.0.8"],
            "published_date": "2023-02-08",
            "patched_versions": ["1.0.2zg", "1.1.1t", "3.0.8"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-0286"],
            "in_cisa_kev": False,
            "exploit_available": False,
        },
    ],
}

# ---------------------------------------------------------------------------
# Product metadata
# ---------------------------------------------------------------------------
_PRODUCT_META = {
    "roundcube": {
        "vendor": "The Roundcube Community",
        "category": "webmail",
        "product_type": "webmail",
        "ecosystem": "php",
        "homepage": "https://roundcube.net",
        "aliases": ["roundcubemail"],
        "cpe_identifiers": ["cpe:2.3:a:roundcube:webmail:*:*:*:*:*:*:*:*"],
        "description": "Open-source webmail client based on PHP",
    },
    "zimbra": {
        "vendor": "Synacor (Zimbra)",
        "category": "webmail",
        "product_type": "webmail",
        "ecosystem": "java",
        "homepage": "https://www.zimbra.com",
        "aliases": ["zimbra collaboration", "zimbra zcs"],
        "cpe_identifiers": ["cpe:2.3:a:zimbra:collaboration:*:*:*:*:*:*:*:*"],
        "description": "Enterprise collaboration suite with webmail",
    },
    "microsoft owa": {
        "vendor": "Microsoft",
        "category": "webmail",
        "product_type": "webmail",
        "ecosystem": "dotnet",
        "homepage": "https://www.microsoft.com/exchange",
        "aliases": ["outlook web app", "outlook web access", "owa"],
        "cpe_identifiers": ["cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*"],
        "description": "Microsoft Exchange's browser-based email client (OWA)",
    },
    "microsoft exchange": {
        "vendor": "Microsoft",
        "category": "webmail",
        "product_type": "mail_server",
        "ecosystem": "dotnet",
        "homepage": "https://www.microsoft.com/exchange",
        "aliases": ["exchange server", "ms exchange"],
        "cpe_identifiers": ["cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*"],
        "description": "Microsoft Exchange email server",
    },
    "horde": {
        "vendor": "The Horde Project",
        "category": "webmail",
        "product_type": "webmail",
        "ecosystem": "php",
        "homepage": "https://www.horde.org",
        "aliases": ["horde groupware", "horde imp"],
        "cpe_identifiers": ["cpe:2.3:a:horde:groupware:*:*:*:*:*:*:*:*"],
        "description": "Open-source groupware suite with webmail (Horde IMP)",
    },
    "squirrelmail": {
        "vendor": "The SquirrelMail Project",
        "category": "webmail",
        "product_type": "webmail",
        "ecosystem": "php",
        "homepage": "https://squirrelmail.org",
        "aliases": [],
        "cpe_identifiers": ["cpe:2.3:a:squirrelmail:squirrelmail:*:*:*:*:*:*:*:*"],
        "description": "Legacy PHP-based webmail client",
    },
    "postfix": {
        "vendor": "Wietse Venema / IBM",
        "category": "smtp",
        "product_type": "mta",
        "ecosystem": "c",
        "homepage": "https://www.postfix.org",
        "aliases": ["postfix mta"],
        "cpe_identifiers": ["cpe:2.3:a:postfix:postfix:*:*:*:*:*:*:*:*"],
        "description": "Free and open-source mail transfer agent",
    },
    "sendmail": {
        "vendor": "Proofpoint / Sendmail Inc.",
        "category": "smtp",
        "product_type": "mta",
        "ecosystem": "c",
        "homepage": "https://www.proofpoint.com/sendmail",
        "aliases": ["sendmail mta"],
        "cpe_identifiers": ["cpe:2.3:a:sendmail:sendmail:*:*:*:*:*:*:*:*"],
        "description": "Classic Unix mail transfer agent",
    },
    "exim": {
        "vendor": "University of Cambridge",
        "category": "smtp",
        "product_type": "mta",
        "ecosystem": "c",
        "homepage": "https://www.exim.org",
        "aliases": ["exim mta", "exim4"],
        "cpe_identifiers": ["cpe:2.3:a:exim:exim:*:*:*:*:*:*:*:*"],
        "description": "Mail transfer agent widely used on Unix-like systems",
    },
    "dovecot": {
        "vendor": "Open-Xchange (Dovecot OY)",
        "category": "imap_pop3",
        "product_type": "imap_server",
        "ecosystem": "c",
        "homepage": "https://www.dovecot.org",
        "aliases": ["dovecot imap"],
        "cpe_identifiers": ["cpe:2.3:a:dovecot:dovecot:*:*:*:*:*:*:*:*"],
        "description": "Open-source IMAP and POP3 email server",
    },
    "openssl": {
        "vendor": "OpenSSL Software Foundation",
        "category": "tls_crypto",
        "product_type": "library",
        "ecosystem": "c",
        "homepage": "https://www.openssl.org",
        "aliases": ["libssl", "libcrypto"],
        "cpe_identifiers": ["cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"],
        "description": "Cryptography library implementing SSL/TLS protocols",
    },
}


# ---------------------------------------------------------------------------
# Seed logic
# ---------------------------------------------------------------------------

async def upsert_product(session: AsyncSession, product_key: str, meta: dict) -> uuid.UUID:
    """Insert product if not exists; return its id."""
    stmt = pg_insert(CveProduct).values(
        id=uuid.uuid4(),
        canonical_name=product_key,
        vendor=meta.get("vendor"),
        category=meta.get("category", "other"),
        product_type=meta.get("product_type"),
        ecosystem=meta.get("ecosystem"),
        homepage=meta.get("homepage"),
        description=meta.get("description"),
        aliases=meta.get("aliases", []),
        cpe_identifiers=meta.get("cpe_identifiers", []),
        purl_identifiers=[],
        is_active=True,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    ).on_conflict_do_nothing(index_elements=["canonical_name"])
    await session.execute(stmt)
    await session.flush()

    result = await session.execute(
        text("SELECT id FROM cve_products WHERE canonical_name = :name"),
        {"name": product_key},
    )
    row = result.fetchone()
    return row[0]


async def upsert_vulnerability(session: AsyncSession, cve_dict: dict) -> tuple[uuid.UUID, bool]:
    """Insert CVE if not exists. Returns (id, was_inserted)."""
    now = datetime.now(timezone.utc)
    published = None
    if cve_dict.get("published_date"):
        try:
            from datetime import date as _date
            d = _date.fromisoformat(cve_dict["published_date"])
            published = datetime(d.year, d.month, d.day, tzinfo=timezone.utc)
        except ValueError:
            pass

    severity_raw = cve_dict.get("severity", "MEDIUM").upper()
    severity_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    severity = severity_map.get(severity_raw, "medium")

    stmt = pg_insert(CveVulnerability).values(
        id=uuid.uuid4(),
        cve_id=cve_dict["cve_id"],
        title=cve_dict["cve_id"],
        description=cve_dict.get("description", ""),
        published_at=published,
        modified_at=published,
        status="active",
        cvss_v3_score=cve_dict.get("cvss_score"),
        cvss_v3_vector=cve_dict.get("cvss_vector"),
        severity=severity,
        cwe_ids=[],
        references=cve_dict.get("references", []),
        exploit_available=cve_dict.get("exploit_available", False),
        exploit_maturity="functional" if cve_dict.get("exploit_available") else None,
        exploit_references=[],
        in_cisa_kev=cve_dict.get("in_cisa_kev", False),
        kev_ransomware_use=False,
        relevance="direct",
        relevance_confidence=0.9,
        relevance_manual=False,
        source_confidence=0.95,
        created_at=now,
        updated_at=now,
    ).on_conflict_do_nothing(index_elements=["cve_id"])
    result = await session.execute(stmt)
    was_inserted = result.rowcount > 0
    await session.flush()

    row = await session.execute(
        text("SELECT id FROM cve_vulnerabilities WHERE cve_id = :cid"),
        {"cid": cve_dict["cve_id"]},
    )
    return row.fetchone()[0], was_inserted


async def insert_affected_range(
    session: AsyncSession,
    vuln_id: uuid.UUID,
    product_id: uuid.UUID,
    cve_dict: dict,
) -> None:
    patched = cve_dict.get("patched_versions", [])
    stmt = pg_insert(CveAffectedRange).values(
        id=uuid.uuid4(),
        vulnerability_id=vuln_id,
        product_id=product_id,
        introduced_version=None,
        fixed_version=patched[0] if patched else None,
        last_affected_version=None,
        version_type="semver",
        version_constraints=cve_dict.get("affected_versions", []),
        source="STATIC_SEED",
        range_confidence=0.9,
    ).on_conflict_do_nothing()
    await session.execute(stmt)


async def insert_source(
    session: AsyncSession,
    vuln_id: uuid.UUID,
    cve_id: str,
) -> None:
    now = datetime.now(timezone.utc)
    stmt = pg_insert(CveSource).values(
        id=uuid.uuid4(),
        vulnerability_id=vuln_id,
        source_name="STATIC_SEED",
        source_record_id=cve_id,
        source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        retrieved_at=now,
        source_modified_at=None,
        raw_record_hash=None,
        source_revision="static_v1",
    ).on_conflict_do_nothing(constraint="uq_cve_source_vuln_source")
    await session.execute(stmt)


async def update_sync_status(session: AsyncSession, records_added: int) -> None:
    now = datetime.now(timezone.utc)
    await session.execute(
        text("""
            UPDATE cve_sync_status
            SET last_sync_at = :now,
                last_success_at = :now,
                records_added = records_added + :added,
                is_running = false,
                updated_at = :now
            WHERE source_name = 'STATIC_SEED'
        """),
        {"now": now, "added": records_added},
    )


async def main() -> None:
    products_created = 0
    cves_inserted = 0
    cves_skipped = 0

    async with SessionLocal() as session:
        async with session.begin():
            for product_key, cve_list in _LOCAL_CVE_DB.items():
                meta = _PRODUCT_META.get(product_key, {"category": "other"})
                product_id = await upsert_product(session, product_key, meta)
                products_created += 1
                print(f"  product: {product_key} → {product_id}")

                for cve_dict in cve_list:
                    vuln_id, was_inserted = await upsert_vulnerability(session, cve_dict)

                    if was_inserted:
                        await insert_affected_range(session, vuln_id, product_id, cve_dict)
                        await insert_source(session, vuln_id, cve_dict["cve_id"])
                        cves_inserted += 1
                        print(f"    + {cve_dict['cve_id']} ({cve_dict['severity']})")
                    else:
                        # CVE exists — still link affected range to this product if not already linked
                        await insert_affected_range(session, vuln_id, product_id, cve_dict)
                        cves_skipped += 1
                        print(f"    ~ {cve_dict['cve_id']} (already exists)")

            await update_sync_status(session, cves_inserted)

    print()
    print(f"Done. {products_created} products, {cves_inserted} CVEs inserted, {cves_skipped} skipped.")


if __name__ == "__main__":
    asyncio.run(main())
