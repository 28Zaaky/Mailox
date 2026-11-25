"""
VulnIntelEngine — Module 06: Vulnerability Intelligence Engine.

Correlates software products/versions identified in other engine findings
against a local CVE knowledge base and optionally the NVD API.

Design constraints:
- Never assert a CVE is present without a matching product+version
- Confidence classification: CONFIRMED / POTENTIALLY / NOT_AFFECTED / UNKNOWN
- NVD API calls are optional and gated behind NVD_API_KEY setting
- All results are cached in Redis to avoid hammering upstream APIs
- Absence of CVE data = UNKNOWN, not "clean"
- Never connect to SMTP servers; this engine only does HTTP CVE lookups
"""
import asyncio
import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import httpx
import structlog
from sqlalchemy import or_, select
from sqlalchemy.orm import selectinload

from app.engines.base import BaseEngine, EngineResult
from app.schemas.findings import Evidence, EvidenceType, Finding, RiskLevel

logger = structlog.get_logger("mailox.engines.vuln_intel")


class CVEConfidence(str, Enum):
    CONFIRMED = "confirmed"       # parsed version inside a well-formed affected range
    POTENTIALLY = "potentially"   # version present but unparseable / range data malformed
    UNCERTAIN = "uncertain"       # version known but CVE carries no range data (e.g. NVD keyword hit)
    NOT_AFFECTED = "not_affected"  # version outside every (well-formed) affected range
    UNKNOWN = "unknown"           # unable to determine: no version identified


@dataclass
class CVEEntry:
    cve_id: str
    description: str
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    severity: str                   # LOW / MEDIUM / HIGH / CRITICAL
    affected_versions: list[str]    # CPE-style or semver ranges
    published_date: Optional[str]
    patched_versions: list[str]
    references: list[str]
    in_cisa_kev: bool = False       # Known Exploited Vulnerabilities catalog
    exploit_available: bool = False


@dataclass
class SoftwareMatch:
    product: str
    version: Optional[str]
    source_engine: str
    source_finding_id: Optional[str] = None
    cves: list[CVEEntry] = field(default_factory=list)
    not_affected_cves: list[CVEEntry] = field(default_factory=list)
    # Per-CVE status (cve_id -> CVEConfidence). match.confidence is only the
    # aggregate; each emitted finding uses its own CVE's status.
    cve_status: dict[str, CVEConfidence] = field(default_factory=dict)
    confidence: CVEConfidence = CVEConfidence.UNKNOWN


# ---------------------------------------------------------------------------
# Local knowledge base — high-value CVEs for common webmail/SMTP software.
# This is NOT a full CVE database; it covers critical findings relevant to
# the software MAILOX discovers. External NVD queries supplement this.
# ---------------------------------------------------------------------------
_LOCAL_CVE_DB: dict[str, list[dict]] = {
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
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2023-43770",
                "https://github.com/roundcube/roundcubemail/releases",
            ],
            "in_cisa_kev": True,
            "exploit_available": True,
        },
        {
            "cve_id": "CVE-2024-37383",
            "description": "Roundcube Webmail XSS via SVG animate element (bypass of sanitizer)",
            "cvss_score": 6.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "severity": "MEDIUM",
            # OSV range: Introduced 0 (all versions), Fixed 1.5.7 — 1.4.x IS affected.
            # Second range: Introduced 1.6.0, Fixed 1.6.7.
            # Source: https://osv.dev/vulnerability/CVE-2024-37383
            "affected_versions": ["< 1.5.7", ">=1.6.0, < 1.6.7"],
            "published_date": "2024-06-04",
            "patched_versions": ["1.5.7", "1.6.7"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2024-37383",
                "https://osv.dev/vulnerability/CVE-2024-37383",
            ],
            "in_cisa_kev": False,
            "exploit_available": True,
        },
        {
            "cve_id": "CVE-2024-42009",
            "description": "Roundcube Webmail XSS via POST requests to HTML compose pages",
            "cvss_score": 9.3,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
            "severity": "CRITICAL",
            # OSV range: Introduced 0 (all versions), Fixed 1.5.8 — 1.4.x IS affected.
            # Second range: Introduced 1.6.0, Fixed 1.6.8.
            # Source: https://osv.dev/vulnerability/CVE-2024-42009
            "affected_versions": ["< 1.5.8", ">=1.6.0, < 1.6.8"],
            "published_date": "2024-08-05",
            "patched_versions": ["1.5.8", "1.6.8"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2024-42009",
                "https://osv.dev/vulnerability/CVE-2024-42009",
                "https://roundcube.net/news/2024/08/04/security-updates-1.6.8-and-1.5.8",
            ],
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
            # Branch-specific ranges using 4-component semver (8.8.15.41 = "8.8.15 Patch 41")
            "affected_versions": [
                ">=8.8.0, < 8.8.15.41",   # 8.8.x branch before Patch 41
                ">=9.0.0, < 9.0.0.34",    # 9.0.x branch before Patch 34
                ">=10.0.0, < 10.0.2",     # 10.0.x branch
            ],
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
            # Branch-specific ranges; unpatched base version (patch 0) is correctly < patch N
            "affected_versions": [
                ">=8.8.0, < 8.8.15.46",   # 8.8.x branch before Patch 46
                ">=9.0.0, < 9.0.0.41",    # 9.0.x branch before Patch 41
                ">=10.0.0, < 10.0.9",     # 10.0.x branch
                ">=10.1.0, < 10.1.1",     # 10.1.x branch
            ],
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
            # OWA build number ranges (from X-OWA-Version header, e.g. "15.1.2375.17")
            "affected_versions": [
                ">=15.0.1000.0, < 15.0.1497.26",  # Exchange 2013 CU23 pre-patch
                ">=15.1.0, < 15.1.2106.13",        # Exchange 2016 through CU18 pre-patch
                ">=15.1.2176.0, < 15.1.2176.14",   # Exchange 2016 CU19 pre-patch
                ">=15.2.0, < 15.2.792.13",          # Exchange 2019 through CU8 pre-patch
            ],
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
            "affected_versions": [
                ">=15.0.1000.0, < 15.0.1497.42",  # Exchange 2013 CU23 pre-patch
                ">=15.1.0, < 15.1.2507.13",        # Exchange 2016 all CUs pre-patch
                ">=15.2.0, < 15.2.986.36",          # Exchange 2019 through CU11 pre-patch
                ">=15.2.1118.0, < 15.2.1118.20",   # Exchange 2019 CU12 pre-patch
            ],
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
            "affected_versions": [
                ">=15.0.1000.0, < 15.0.1497.26",
                ">=15.1.0, < 15.1.2106.13",
                ">=15.1.2176.0, < 15.1.2176.14",
                ">=15.2.0, < 15.2.792.13",
            ],
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
            "affected_versions": [
                ">=15.0.1000.0, < 15.0.1497.42",
                ">=15.1.0, < 15.1.2507.13",
                ">=15.2.0, < 15.2.986.36",
                ">=15.2.1118.0, < 15.2.1118.20",
            ],
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
            # Per-branch ranges (each stable branch got its own fix). A flat
            # list of bare "< X" bounds is OR'ed by the matcher, so "< 3.8.4"
            # would swallow 3.7.10 / 3.6.14 / 3.5.24 — never write it that way.
            "affected_versions": [
                "< 3.5.23",
                ">=3.6.0, < 3.6.13",
                ">=3.7.0, < 3.7.9",
                ">=3.8.0, < 3.8.4",
            ],
            "published_date": "2023-12-24",
            "patched_versions": ["3.5.23", "3.6.13", "3.7.9", "3.8.4"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2023-51764",
                "https://www.postfix.org/smtp-smuggling.html",
            ],
            "in_cisa_kev": False,
            "exploit_available": True,
        },
        # NOTE: CVE-2021-33515 used to be listed here with Postfix ranges.
        # It is a Dovecot submission-service STARTTLS injection bug (NVD
        # CPE: dovecot:dovecot) and does not affect Postfix; see "dovecot".
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
            "description": "Sendmail file descriptor leak allows local privilege escalation via SMTP daemon (sm-mta)",
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
            "description": "Dovecot IMAP privilege escalation — when multiple authentication mechanisms share a user database, an attacker can authenticate with a different mechanism to gain higher privilege",
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
            "description": "Dovecot IMAP STARTTLS plaintext command injection — allows injecting commands before TLS negotiation completes",
            "cvss_score": 4.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
            "severity": "MEDIUM",
            # NVD: "The submission service in Dovecot before 2.3.15 ..."
            "affected_versions": ["< 2.3.15"],
            "published_date": "2021-07-02",
            "patched_versions": ["2.3.15"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-33515"],
            "in_cisa_kev": False,
            "exploit_available": False,
        },
        {
            "cve_id": "CVE-2020-24386",
            "description": "Dovecot IMAP hibernation feature allows accessing other users' mail when IMAP protocol extensions are enabled",
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
            "description": "Exim RCE via RCPT TO command — 'The Return of the WIZard' (unauthenticated, local delivery escalation path)",
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "severity": "CRITICAL",
            "affected_versions": [">=4.87, < 4.92"],
            "published_date": "2019-06-05",
            "patched_versions": ["4.92"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2019-10149",
                "https://www.exim.org/static/doc/security/CVE-2019-10149.txt",
            ],
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
            "description": "Exim integer overflow in receive_add_recipient() leading to heap corruption — part of 21Nails disclosure",
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
            "description": "Exim new-line injection before contemporaneous EHLO — allows spoofed sender / SMTP header injection",
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
            "description": "Exim improper neutralization of special elements in MTA routing — allows arbitrary command injection via crafted email headers",
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
            "description": "Exim misparse of multiline RFC 2231 header filename — allows bypassing extension-based attachment blocking to deliver malicious executables",
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
            "description": "SquirrelMail 1.4.22 CSV injection via crafted email subject when using the CSV export feature",
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
            "description": "OpenSSL infinite loop in BN_mod_sqrt() when parsing malformed certificates — remote DoS against TLS servers",
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
            "description": "OpenSSL X.509 email address buffer overflow in punycode decoding — stack overflow DoS or potential RCE",
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
            "description": "OpenSSL type confusion with X.400 GeneralName in X.509 — read memory corruption potentially allowing remote code execution",
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

_SEVERITY_TO_RISK = {
    "CRITICAL": RiskLevel.CRITICAL,
    "HIGH": RiskLevel.HIGH,
    "MEDIUM": RiskLevel.MEDIUM,
    "LOW": RiskLevel.LOW,
    "INFO": RiskLevel.INFO,
}


class VulnIntelEngine(BaseEngine):
    """
    Post-processing engine: takes findings from earlier engines, extracts
    identified software products/versions, and correlates against CVE data.

    Can also run standalone via run(domain) using metadata injection.
    Use run_from_findings(domain, findings) for the primary pipeline integration.
    """
    name: str = "vuln_intel"
    default_timeout: float = 60.0

    def __init__(self, timeout: Optional[float] = None) -> None:
        super().__init__(timeout)
        self._redis: Optional[object] = None

    async def _run(self, domain: str) -> EngineResult:
        # Standalone mode: no prior findings — return empty result with info note
        result = EngineResult(engine=self.name, domain=domain)
        result.metadata["note"] = (
            "VulnIntelEngine requires prior findings from webmail/SMTP engines. "
            "Call run_from_findings(domain, findings) instead of run(domain)."
        )
        return result

    async def run_from_findings(
        self,
        domain: str,
        prior_findings: list[Finding],
        db=None,
    ) -> EngineResult:
        """Primary entry point for pipeline use. db: optional AsyncSession for DB-backed CVE lookup."""
        result = EngineResult(engine=self.name, domain=domain)
        software_matches = self._extract_software(prior_findings)

        if not software_matches:
            result.metadata["note"] = "No identified software products found in prior findings."
            return result

        from app.core.config import settings
        redis_client = await self._get_redis()

        for match in software_matches:
            await self._enrich_with_cves(match, settings, redis_client, db=db)
            self._emit_cve_findings(result, match, domain)

        result.metadata["software_checked"] = [
            {"product": m.product, "version": m.version} for m in software_matches
        ]
        return result

    # Regex to extract MTA product+version from SMTP banners
    # e.g. "220 mx.example.com ESMTP Exim 4.94.2", "220 ... Postfix"
    # Postfix hides its version by default (smtpd_banner = $myhostname ESMTP
    # $mail_name); the optional group only catches banners customised to
    # include $mail_version ("Postfix 3.7.10"). No version -> no CVE findings.
    _BANNER_PATTERNS = [
        (re.compile(r"\bExim\s+([\d.]+)", re.I), "exim"),
        (re.compile(r"\bPostfix\b(?:[ /-]v?(\d+\.\d+(?:\.\d+)?)\b)?", re.I), "postfix"),
        (re.compile(r"\bSendmail\s+([\d./]+)", re.I), "sendmail"),
        (re.compile(r"\bMicrosoft\s+ESMTP\s+MAIL\s+Service", re.I), "microsoft exchange"),
    ]

    def _extract_software(self, findings: list[Finding]) -> list[SoftwareMatch]:
        """
        Parse product/version from Finding evidence.
        Handles:
        - WM-001 (webmail discovery) technical_details
        - smtp_discovery findings with smtp_banner in technical_details
        """
        matches: list[SoftwareMatch] = []
        seen: set[str] = set()

        for finding in findings:
            # Webmail products
            if finding.check_id.startswith("WM-001"):
                for ev in finding.evidence:
                    td = ev.technical_details or {}
                    product = td.get("product")
                    version = td.get("version")
                    if not product:
                        continue
                    key = f"{product.lower()}:{version or ''}"
                    if key in seen:
                        continue
                    seen.add(key)
                    matches.append(SoftwareMatch(
                        product=product,
                        version=version,
                        source_engine=td.get("source_engine", "webmail"),
                        source_finding_id=finding.check_id,
                    ))

            # SMTP banners from smtp_discovery
            if finding.engine == "smtp_discovery":
                for ev in finding.evidence:
                    td = ev.technical_details or {}
                    banner = td.get("smtp_banner") or td.get("banner") or ""
                    if not banner:
                        continue
                    for pattern, product_key in self._BANNER_PATTERNS:
                        m = pattern.search(banner)
                        if m:
                            version = (m.group(1) if m.re.groups else None) or None
                            key = f"{product_key}:{version or ''}"
                            if key in seen:
                                continue
                            seen.add(key)
                            matches.append(SoftwareMatch(
                                product=product_key,
                                version=version,
                                source_engine="smtp_discovery",
                                source_finding_id=finding.check_id,
                            ))

        return matches

    async def _load_cves_from_db(self, db, product_key: str) -> list["CVEEntry"]:
        """Load CVE entries from the database for a given product key."""
        try:
            from app.db.models.cve_intel import CveAffectedRange, CveProduct, CveVulnerability

            stmt = (
                select(CveVulnerability)
                .join(CveAffectedRange, CveAffectedRange.vulnerability_id == CveVulnerability.id)
                .join(CveProduct, CveAffectedRange.product_id == CveProduct.id)
                .where(
                    or_(
                        CveProduct.canonical_name == product_key,
                        CveProduct.aliases.contains([product_key]),
                    )
                )
                .options(
                    selectinload(CveVulnerability.affected_ranges).selectinload(CveAffectedRange.product)
                )
                .distinct()
            )
            result = await db.execute(stmt)
            vulns = result.scalars().unique().all()

            entries: list[CVEEntry] = []
            for vuln in vulns:
                product_ranges = [
                    r for r in vuln.affected_ranges
                    if (r.product.canonical_name == product_key
                        or product_key in (r.product.aliases or []))
                ]
                affected = [c for r in product_ranges for c in (r.version_constraints or [])]
                patched = [r.fixed_version for r in product_ranges if r.fixed_version]
                if not patched and product_ranges:
                    patched = [r.last_affected_version for r in product_ranges if r.last_affected_version]

                entries.append(CVEEntry(
                    cve_id=vuln.cve_id,
                    description=vuln.description or "",
                    cvss_score=vuln.cvss_v3_score,
                    cvss_vector=vuln.cvss_v3_vector,
                    severity=vuln.severity or "UNKNOWN",
                    affected_versions=affected,
                    published_date=(
                        vuln.published_at.strftime("%Y-%m-%d") if vuln.published_at else None
                    ),
                    patched_versions=patched,
                    references=vuln.references or [],
                    in_cisa_kev=vuln.in_cisa_kev,
                    exploit_available=vuln.exploit_available,
                ))
            return entries
        except Exception as exc:
            self.logger.warning("db_cve_lookup_failed", product=product_key, error=str(exc))
            return []

    async def _enrich_with_cves(
        self,
        match: SoftwareMatch,
        settings: object,
        redis_client: Optional[object],
        db=None,
    ) -> None:
        """Populate match.cves from DB (or static fallback) then optionally NVD API."""
        product_key = match.product.lower()

        # Prefer DB; fall back to static dict when DB unavailable
        if db is not None:
            cve_entries = await self._load_cves_from_db(db, product_key)
            local_entries = [
                {
                    "cve_id": e.cve_id,
                    "description": e.description,
                    "cvss_score": e.cvss_score,
                    "cvss_vector": e.cvss_vector,
                    "severity": e.severity,
                    "affected_versions": e.affected_versions,
                    "published_date": e.published_date,
                    "patched_versions": e.patched_versions,
                    "references": e.references,
                    "in_cisa_kev": e.in_cisa_kev,
                    "exploit_available": e.exploit_available,
                }
                for e in cve_entries
            ]
        else:
            local_entries = _LOCAL_CVE_DB.get(product_key, [])

        for entry_dict in local_entries:
            cve = CVEEntry(**entry_dict)
            if match.version:
                cve_confidence = self._check_version_range(
                    match.version, cve.affected_versions, cve.patched_versions
                )
            else:
                # Without a version nothing can be asserted about any CVE.
                cve_confidence = CVEConfidence.UNKNOWN

            match.cve_status[cve.cve_id] = cve_confidence
            if cve_confidence == CVEConfidence.NOT_AFFECTED:
                match.not_affected_cves.append(cve)
            else:
                match.cves.append(cve)

        match.confidence = self._aggregate_status(match, has_entries=bool(local_entries))

        # NVD API — optional, rate-limited, cached (only when DB had no entries)
        nvd_key = getattr(self, "_nvd_api_key", None) or getattr(settings, "NVD_API_KEY", None)
        if nvd_key and not local_entries and match.version and db is None:
            await self._query_nvd(match, nvd_key, redis_client, settings)
            match.confidence = self._aggregate_status(match, has_entries=bool(match.cves))

    @staticmethod
    def _aggregate_status(match: SoftwareMatch, has_entries: bool) -> CVEConfidence:
        """Strongest per-CVE status among active CVEs (CONFIRMED > POTENTIALLY > UNCERTAIN > UNKNOWN)."""
        if not match.version:
            return CVEConfidence.UNKNOWN
        if not match.cves:
            return CVEConfidence.NOT_AFFECTED if has_entries else CVEConfidence.UNKNOWN
        order = [
            CVEConfidence.CONFIRMED,
            CVEConfidence.POTENTIALLY,
            CVEConfidence.UNCERTAIN,
            CVEConfidence.UNKNOWN,
        ]
        statuses = {match.cve_status.get(c.cve_id, CVEConfidence.UNCERTAIN) for c in match.cves}
        for status in order:
            if status in statuses:
                return status
        return CVEConfidence.UNKNOWN

    # A range is "well-formed" when every comma-separated constraint parses.
    _CONSTRAINT_RE = re.compile(r'^(>=|<=|>|<|==)\s*([0-9]+(?:\.[0-9]+)*[a-z]{0,3})$')

    def _range_is_valid(self, range_str: str) -> bool:
        parts = [p.strip() for p in range_str.split(",") if p.strip()]
        return bool(parts) and all(self._CONSTRAINT_RE.match(p) for p in parts)

    def _normalize_ranges(self, affected_ranges: list[str]) -> list[str]:
        """
        Defensive fix for legacy/DB data written as a flat OR of bare upper
        bounds, e.g. ["< 3.8.4", "< 3.7.9", "< 3.6.13", "< 3.5.23"]. OR'ed
        literally, "< 3.8.4" matches every older branch, so a patched 3.7.10
        would be CONFIRMED. When several bare "<"/"<=" bounds exist, the lowest
        keeps its open lower end and each other one is scoped to its own
        major.minor branch (">= 3.7.0, < 3.7.9").
        """
        bare: list[tuple[tuple[int, ...], str]] = []
        for r in affected_ranges:
            s = r.strip()
            if "," in s:
                continue
            m = self._CONSTRAINT_RE.match(s)
            if m and m.group(1) in ("<", "<="):
                pv = self._parse_semver(m.group(2))
                if pv:
                    bare.append((pv, s))
        if len(bare) < 2:
            return list(affected_ranges)

        lowest = min(bare, key=lambda t: t[0])[1]
        out: list[str] = []
        for r in affected_ranges:
            s = r.strip()
            entry = next((b for b in bare if b[1] == s), None)
            if entry is None or s == lowest:
                out.append(r)
                continue
            major, minor = entry[0][0], entry[0][1]
            out.append(f">={major}.{minor}.0, {s}")
        return out

    def _check_version_range(
        self,
        version: str,
        affected_ranges: list[str],
        patched_versions: list[str],
    ) -> CVEConfidence:
        """
        Per-CVE version classification.

        - CONFIRMED    : parsed version inside one well-formed affected range
        - NOT_AFFECTED : every range is well-formed and none contains the version
        - POTENTIALLY  : version unparseable, or some range unparseable and no
                         other range/patch info settles it
        - UNCERTAIN    : the CVE has no range data at all (nothing to compare)

        Ranges in the list are OR'ed; each range is an AND of its constraints.
        """
        v = self._parse_semver(version) if version else None
        if not v:
            return CVEConfidence.POTENTIALLY

        if not affected_ranges:
            # No range data: only an explicit patched version can clear it.
            # Without that we cannot say anything either way.
            fixes = [p for p in (self._parse_semver(x) for x in patched_versions) if p]
            if fixes and v >= max(fixes):
                return CVEConfidence.NOT_AFFECTED
            return CVEConfidence.UNCERTAIN

        ranges = self._normalize_ranges(affected_ranges)
        all_valid = True
        for range_str in ranges:
            if not self._range_is_valid(range_str):
                all_valid = False
                continue
            if self._version_in_range(v, range_str):
                return CVEConfidence.CONFIRMED

        if all_valid:
            return CVEConfidence.NOT_AFFECTED

        # Some range could not be evaluated: only clear the CVE if the version
        # is at/after the highest known fix (a lower-branch fix proves nothing).
        parsed_patches = [p for p in (self._parse_semver(x) for x in patched_versions) if p]
        if parsed_patches and v >= max(parsed_patches):
            return CVEConfidence.NOT_AFFECTED
        return CVEConfidence.POTENTIALLY

    def _parse_semver(self, version_str: str) -> Optional[tuple[int, ...]]:
        """Parse a version string into a 4-tuple of ints. Returns None on failure.

        Supports:
        - Standard semver: "1.6.3" → (1, 6, 3, 0)
        - 4-component: "15.1.2375.17" → (15, 1, 2375, 17) [Exchange OWA build]
        - Zimbra Patch notation: "8.8.15 Patch 41" → (8, 8, 15, 41)
        - Zimbra p-notation: "8.8.15.p41" → (8, 8, 15, 41)

        Always returns a 4-tuple so comparisons between any two parsed versions
        are consistent (no length mismatch when comparing 3-component against 4-component).
        """
        s = version_str.strip()

        # Zimbra "8.8.15 Patch 41" or "9.0.0 Patch 34"
        zm = re.match(r'^(\d+\.\d+\.\d+)\s+[Pp]atch\s+(\d+)', s)
        if zm:
            base = [int(x) for x in zm.group(1).split('.')]
            while len(base) < 3:
                base.append(0)
            return tuple(base[:3] + [int(zm.group(2))])

        # Zimbra "8.8.15.p41"
        pm = re.match(r'^(\d+\.\d+\.\d+)\.p(\d+)', s)
        if pm:
            base = [int(x) for x in pm.group(1).split('.')]
            while len(base) < 3:
                base.append(0)
            return tuple(base[:3] + [int(pm.group(2))])

        # OpenSSL letter releases: "1.1.1n", "1.0.2zd". The letter suffix is
        # encoded as the 4th component (a=1 … z=26, za=703 …) so ordering holds:
        # 1.1.1 < 1.1.1a < 1.1.1z < 1.1.1za. Without this, "1.1.1m" parsed as
        # 1.1.1 and fell outside ">=1.1.1, < 1.1.1n".
        lm = re.match(r'^(\d+)\.(\d+)\.(\d+)([a-z]{1,3})$', s)
        if lm:
            suffix = 0
            for ch in lm.group(4):
                suffix = suffix * 27 + (ord(ch) - 96)
            return (int(lm.group(1)), int(lm.group(2)), int(lm.group(3)), suffix)

        # Standard dotted decimal (1–4 components)
        m = re.match(r'^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?', s)
        if not m:
            return None
        parts = [int(g) for g in m.groups() if g is not None]
        while len(parts) < 4:
            parts.append(0)
        return tuple(parts)

    def _version_in_range(self, v: tuple[int, ...], range_str: str) -> bool:
        """Check if version tuple satisfies a range like '< 1.6.3' or '>= 1.5.0, < 1.5.4'."""
        try:
            if "," in range_str:
                parts = [p.strip() for p in range_str.split(",")]
                return all(self._single_constraint(v, p) for p in parts)
            return self._single_constraint(v, range_str.strip())
        except Exception:
            return False

    def _single_constraint(self, v: tuple[int, ...], constraint: str) -> bool:
        m = re.match(r'(>=|<=|>|<|==)\s*([0-9]+(?:\.[0-9]+)*[a-z]{0,3})', constraint.strip())
        if not m:
            return False
        op, ver_str = m.group(1), m.group(2)
        cv = self._parse_semver(ver_str)
        if not cv:
            return False
        if op == "<":
            return v < cv
        if op == "<=":
            return v <= cv
        if op == ">":
            return v > cv
        if op == ">=":
            return v >= cv
        if op == "==":
            return v == cv
        return False

    def _aggregate_confidence(
        self,
        cves: list[CVEEntry],
        version: Optional[str],
    ) -> CVEConfidence:
        # Unused: confidence is now computed per-CVE in _enrich_with_cves.
        # Kept for interface stability; callers outside this engine should not
        # rely on it since it cannot know individual CVE match results.
        if not cves:
            return CVEConfidence.UNKNOWN
        return CVEConfidence.POTENTIALLY

    async def _query_nvd(
        self,
        match: SoftwareMatch,
        api_key: str,
        redis_client: Optional[object],
        settings: object,
    ) -> None:
        """
        Query NVD API for CVEs matching the product keyword.
        Results cached in Redis for CVE_CACHE_TTL_SECONDS.
        """
        cache_key = f"mailox:nvd:{hashlib.sha256(match.product.lower().encode()).hexdigest()[:16]}"
        cache_ttl = getattr(settings, "CVE_CACHE_TTL_SECONDS", 3600)

        if redis_client:
            try:
                cached = await redis_client.get(cache_key)
                if cached:
                    cve_dicts = json.loads(cached)
                    for d in cve_dicts:
                        match.cves.append(CVEEntry(**d))
                    return
            except Exception as e:
                self.logger.debug("nvd_cache_miss", error=str(e))

        last_exc: Optional[Exception] = None
        for attempt in range(3):
            try:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    resp = await client.get(
                        "https://services.nvd.nist.gov/rest/json/cves/2.0",
                        params={"keywordSearch": match.product, "resultsPerPage": 20},
                        headers={"apiKey": api_key},
                    )

                if resp.status_code in (429, 503):
                    # Rate-limited or temporarily unavailable — respect Retry-After if set,
                    # otherwise use exponential backoff. Cap at 30s to avoid indefinite delay.
                    retry_after_raw = resp.headers.get("Retry-After")
                    if retry_after_raw is not None:
                        try:
                            delay = min(float(retry_after_raw), 30.0)
                        except (ValueError, TypeError):
                            delay = float(2 ** attempt)
                    else:
                        delay = float(2 ** attempt)
                    self.logger.debug(
                        "nvd_rate_limited",
                        attempt=attempt,
                        status=resp.status_code,
                        delay=delay,
                        product=match.product,
                    )
                    await asyncio.sleep(delay)
                    continue

                if resp.status_code != 200:
                    self.logger.debug("nvd_api_error", status=resp.status_code)
                    return

                data = resp.json()
                cve_dicts = []
                for item in data.get("vulnerabilities", []):
                    cve_data = item.get("cve", {})
                    cve_id = cve_data.get("id", "")
                    desc = next(
                        (d["value"] for d in cve_data.get("descriptions", []) if d.get("lang") == "en"),
                        "",
                    )
                    metrics = cve_data.get("metrics", {})
                    cvss_score = None
                    cvss_vector = None
                    severity = "UNKNOWN"
                    for m_list in metrics.get("cvssMetricV31", []):
                        cvss_data = m_list.get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        cvss_vector = cvss_data.get("vectorString")
                        severity = cvss_data.get("baseSeverity", "UNKNOWN")
                        break

                    refs = [r.get("url", "") for r in cve_data.get("references", [])[:3]]
                    entry_dict = {
                        "cve_id": cve_id,
                        "description": desc[:500],
                        "cvss_score": cvss_score,
                        "cvss_vector": cvss_vector,
                        "severity": severity,
                        "affected_versions": [],
                        "published_date": cve_data.get("published", "")[:10],
                        "patched_versions": [],
                        "references": refs,
                        "in_cisa_kev": False,
                        "exploit_available": False,
                    }
                    cve_dicts.append(entry_dict)
                    match.cves.append(CVEEntry(**entry_dict))

                if redis_client and cve_dicts:
                    try:
                        await redis_client.setex(cache_key, cache_ttl, json.dumps(cve_dicts))
                    except Exception:
                        pass
                return  # success

            except (httpx.TimeoutException, httpx.ConnectError) as exc:
                last_exc = exc
                self.logger.debug(
                    "nvd_network_error",
                    attempt=attempt,
                    error=type(exc).__name__,
                    product=match.product,
                )
                if attempt < 2:
                    await asyncio.sleep(2 ** attempt)
            except Exception as exc:
                self.logger.debug("nvd_query_failed", product=match.product, error=type(exc).__name__)
                return

        if last_exc:
            self.logger.debug(
                "nvd_all_attempts_failed",
                product=match.product,
                error=type(last_exc).__name__,
            )

    def _emit_cve_findings(
        self,
        result: EngineResult,
        match: SoftwareMatch,
        domain: str,
    ) -> None:
        # Emit INFO finding when product detected but all checked CVEs are patched
        if not match.cves and match.not_affected_cves:
            cve_ids = ", ".join(c.cve_id for c in match.not_affected_cves)
            version_str = match.version or "unknown version"
            result.add_finding(self._make_finding(
                check_id=f"VI-CLEAN-{match.product.upper().replace(' ', '_')}",
                title=f"{match.product} {version_str} — no known CVEs apply",
                description=(
                    f"Detected {match.product} {version_str}. "
                    f"All {len(match.not_affected_cves)} CVEs in the local database were checked "
                    f"and none apply to this version: {cve_ids}. "
                    "This does not guarantee absence of vulnerabilities outside the checked set."
                ),
                risk_level=RiskLevel.INFO,
                confidence=0.95,
                evidence=[Evidence(
                    type=EvidenceType.ANALYSIS,
                    observed_value=f"{match.product} {version_str}",
                    expected_value="No vulnerable version range matches",
                    source=domain,
                    technical_details={
                        "product": match.product,
                        "version": match.version,
                        "cves_checked": [
                            {
                                "cve_id": c.cve_id,
                                "severity": c.severity,
                                "cvss_score": c.cvss_score,
                                "affected_versions": c.affected_versions,
                                "patched_versions": c.patched_versions,
                                "status": "NOT_AFFECTED",
                            }
                            for c in match.not_affected_cves
                        ],
                    },
                )],
                remediation=(
                    f"Keep {match.product} up to date. "
                    "Monitor vendor security advisories for new CVEs."
                ),
                affected_asset=domain,
            ))
            return

        if not match.cves:
            return

        if not match.version:
            # Unable to determine: a product name alone says nothing about
            # which CVEs apply. One INFO coverage-gap finding, no CVE findings.
            self._emit_version_undetermined(result, match, domain)
            return

        confidence_map = {
            CVEConfidence.CONFIRMED: 0.9,
            CVEConfidence.POTENTIALLY: 0.5,
            CVEConfidence.UNCERTAIN: 0.3,
        }
        title_suffix = {
            CVEConfidence.CONFIRMED: "",
            CVEConfidence.POTENTIALLY: " (version unconfirmed)",
            CVEConfidence.UNCERTAIN: " (no version range data)",
        }

        for cve in match.cves:
            status = match.cve_status.get(cve.cve_id, CVEConfidence.UNCERTAIN)
            if status not in confidence_map:
                # NOT_AFFECTED / UNKNOWN never become CVE findings.
                continue
            # CVSS / severity are the stored NVD values; never derived here.
            risk = _SEVERITY_TO_RISK.get((cve.severity or "").upper(), RiskLevel.MEDIUM)
            confidence = confidence_map[status]

            kev_note = " [CISA KEV — actively exploited]" if cve.in_cisa_kev else ""
            exploit_note = " Exploit code available." if cve.exploit_available else ""
            title_confidence = title_suffix[status]

            result.add_finding(self._make_finding(
                check_id=f"VI-{cve.cve_id}",
                title=f"{cve.cve_id}{kev_note} in {match.product}{title_confidence}",
                description=(
                    f"{cve.cve_id} ({cve.severity}, CVSS {cve.cvss_score or 'N/A'}): "
                    f"{cve.description}{exploit_note} "
                    f"Detected product: {match.product}"
                    + (f" version {match.version}" if match.version else " (version not identified)")
                    + f". CVE confidence: {status.value}."
                ),
                risk_level=risk,
                confidence=confidence,
                evidence=[Evidence(
                    type=EvidenceType.ANALYSIS,
                    observed_value=f"{match.product} {match.version or 'unknown version'}",
                    expected_value=f"Patched: {', '.join(cve.patched_versions) or 'unknown'}",
                    source=domain,
                    technical_details={
                        "cve_id": cve.cve_id,
                        "cvss_score": cve.cvss_score,
                        "cvss_vector": cve.cvss_vector,
                        "severity": cve.severity,
                        "in_cisa_kev": cve.in_cisa_kev,
                        "exploit_available": cve.exploit_available,
                        "confidence": status.value,
                        "product": match.product,
                        "version": match.version,
                        "published_date": cve.published_date,
                    },
                )],
                remediation=(
                    f"Upgrade {match.product} to a version that includes the fix for {cve.cve_id}. "
                    f"Patched versions: {', '.join(cve.patched_versions) or 'check vendor advisory'}."
                ),
                affected_asset=domain,
                business_impact=(
                    "Known CVEs with public exploits can be weaponized for unauthorized access, "
                    "data exfiltration, or lateral movement."
                    + (" Actively exploited in the wild per CISA KEV." if cve.in_cisa_kev else "")
                ),
                references=cve.references or [f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}"],
            ))

    def _emit_version_undetermined(
        self,
        result: EngineResult,
        match: SoftwareMatch,
        domain: str,
    ) -> None:
        product_tag = re.sub(r"[^A-Z0-9]+", "_", match.product.upper()).strip("_")
        cve_ids = [c.cve_id for c in match.cves]
        result.add_finding(self._make_finding(
            check_id=f"VI-VERSION-UNDETERMINED-{product_tag}",
            title=f"{match.product} detected — version undetermined, CVE exposure not assessed",
            description=(
                f"{match.product} was identified but its version could not be determined "
                f"(e.g. version hidden in the banner). {len(cve_ids)} known CVE(s) for this "
                "product could not be evaluated and are NOT reported as findings. "
                "Confirm the version with an authenticated/local check."
            ),
            risk_level=RiskLevel.INFO,
            confidence=0.5,
            evidence=[Evidence(
                type=EvidenceType.ANALYSIS,
                observed_value=f"{match.product} (version not disclosed)",
                expected_value="Identifiable product version",
                source=domain,
                technical_details={
                    "product": match.product,
                    "version": None,
                    "source_engine": match.source_engine,
                    "confidence": CVEConfidence.UNKNOWN.value,
                    "cves_not_evaluated": cve_ids,
                },
            )],
            remediation=(
                f"Determine the deployed {match.product} version locally and compare it "
                "against vendor advisories."
            ),
            affected_asset=domain,
        ))

    async def _get_redis(self) -> Optional[object]:
        """Lazy-init Redis connection. Returns None if unavailable."""
        if self._redis is not None:
            return self._redis
        try:
            import redis.asyncio as aioredis
            from app.core.config import settings
            self._redis = await aioredis.from_url(settings.REDIS_URL, decode_responses=True)
            return self._redis
        except Exception:
            return None
