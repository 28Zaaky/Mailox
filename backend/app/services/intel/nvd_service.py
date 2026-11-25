import asyncio
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.models.cve_intel import VulnRelevance
from app.services.intel.base import BaseIntelService, SyncResult

logger = structlog.get_logger("mailox.services.intel.nvd")

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_PAGE_SIZE = 2000

_EMAIL_PRODUCTS = [
    "exim",
    "postfix",
    "dovecot",
    "roundcube",
    "zimbra",
    "horde",
    "squirrelmail",
    "sendmail",
    "openssl",
    "microsoft exchange",
    "microsoft owa",
]

_PRODUCT_CATEGORY_MAP = {
    "exim": "smtp",
    "postfix": "smtp",
    "sendmail": "smtp",
    "dovecot": "imap_pop3",
    "roundcube": "webmail",
    "zimbra": "webmail",
    "horde": "webmail",
    "squirrelmail": "webmail",
    "openssl": "tls_crypto",
    "microsoft exchange": "smtp",
    "microsoft owa": "webmail",
}


def _classify_relevance(description: str) -> str:
    desc_lower = (description or "").lower()
    if any(kw in desc_lower for kw in ("remote code execution", "unauthenticated", "authentication bypass", "pre-auth")):
        return VulnRelevance.DIRECT.value
    if "information disclosure" in desc_lower:
        return VulnRelevance.APPLICATION.value
    if any(kw in desc_lower for kw in ("denial of service", "dos", "memory corruption")):
        return VulnRelevance.INFRASTRUCTURE.value
    return VulnRelevance.INFRASTRUCTURE.value


def _parse_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _extract_cvss(metrics: dict) -> tuple[Optional[float], Optional[str], Optional[str]]:
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            return (
                data.get("baseScore"),
                data.get("vectorString"),
                data.get("baseSeverity"),
            )
    return None, None, None


def _extract_cwe(weaknesses: list) -> list[str]:
    result = []
    for w in weaknesses:
        for desc in w.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                result.append(val)
    return list(set(result))


def _extract_version_ranges(configurations: list, product_name: str) -> list[dict]:
    ranges = []
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", False):
                    continue
                cpe = match.get("criteria", "")
                if product_name.lower().replace(" ", "_") not in cpe.lower().replace(" ", "_"):
                    continue
                ranges.append({
                    "introduced": match.get("versionStartIncluding"),
                    "fixed": match.get("versionEndExcluding"),
                    "last_affected": match.get("versionEndIncluding"),
                    "cpe": cpe,
                })
    return ranges


class NVDIngestionService(BaseIntelService):
    source_name = "NVD"

    def __init__(self) -> None:
        self._api_key = settings.NVD_API_KEY
        # With key: 50 req/30s → ~0.6s between requests
        # Without key: 5 req/30s → 6s between requests
        self._request_delay = 0.7 if self._api_key else 6.5

    async def sync(self, db: AsyncSession) -> SyncResult:
        result = SyncResult()
        await self._update_sync_status(db, result, is_running=True)
        await db.commit()

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                for product_name in _EMAIL_PRODUCTS:
                    logger.info("nvd.sync.product", product=product_name)
                    try:
                        await self._sync_product(db, client, product_name, result)
                    except Exception as exc:
                        logger.warning("nvd.sync.product.error", product=product_name, error=str(exc))
                        result.failed += 1

        except Exception as exc:
            result.error = str(exc)
            logger.error("nvd.sync.fatal", error=str(exc))

        await self._update_sync_status(db, result, is_running=False)
        await db.commit()
        return result

    async def _sync_product(
        self,
        db: AsyncSession,
        client: httpx.AsyncClient,
        product_name: str,
        result: SyncResult,
    ) -> None:
        product = await self._upsert_product(db, product_name, {
            "category": _PRODUCT_CATEGORY_MAP.get(product_name, "other"),
            "vendor": product_name.split()[0].capitalize(),
            "aliases": [],
            "cpe_identifiers": [],
        })
        await db.commit()

        start_index = 0
        total_results = None
        batch_count = 0

        while total_results is None or start_index < total_results:
            params: dict[str, Any] = {
                "keywordSearch": product_name,
                "resultsPerPage": _PAGE_SIZE,
                "startIndex": start_index,
            }
            headers = {}
            if self._api_key:
                headers["apiKey"] = self._api_key

            resp = await self._fetch_with_retry(client, _NVD_BASE, params, headers)
            data = resp.json()

            total_results = data.get("totalResults", 0)
            items = data.get("vulnerabilities", [])

            for item in items:
                try:
                    await self._process_cve(db, item, product, product_name, result)
                    batch_count += 1
                    if batch_count % 100 == 0:
                        await db.commit()
                except Exception as exc:
                    logger.warning("nvd.cve.process.error", cve=item.get("cve", {}).get("id"), error=str(exc))
                    result.failed += 1

            start_index += len(items)
            if not items:
                break

            await asyncio.sleep(self._request_delay)

        await db.commit()

    async def _process_cve(
        self,
        db: AsyncSession,
        item: dict,
        product: Any,
        product_name: str,
        result: SyncResult,
    ) -> None:
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "")
        if not cve_id:
            result.skipped += 1
            return

        descriptions = cve_data.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"), None
        )

        metrics = cve_data.get("metrics", {})
        cvss_score, cvss_vector, severity = _extract_cvss(metrics)

        references = [r.get("url", "") for r in cve_data.get("references", []) if r.get("url")]
        cwe_ids = _extract_cwe(cve_data.get("weaknesses", []))

        relevance = _classify_relevance(description or "")

        fields = {
            "title": (description or "")[:500] if description else None,
            "description": description,
            "published_at": _parse_dt(cve_data.get("published")),
            "modified_at": _parse_dt(cve_data.get("lastModified")),
            "status": "active",
            "cvss_v3_score": cvss_score,
            "cvss_v3_vector": cvss_vector,
            "severity": severity,
            "cwe_ids": cwe_ids,
            "references": references,
            "exploit_available": False,
            "relevance": relevance,
            "relevance_confidence": 0.7,
            "source_confidence": 0.95,
        }

        raw_hash = hashlib.sha256(
            json.dumps(fields, sort_keys=True, default=str).encode()
        ).hexdigest()

        vuln, created = await self._upsert_vulnerability(db, cve_id, fields)
        if created:
            result.added += 1
        else:
            result.updated += 1

        await self._upsert_source(
            db,
            vuln.id,
            self.source_name,
            cve_id,
            f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            _parse_dt(cve_data.get("lastModified")),
            raw_hash,
        )

        # Version ranges from CPE configurations
        version_ranges = _extract_version_ranges(
            cve_data.get("configurations", []), product_name
        )
        for vr in version_ranges:
            await self._upsert_affected_range(
                db,
                vuln.id,
                product.id,
                vr.get("introduced"),
                vr.get("fixed"),
                vr.get("last_affected"),
                "semver",
                [],
                "NVD",
            )

    async def _fetch_with_retry(
        self,
        client: httpx.AsyncClient,
        url: str,
        params: dict,
        headers: dict,
        max_retries: int = 3,
    ) -> httpx.Response:
        delay = 10.0
        for attempt in range(max_retries + 1):
            try:
                resp = await client.get(url, params=params, headers=headers)
                if resp.status_code == 429:
                    wait = min(delay * (2 ** attempt), 60.0)
                    logger.warning("nvd.rate_limited", wait=wait, attempt=attempt)
                    await asyncio.sleep(wait)
                    continue
                resp.raise_for_status()
                return resp
            except httpx.HTTPStatusError as exc:
                if attempt == max_retries:
                    raise
                await asyncio.sleep(delay * (2 ** attempt))
        raise RuntimeError(f"NVD request failed after {max_retries} retries")
