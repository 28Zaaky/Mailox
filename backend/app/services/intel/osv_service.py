import asyncio
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Optional

import httpx
import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.cve_intel import VulnRelevance
from app.services.intel.base import BaseIntelService, SyncResult

logger = structlog.get_logger("mailox.services.intel.osv")

_OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# (ecosystem, package_name, canonical_product_name)
_OSV_TARGETS = [
    ("Packagist", "roundcube/roundcube", "roundcube"),
    ("Packagist", "horde/horde", "horde"),
    ("Packagist", "horde/imp", "horde"),
    ("Packagist", "squirrelmail/squirrelmail", "squirrelmail"),
]


def _parse_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _extract_version_events(osv_ranges: list) -> list[dict]:
    results = []
    for r in osv_ranges:
        if r.get("type") not in ("SEMVER", "ECOSYSTEM"):
            continue
        introduced = None
        fixed = None
        last_affected = None
        for event in r.get("events", []):
            if "introduced" in event:
                introduced = event["introduced"] if event["introduced"] != "0" else None
            elif "fixed" in event:
                fixed = event["fixed"]
            elif "last_affected" in event:
                last_affected = event["last_affected"]
        results.append({
            "introduced": introduced,
            "fixed": fixed,
            "last_affected": last_affected,
            "type": r.get("type", "SEMVER").lower(),
        })
    return results


class OSVIngestionService(BaseIntelService):
    source_name = "OSV"

    async def sync(self, db: AsyncSession) -> SyncResult:
        result = SyncResult()
        await self._update_sync_status(db, result, is_running=True)
        await db.commit()

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                for ecosystem, package, product_name in _OSV_TARGETS:
                    logger.info("osv.sync.package", ecosystem=ecosystem, package=package)
                    try:
                        await self._sync_package(db, client, ecosystem, package, product_name, result)
                        await asyncio.sleep(0.5)
                    except Exception as exc:
                        logger.warning("osv.sync.package.error", package=package, error=str(exc))
                        result.failed += 1

        except Exception as exc:
            result.error = str(exc)
            logger.error("osv.sync.fatal", error=str(exc))

        await self._update_sync_status(db, result, is_running=False)
        await db.commit()
        return result

    async def _sync_package(
        self,
        db: AsyncSession,
        client: httpx.AsyncClient,
        ecosystem: str,
        package: str,
        product_name: str,
        result: SyncResult,
    ) -> None:
        payload = {"package": {"name": package, "ecosystem": ecosystem}}
        resp = await client.post(_OSV_QUERY_URL, json=payload)
        resp.raise_for_status()
        data = resp.json()

        vulns = data.get("vulns", [])
        logger.info("osv.package.results", package=package, count=len(vulns))

        product = await self._upsert_product(db, product_name, {
            "category": "webmail",
            "ecosystem": ecosystem,
            "aliases": [package],
        })
        await db.commit()

        batch_count = 0
        for osv_vuln in vulns:
            try:
                await self._process_osv_vuln(db, osv_vuln, product, result)
                batch_count += 1
                if batch_count % 100 == 0:
                    await db.commit()
            except Exception as exc:
                logger.warning("osv.vuln.error", id=osv_vuln.get("id"), error=str(exc))
                result.failed += 1

        await db.commit()

    async def _process_osv_vuln(
        self,
        db: AsyncSession,
        osv_vuln: dict,
        product: object,
        result: SyncResult,
    ) -> None:
        osv_id = osv_vuln.get("id", "")
        aliases = osv_vuln.get("aliases", [])

        # Prefer CVE ID from aliases
        cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
        if not cve_id:
            # Use OSV ID as the record key if no CVE alias
            cve_id = osv_id

        if not cve_id:
            result.skipped += 1
            return

        summary = osv_vuln.get("summary", "")
        details = osv_vuln.get("details", "")
        description = details or summary

        # CVSS from severity array
        cvss_score = None
        severity_str = None
        for sev in osv_vuln.get("severity", []):
            score_str = sev.get("score", "")
            if sev.get("type") == "CVSS_V3" and score_str:
                # Score string may be a CVSS vector or numeric; try numeric
                try:
                    cvss_score = float(score_str)
                except ValueError:
                    pass
                if cvss_score is not None:
                    if cvss_score >= 9.0:
                        severity_str = "CRITICAL"
                    elif cvss_score >= 7.0:
                        severity_str = "HIGH"
                    elif cvss_score >= 4.0:
                        severity_str = "MEDIUM"
                    else:
                        severity_str = "LOW"

        fields = {
            "title": summary[:500] if summary else None,
            "description": description,
            "published_at": _parse_dt(osv_vuln.get("published")),
            "modified_at": _parse_dt(osv_vuln.get("modified")),
            "status": "active",
            "cvss_v3_score": cvss_score,
            "severity": severity_str,
            "references": [r.get("url", "") for r in osv_vuln.get("references", []) if r.get("url")],
            "relevance": VulnRelevance.APPLICATION.value,
            "relevance_confidence": 0.8,
            "source_confidence": 0.9,
        }

        raw_hash = hashlib.sha256(
            json.dumps(osv_vuln, sort_keys=True, default=str).encode()
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
            osv_id,
            f"https://osv.dev/vulnerability/{osv_id}",
            _parse_dt(osv_vuln.get("modified")),
            raw_hash,
        )

        # Version ranges
        for affected in osv_vuln.get("affected", []):
            for version_range in _extract_version_events(affected.get("ranges", [])):
                await self._upsert_affected_range(
                    db,
                    vuln.id,
                    product.id,
                    version_range.get("introduced"),
                    version_range.get("fixed"),
                    version_range.get("last_affected"),
                    "semver",
                    [],
                    "OSV",
                )
