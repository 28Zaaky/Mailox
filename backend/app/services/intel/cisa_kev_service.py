import hashlib
import json
import uuid
from datetime import date, datetime, timezone
from typing import Optional

import httpx
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.cve_intel import CveVulnerability, VulnRelevance
from app.services.intel.base import BaseIntelService, SyncResult

logger = structlog.get_logger("mailox.services.intel.cisa_kev")

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _parse_date(s: Optional[str]) -> Optional[date]:
    if not s:
        return None
    try:
        return date.fromisoformat(s)
    except (ValueError, AttributeError):
        return None


class CISAKEVService(BaseIntelService):
    source_name = "CISA_KEV"

    async def sync(self, db: AsyncSession) -> SyncResult:
        result = SyncResult()
        await self._update_sync_status(db, result, is_running=True)
        await db.commit()

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(_KEV_URL)
                resp.raise_for_status()
                data = resp.json()

            entries = data.get("vulnerabilities", [])
            logger.info("cisa_kev.fetched", count=len(entries))

            batch_count = 0
            for entry in entries:
                try:
                    await self._process_entry(db, entry, result)
                    batch_count += 1
                    if batch_count % 100 == 0:
                        await db.commit()
                except Exception as exc:
                    logger.warning("cisa_kev.entry.error", cve=entry.get("cveID"), error=str(exc))
                    result.failed += 1

        except Exception as exc:
            result.error = str(exc)
            logger.error("cisa_kev.sync.fatal", error=str(exc))

        await self._update_sync_status(db, result, is_running=False)
        await db.commit()
        return result

    async def _process_entry(
        self,
        db: AsyncSession,
        entry: dict,
        result: SyncResult,
    ) -> None:
        cve_id = entry.get("cveID", "")
        if not cve_id or not cve_id.startswith("CVE-"):
            result.skipped += 1
            return

        date_added = _parse_date(entry.get("dateAdded"))
        due_date = _parse_date(entry.get("dueDate"))
        ransomware_use = (entry.get("knownRansomwareCampaignUse", "Unknown") == "Known")
        required_action = entry.get("requiredAction", "")
        description = entry.get("shortDescription", "") or entry.get("vulnerabilityName", "")
        vendor = entry.get("vendorProject", "")
        product = entry.get("product", "")

        # Look up existing vulnerability
        res = await db.execute(
            select(CveVulnerability).where(CveVulnerability.cve_id == cve_id)
        )
        vuln = res.scalar_one_or_none()

        kev_fields = {
            "in_cisa_kev": True,
            "kev_date_added": date_added,
            "kev_required_action": required_action,
            "kev_due_date": due_date,
            "kev_ransomware_use": ransomware_use,
            "exploit_available": True,
            "relevance": VulnRelevance.DIRECT.value,
            "relevance_confidence": 0.95,
        }

        if vuln is not None:
            # Update KEV fields on existing record
            for k, v in kev_fields.items():
                setattr(vuln, k, v)
            vuln.updated_at = datetime.now(timezone.utc)
            await db.flush()
            result.updated += 1
        else:
            # Create minimal record — CISA KEV is authoritative for exploitability
            minimal_fields = {
                **kev_fields,
                "title": entry.get("vulnerabilityName", cve_id)[:500],
                "description": description,
                "status": "active",
                "source_confidence": 1.0,
            }
            vuln, created = await self._upsert_vulnerability(db, cve_id, minimal_fields)
            if created:
                result.added += 1
            else:
                result.updated += 1

        raw_hash = hashlib.sha256(
            json.dumps(entry, sort_keys=True, default=str).encode()
        ).hexdigest()

        await self._upsert_source(
            db,
            vuln.id,
            self.source_name,
            cve_id,
            f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog#{cve_id.lower()}",
            None,
            raw_hash,
        )
