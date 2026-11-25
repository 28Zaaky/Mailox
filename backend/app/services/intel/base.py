import hashlib
import json
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

import structlog
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.cve_intel import (
    CveAffectedRange,
    CveProduct,
    CveSource,
    CveSyncStatus,
    CveVulnerability,
)

logger = structlog.get_logger("mailox.services.intel.base")


@dataclass
class SyncResult:
    added: int = 0
    updated: int = 0
    skipped: int = 0
    failed: int = 0
    error: Optional[str] = None


class BaseIntelService(ABC):
    source_name: str = ""

    @abstractmethod
    async def sync(self, db: AsyncSession) -> SyncResult:
        ...

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _upsert_vulnerability(
        self,
        db: AsyncSession,
        cve_id: str,
        fields: dict[str, Any],
    ) -> tuple["CveVulnerability", bool]:
        raw_hash = hashlib.sha256(
            json.dumps(fields, sort_keys=True, default=str).encode()
        ).hexdigest()

        result = await db.execute(
            select(CveVulnerability).where(CveVulnerability.cve_id == cve_id)
        )
        vuln = result.scalar_one_or_none()

        if vuln is None:
            vuln = CveVulnerability(id=uuid.uuid4(), cve_id=cve_id, **fields)
            db.add(vuln)
            await db.flush()
            return vuln, True

        # Check if content changed
        existing_source = await db.execute(
            select(CveSource).where(
                CveSource.vulnerability_id == vuln.id,
                CveSource.source_name == self.source_name,
            )
        )
        src = existing_source.scalar_one_or_none()
        if src and src.raw_record_hash == raw_hash:
            return vuln, False

        # Update changed fields
        for k, v in fields.items():
            if hasattr(vuln, k):
                setattr(vuln, k, v)
        vuln.updated_at = datetime.now(timezone.utc)
        await db.flush()
        return vuln, False

    async def _upsert_product(
        self,
        db: AsyncSession,
        canonical_name: str,
        fields: dict[str, Any],
    ) -> CveProduct:
        result = await db.execute(
            select(CveProduct).where(CveProduct.canonical_name == canonical_name)
        )
        product = result.scalar_one_or_none()
        if product is None:
            product = CveProduct(id=uuid.uuid4(), canonical_name=canonical_name, **fields)
            db.add(product)
            await db.flush()
        return product

    async def _upsert_source(
        self,
        db: AsyncSession,
        vuln_id: uuid.UUID,
        source_name: str,
        source_record_id: Optional[str],
        source_url: Optional[str],
        source_modified_at: Optional[datetime],
        raw_record_hash: str,
    ) -> None:
        result = await db.execute(
            select(CveSource).where(
                CveSource.vulnerability_id == vuln_id,
                CveSource.source_name == source_name,
            )
        )
        src = result.scalar_one_or_none()
        now = datetime.now(timezone.utc)
        if src is None:
            src = CveSource(
                id=uuid.uuid4(),
                vulnerability_id=vuln_id,
                source_name=source_name,
                source_record_id=source_record_id,
                source_url=source_url,
                retrieved_at=now,
                source_modified_at=source_modified_at,
                raw_record_hash=raw_record_hash,
            )
            db.add(src)
        else:
            src.retrieved_at = now
            src.source_modified_at = source_modified_at
            src.raw_record_hash = raw_record_hash
            src.source_record_id = source_record_id
            src.source_url = source_url
        await db.flush()

    async def _upsert_affected_range(
        self,
        db: AsyncSession,
        vuln_id: uuid.UUID,
        product_id: uuid.UUID,
        introduced: Optional[str],
        fixed: Optional[str],
        last_affected: Optional[str],
        version_type: str,
        constraints: list[str],
        source: str,
    ) -> None:
        result = await db.execute(
            select(CveAffectedRange).where(
                CveAffectedRange.vulnerability_id == vuln_id,
                CveAffectedRange.product_id == product_id,
                CveAffectedRange.introduced_version == introduced,
                CveAffectedRange.fixed_version == fixed,
            )
        )
        rng = result.scalar_one_or_none()
        if rng is None:
            rng = CveAffectedRange(
                id=uuid.uuid4(),
                vulnerability_id=vuln_id,
                product_id=product_id,
                introduced_version=introduced,
                fixed_version=fixed,
                last_affected_version=last_affected,
                version_type=version_type,
                version_constraints=constraints,
                source=source,
                range_confidence=0.9,
            )
            db.add(rng)
            await db.flush()

    async def _update_sync_status(
        self,
        db: AsyncSession,
        result: SyncResult,
        is_running: bool = False,
    ) -> None:
        now = datetime.now(timezone.utc)
        existing = await db.execute(
            select(CveSyncStatus).where(CveSyncStatus.source_name == self.source_name)
        )
        status = existing.scalar_one_or_none()
        if status is None:
            status = CveSyncStatus(source_name=self.source_name, updated_at=now)
            db.add(status)

        status.is_running = is_running
        status.last_sync_at = now
        status.records_added = result.added
        status.records_updated = result.updated
        status.records_skipped = result.skipped
        status.records_failed = result.failed
        status.error_msg = result.error
        status.updated_at = now
        if not result.error:
            status.last_success_at = now
        await db.flush()
