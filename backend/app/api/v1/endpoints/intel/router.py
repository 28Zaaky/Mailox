import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_user
from app.db.models.cve_intel import (
    CveAffectedRange, CveProduct, CveSyncStatus, CveVulnerability, VulnRelevance,
)
from app.db.models.user import User
from app.db.session import get_db
from app.api.v1.endpoints.intel.schemas import (
    AffectedRangeOut, ProductOut, RelevancePatch, SourceOut,
    SyncStatusOut, SyncTriggerResponse, VulnerabilityDetail,
    VulnerabilityListResponse, VulnerabilityOut,
)

router = APIRouter(prefix="/intel", tags=["intel"])

_VALID_SOURCES = {"nvd", "cisa_kev", "osv", "all"}


def _require_admin(current_user: User = Depends(get_current_user)) -> User:
    if not current_user.is_platform_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin only")
    return current_user


# ── Vulnerabilities list ──────────────────────────────────────────────────────

@router.get("/vulnerabilities", response_model=VulnerabilityListResponse)
async def list_vulnerabilities(
    severity: Optional[List[str]] = Query(None),
    relevance: Optional[List[str]] = Query(None),
    in_cisa_kev: Optional[bool] = Query(None),
    exploit_available: Optional[bool] = Query(None),
    product: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> VulnerabilityListResponse:
    # Subquery: count distinct products per vulnerability
    product_count_sq = (
        select(
            CveAffectedRange.vulnerability_id,
            func.count(func.distinct(CveAffectedRange.product_id)).label("cnt"),
        )
        .group_by(CveAffectedRange.vulnerability_id)
        .subquery()
    )

    q = select(CveVulnerability, func.coalesce(product_count_sq.c.cnt, 0).label("apc")).outerjoin(
        product_count_sq, product_count_sq.c.vulnerability_id == CveVulnerability.id
    )

    if severity:
        q = q.where(CveVulnerability.severity.in_(severity))
    if relevance:
        q = q.where(CveVulnerability.relevance.in_(relevance))
    if in_cisa_kev is not None:
        q = q.where(CveVulnerability.in_cisa_kev == in_cisa_kev)
    if exploit_available is not None:
        q = q.where(CveVulnerability.exploit_available == exploit_available)
    if product:
        product_ids_sq = (
            select(CveAffectedRange.vulnerability_id)
            .join(CveProduct, CveProduct.id == CveAffectedRange.product_id)
            .where(
                or_(
                    CveProduct.canonical_name.ilike(f"%{product}%"),
                    CveProduct.aliases.astext.ilike(f"%{product}%"),
                )
            )
        )
        q = q.where(CveVulnerability.id.in_(product_ids_sq))
    if search:
        q = q.where(
            or_(
                CveVulnerability.cve_id.ilike(f"%{search}%"),
                CveVulnerability.description.ilike(f"%{search}%"),
                CveVulnerability.title.ilike(f"%{search}%"),
            )
        )

    # Total count
    count_q = select(func.count()).select_from(q.subquery())
    total_result = await db.execute(count_q)
    total = total_result.scalar_one()

    # Paginated results
    q = q.order_by(CveVulnerability.published_at.desc().nullslast()).offset(
        (page - 1) * per_page
    ).limit(per_page)

    rows = await db.execute(q)
    items = []
    for vuln, apc in rows.all():
        items.append(
            VulnerabilityOut(
                id=vuln.id,
                cve_id=vuln.cve_id,
                title=vuln.title,
                description=vuln.description,
                published_at=vuln.published_at,
                severity=vuln.severity,
                cvss_v3_score=vuln.cvss_v3_score,
                in_cisa_kev=vuln.in_cisa_kev,
                exploit_available=vuln.exploit_available,
                relevance=vuln.relevance,
                affected_product_count=apc or 0,
            )
        )

    return VulnerabilityListResponse(items=items, total=total, page=page, per_page=per_page)


# ── Vulnerability detail ──────────────────────────────────────────────────────

@router.get("/vulnerabilities/{cve_id}", response_model=VulnerabilityDetail)
async def get_vulnerability(
    cve_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> VulnerabilityDetail:
    result = await db.execute(
        select(CveVulnerability)
        .where(CveVulnerability.cve_id == cve_id.upper())
        .options(
            selectinload(CveVulnerability.affected_ranges).selectinload(CveAffectedRange.product),
            selectinload(CveVulnerability.sources),
        )
    )
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="CVE not found")

    ranges = [
        AffectedRangeOut(
            product_name=r.product.canonical_name if r.product else "unknown",
            introduced_version=r.introduced_version,
            fixed_version=r.fixed_version,
            last_affected_version=r.last_affected_version,
            version_type=r.version_type,
            version_constraints=r.version_constraints or [],
        )
        for r in vuln.affected_ranges
    ]
    sources = [
        SourceOut(
            source_name=s.source_name,
            source_record_id=s.source_record_id,
            source_url=s.source_url,
            retrieved_at=s.retrieved_at,
        )
        for s in vuln.sources
    ]

    unique_products = {r.product_id for r in vuln.affected_ranges}

    return VulnerabilityDetail(
        id=vuln.id,
        cve_id=vuln.cve_id,
        title=vuln.title,
        description=vuln.description,
        published_at=vuln.published_at,
        severity=vuln.severity,
        cvss_v3_score=vuln.cvss_v3_score,
        cvss_v3_vector=vuln.cvss_v3_vector,
        in_cisa_kev=vuln.in_cisa_kev,
        exploit_available=vuln.exploit_available,
        exploit_references=vuln.exploit_references or [],
        relevance=vuln.relevance,
        affected_product_count=len(unique_products),
        cwe_ids=vuln.cwe_ids or [],
        references=vuln.references or [],
        kev_date_added=vuln.kev_date_added,
        kev_required_action=vuln.kev_required_action,
        kev_due_date=vuln.kev_due_date,
        kev_ransomware_use=vuln.kev_ransomware_use,
        affected_ranges=ranges,
        sources=sources,
    )


# ── Products list ─────────────────────────────────────────────────────────────

@router.get("/products", response_model=List[ProductOut])
async def list_products(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> List[ProductOut]:
    cve_count_sq = (
        select(
            CveAffectedRange.product_id,
            func.count(func.distinct(CveAffectedRange.vulnerability_id)).label("cnt"),
        )
        .group_by(CveAffectedRange.product_id)
        .subquery()
    )

    result = await db.execute(
        select(CveProduct, func.coalesce(cve_count_sq.c.cnt, 0).label("cve_count"))
        .outerjoin(cve_count_sq, cve_count_sq.c.product_id == CveProduct.id)
        .where(CveProduct.is_active == True)  # noqa: E712
        .order_by(CveProduct.canonical_name)
    )

    return [
        ProductOut(
            id=p.id,
            canonical_name=p.canonical_name,
            vendor=p.vendor,
            category=p.category,
            aliases=p.aliases or [],
            cve_count=cnt or 0,
        )
        for p, cnt in result.all()
    ]


# ── Sync status ───────────────────────────────────────────────────────────────

@router.get("/sync/status", response_model=List[SyncStatusOut])
async def get_sync_status(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> List[SyncStatusOut]:
    result = await db.execute(select(CveSyncStatus).order_by(CveSyncStatus.source_name))
    rows = result.scalars().all()
    return [SyncStatusOut.model_validate(r) for r in rows]


# ── Trigger sync ──────────────────────────────────────────────────────────────

@router.post("/sync/{source}", response_model=SyncTriggerResponse)
async def trigger_sync(
    source: str,
    _: User = Depends(_require_admin),
) -> SyncTriggerResponse:
    if source not in _VALID_SOURCES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown source. Valid: {sorted(_VALID_SOURCES)}",
        )

    from app.worker.tasks import (
        sync_all_intel_task, sync_cisa_kev_task, sync_nvd_task, sync_osv_task,
    )

    task_map = {
        "nvd": sync_nvd_task,
        "cisa_kev": sync_cisa_kev_task,
        "osv": sync_osv_task,
        "all": sync_all_intel_task,
    }
    task_result = task_map[source].delay()

    return SyncTriggerResponse(
        task_id=task_result.id,
        source=source,
        message=f"Sync triggered for {source}",
    )


# ── Patch relevance ───────────────────────────────────────────────────────────

@router.patch("/vulnerabilities/{cve_id}", response_model=VulnerabilityOut)
async def patch_vulnerability_relevance(
    cve_id: str,
    body: RelevancePatch,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(_require_admin),
) -> VulnerabilityOut:
    valid_relevance = {r.value for r in VulnRelevance}
    if body.relevance not in valid_relevance:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid relevance. Valid: {sorted(valid_relevance)}",
        )

    result = await db.execute(
        select(CveVulnerability).where(CveVulnerability.cve_id == cve_id.upper())
    )
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="CVE not found")

    vuln.relevance = body.relevance
    vuln.relevance_manual = True
    if body.reason is not None:
        vuln.relevance_reason = body.reason
    await db.commit()

    return VulnerabilityOut(
        id=vuln.id,
        cve_id=vuln.cve_id,
        title=vuln.title,
        description=vuln.description,
        published_at=vuln.published_at,
        severity=vuln.severity,
        cvss_v3_score=vuln.cvss_v3_score,
        in_cisa_kev=vuln.in_cisa_kev,
        exploit_available=vuln.exploit_available,
        relevance=vuln.relevance,
        affected_product_count=0,
    )
