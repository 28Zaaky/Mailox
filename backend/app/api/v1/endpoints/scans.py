import asyncio
import csv
import io
import json
import re
import secrets
import time
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import RequirePermission, get_current_user, get_verified_org
from app.core.config import settings
from app.core.logging import get_logger
from app.core.redis_client import get_redis
from app.core.sse_manager import acquire_sse_slot, heartbeat_sse_slot, release_sse_slot
from app.db.session import get_db
from app.db.models.scan import ScanStatus, ScanFinding, Scan, ScanEngineRun
from app.db.models.user import User
from app.schemas.scan import (
    EngineRunResponse, ScanAssetsResponse, ScanCreate, ScanFindingResponse,
    ScanResponse, ScanWithFindingsResponse, MXRecord, WebmailHost, SMTPHost,
)
from app.services.scan_service import ScanService

_BATCH_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]{1,252}$")
_BATCH_MAX_DOMAINS = 50


class BatchScanItem(BaseModel):
    domain: str
    scan_id: Optional[str] = None
    status: str  # "queued" | "rejected"
    reason: Optional[str] = None


class BatchScanJsonBody(BaseModel):
    domains: List[str]
    profile_id: Optional[uuid.UUID] = None

router = APIRouter(prefix="/scans", tags=["scans"])
_batch_logger = get_logger("mailox.scans")

# Terminal states — SSE stream ends when reached (PARTIAL is terminal)
_TERMINAL = {ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.FAILED, ScanStatus.CANCELLED}


async def _get_user_for_sse(
    org_id: uuid.UUID,
    scan_id: uuid.UUID,
    sse_token: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Validate a short-lived SSE ticket (?sse_token=). Single-use, 60s TTL, stored in Redis."""
    from fastapi import HTTPException

    if not sse_token:
        raise HTTPException(status_code=401, detail="SSE ticket required",
                            headers={"WWW-Authenticate": "Bearer"})

    redis = get_redis()
    key = f"sse_ticket:{sse_token}"
    try:
        value = await redis.get(key)
    except Exception:
        raise HTTPException(status_code=503, detail="SSE auth service unavailable")

    if not value:
        raise HTTPException(status_code=401, detail="Invalid or expired SSE ticket",
                            headers={"WWW-Authenticate": "Bearer"})

    # Single-use: delete immediately after first read
    await redis.delete(key)

    # The shared Redis client uses decode_responses=True -> str; accept bytes too.
    if isinstance(value, bytes):
        try:
            value = value.decode()
        except UnicodeDecodeError:
            raise HTTPException(status_code=401, detail="Malformed SSE ticket")
    try:
        raw_user, raw_org, raw_scan = value.split("|")
        user_id = uuid.UUID(raw_user)
        ticket_org, ticket_scan = uuid.UUID(raw_org), uuid.UUID(raw_scan)
    except (ValueError, AttributeError):
        raise HTTPException(status_code=401, detail="Malformed SSE ticket")
    # Ticket is bound to the org/scan it was issued for.
    if ticket_org != org_id or ticket_scan != scan_id:
        raise HTTPException(status_code=401, detail="Invalid or expired SSE ticket",
                            headers={"WWW-Authenticate": "Bearer"})

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user


@router.post(
    "",
    response_model=ScanWithFindingsResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("assessment:write"))],
)
async def create_scan(
    org_id: uuid.UUID,
    body: ScanCreate,
    current_user: User = Depends(get_current_user),
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
    idempotency_key: Optional[str] = Header(
        None, alias="Idempotency-Key", max_length=128, pattern=r"^[A-Za-z0-9\-_]{1,128}$"
    ),
) -> ScanWithFindingsResponse:
    service = ScanService(db)
    scan = await service.create_and_run_scan(
        org_id=verified_org,
        target_domain=body.target_domain,
        created_by=current_user.id,
        idempotency_key=idempotency_key,
        project_id=body.project_id,
        profile_id=body.profile_id,
        # No platform-admin exemption: the worker re-checks domain ownership on
        # SaaS and has none, so an exempted scan was accepted then FAILED.
    )
    return _to_response_with_findings(scan)


@router.post(
    "/batch",
    response_model=List[BatchScanItem],
    status_code=status.HTTP_207_MULTI_STATUS,
    dependencies=[Depends(RequirePermission("assessment:write"))],
)
async def batch_scan_csv(
    org_id: uuid.UUID,
    file: UploadFile = File(...),
    profile_id: Optional[uuid.UUID] = Form(None),
    current_user: User = Depends(get_current_user),
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> List[BatchScanItem]:
    """Upload a CSV (one domain per line, or column header 'domain') to launch a batch of scans."""
    raw = await file.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 encoded")

    domains = _parse_domains_from_text(text)
    return await _run_batch(domains, profile_id, org_id, verified_org, current_user.id, db)


@router.post(
    "/batch/json",
    response_model=List[BatchScanItem],
    status_code=status.HTTP_207_MULTI_STATUS,
    dependencies=[Depends(RequirePermission("assessment:write"))],
)
async def batch_scan_json(
    org_id: uuid.UUID,
    body: BatchScanJsonBody,
    current_user: User = Depends(get_current_user),
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> List[BatchScanItem]:
    """Submit a JSON list of domains to launch a batch of scans."""
    domains = [d.strip() for d in body.domains if d.strip()]
    return await _run_batch(domains, body.profile_id, org_id, verified_org, current_user.id, db)


@router.get(
    "",
    response_model=List[ScanResponse],
    dependencies=[Depends(RequirePermission("assessment:read"))],
)
async def list_scans(
    org_id: uuid.UUID,
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0, le=100_000),
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> List[ScanResponse]:
    service = ScanService(db)
    pairs = await service.list_scans(org_id=verified_org, limit=limit, offset=offset)
    return [_to_response(s, count) for s, count in pairs]


# Static GET routes must be declared before "/{scan_id}" or they are shadowed (422).
@router.get(
    "/engine-stats",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("assessment:read"))],
)
async def get_engine_stats(
    org_id: uuid.UUID,
    engine: str = Query(..., max_length=50),
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
):
    """Return run stats for a specific engine across all scans for an org."""
    from sqlalchemy import func, desc

    result = await db.execute(
        select(
            func.count(ScanEngineRun.id).label("run_count"),
            func.sum(ScanEngineRun.finding_count).label("finding_total"),
            func.max(ScanEngineRun.finished_at).label("last_run_at"),
        )
        .join(Scan, ScanEngineRun.scan_id == Scan.id)
        .where(Scan.org_id == org_id)
        .where(ScanEngineRun.engine == engine)
        .where(ScanEngineRun.status == "completed")
    )
    row = result.one()

    last_status_result = await db.execute(
        select(ScanEngineRun.status, ScanEngineRun.finished_at)
        .join(Scan, ScanEngineRun.scan_id == Scan.id)
        .where(Scan.org_id == org_id)
        .where(ScanEngineRun.engine == engine)
        .order_by(desc(ScanEngineRun.finished_at))
        .limit(1)
    )
    last_row = last_status_result.one_or_none()

    return {
        "engine": engine,
        "run_count": row.run_count or 0,
        "finding_total": int(row.finding_total or 0),
        "last_run_at": row.last_run_at.isoformat() if row.last_run_at else None,
        "last_status": last_row.status if last_row else None,
    }


@router.get(
    "/{scan_id}",
    response_model=ScanWithFindingsResponse,
    dependencies=[Depends(RequirePermission("assessment:read"))],
)
async def get_scan(
    org_id: uuid.UUID,
    scan_id: uuid.UUID,
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> ScanWithFindingsResponse:
    service = ScanService(db)
    scan = await service.get_scan(scan_id=scan_id, org_id=verified_org)
    return _to_response_with_findings(scan)


@router.get(
    "/{scan_id}/findings",
    response_model=List[ScanFindingResponse],
    dependencies=[Depends(RequirePermission("assessment:read"))],
)
async def get_scan_findings(
    org_id: uuid.UUID,
    scan_id: uuid.UUID,
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> List[ScanFindingResponse]:
    service = ScanService(db)
    findings = await service.get_scan_findings(scan_id=scan_id, org_id=verified_org)
    return [ScanFindingResponse.model_validate(f) for f in findings]


@router.post(
    "/{scan_id}/cancel",
    response_model=ScanResponse,
    dependencies=[Depends(RequirePermission("assessment:write"))],
)
async def cancel_scan(
    org_id: uuid.UUID,
    scan_id: uuid.UUID,
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> ScanResponse:
    service = ScanService(db)
    scan = await service.cancel_scan(scan_id=scan_id, org_id=verified_org)
    return _to_response(scan)


@router.delete(
    "/{scan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(RequirePermission("assessment:write"))],
)
async def delete_scan(
    org_id: uuid.UUID,
    scan_id: uuid.UUID,
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> None:
    service = ScanService(db)
    await service.delete_scan(scan_id=scan_id, org_id=verified_org)


@router.get(
    "/{scan_id}/assets",
    response_model=ScanAssetsResponse,
    dependencies=[Depends(RequirePermission("assessment:read"))],
)
async def get_scan_assets(
    org_id: uuid.UUID,
    scan_id: uuid.UUID,
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> ScanAssetsResponse:
    scan_result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.org_id == verified_org)
    )
    if not scan_result.scalar_one_or_none():
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Not found")

    findings_result = await db.execute(
        select(ScanFinding).where(ScanFinding.scan_id == scan_id)
    )
    all_findings = findings_result.scalars().all()

    mx_records: list[MXRecord] = []
    webmail_hosts: list[WebmailHost] = []
    smtp_hosts: list[SMTPHost] = []

    seen_mx: set[str] = set()
    seen_smtp: set[str] = set()
    seen_wm: set[str] = set()

    for f in all_findings:
        ev = f.evidence or {}
        # evidence is stored as list of Evidence dicts — we need to handle both formats
        if isinstance(ev, list):
            ev_dict: dict = {}
            for item in ev:
                if isinstance(item, dict):
                    ev_dict.update(item.get("technical_details") or {})
                    if not ev_dict.get("observed_value"):
                        ev_dict["observed_value"] = item.get("observed_value", "")
            ev = ev_dict

        if f.engine == "dns_auth":
            if isinstance(ev.get("mx_records"), list):
                for mx in ev["mx_records"]:
                    if isinstance(mx, dict) and mx.get("hostname"):
                        key = mx["hostname"]
                        if key not in seen_mx:
                            seen_mx.add(key)
                            mx_records.append(MXRecord(
                                priority=int(mx.get("priority", 0)),
                                hostname=mx["hostname"],
                            ))
        elif f.engine == "smtp_discovery":
            host = ev.get("host") or ev.get("smtp_host") or f.affected_asset
            port = ev.get("port") or 25
            if host:
                key = f"{host}:{port}"
                if key not in seen_smtp:
                    seen_smtp.add(key)
                    smtp_hosts.append(SMTPHost(host=str(host), port=int(port)))
        elif f.engine == "webmail":
            host = ev.get("host") or ev.get("url") or f.affected_asset
            product = ev.get("product") or ev.get("technology") or "Unknown"
            version = ev.get("version")
            if host:
                key = str(host)
                if key not in seen_wm:
                    seen_wm.add(key)
                    webmail_hosts.append(WebmailHost(
                        host=str(host),
                        product=str(product),
                        version=str(version) if version else None,
                    ))

    return ScanAssetsResponse(
        mx_records=mx_records,
        webmail_hosts=webmail_hosts,
        smtp_hosts=smtp_hosts,
    )


@router.post(
    "/{scan_id}/stream-token",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("assessment:read"))],
)
async def create_stream_token(
    org_id: uuid.UUID,
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Issue a short-lived single-use SSE ticket. Avoids passing the access token in EventSource URLs."""
    from fastapi import HTTPException as _HTTPException
    scan_result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.org_id == verified_org)
    )
    if not scan_result.scalar_one_or_none():
        raise _HTTPException(status_code=404, detail="Not found")

    redis = get_redis()
    ticket = secrets.token_urlsafe(32)
    try:
        await redis.setex(f"sse_ticket:{ticket}", 60, f"{current_user.id}|{org_id}|{scan_id}")
    except Exception:
        raise _HTTPException(status_code=503, detail="SSE auth service unavailable")
    return {"sse_token": ticket}


@router.get(
    "/{scan_id}/stream",
    response_class=StreamingResponse,
)
async def scan_stream(
    org_id: uuid.UUID,
    scan_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(_get_user_for_sse),
    db: AsyncSession = Depends(get_db),
    last_event_id: Optional[str] = Header(None, alias="Last-Event-ID"),
) -> StreamingResponse:
    """
    SSE stream of scan progress updates.

    Auth: requires a short-lived SSE ticket (?sse_token=) issued by POST /stream-token.
    Connection limits are enforced via distributed Redis leases.
    """
    from fastapi import HTTPException as _HTTPException
    from app.db.models.organization import OrganizationMember, ROLE_PERMISSIONS

    # Verify org membership + permission (can't use RequirePermission dep with SSE ticket auth)
    if not current_user.sees_all_orgs:
        mem_result = await db.execute(
            select(OrganizationMember).where(
                OrganizationMember.user_id == current_user.id,
                OrganizationMember.org_id == org_id,
                OrganizationMember.is_active == True,
            )
        )
        membership = mem_result.scalar_one_or_none()
        if not membership:
            raise _HTTPException(status_code=404, detail="Not found")
        role_perms = ROLE_PERMISSIONS.get(membership.role, set())
        if "*" not in role_perms and "assessment:read" not in role_perms:
            raise _HTTPException(status_code=403, detail="Insufficient permissions")

    # Verify scan belongs to org
    scan_check = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.org_id == org_id)
    )
    if not scan_check.scalar_one_or_none():
        raise _HTTPException(status_code=404, detail="Not found")

    # Distributed slot acquisition
    conn_id, acquire_result = await acquire_sse_slot(str(org_id))
    if acquire_result == "org_limit":
        raise _HTTPException(status_code=429, detail="Too many SSE connections for this organization")
    if acquire_result == "global_limit":
        raise _HTTPException(status_code=429, detail="Too many SSE connections")
    if acquire_result == "redis_error":
        raise _HTTPException(status_code=503, detail="SSE service temporarily unavailable")

    async def _event_generator():
        from sqlalchemy.orm import selectinload
        from app.db.models.organization import Organization, OrganizationMember, ROLE_PERMISSIONS
        from app.db.session import AsyncSessionLocal

        event_seq = 0
        events_sent = 0
        skip_initial_sleep = last_event_id is not None
        last_reauth_time = time.monotonic()
        last_heartbeat_time = time.monotonic()

        try:
            while events_sent < settings.SSE_MAX_EVENTS:
                if await request.is_disconnected():
                    break

                if not skip_initial_sleep:
                    await asyncio.sleep(settings.SSE_POLL_INTERVAL)
                skip_initial_sleep = False

                now_monotonic = time.monotonic()

                # SSE lease heartbeat
                if now_monotonic - last_heartbeat_time >= settings.SSE_HEARTBEAT_INTERVAL_SECONDS:
                    last_heartbeat_time = now_monotonic
                    alive = await heartbeat_sse_slot(str(org_id), conn_id)
                    if not alive:
                        yield "event: error\ndata: {\"error\": \"connection_expired\"}\n\n"
                        break

                # Periodic full auth re-validation
                if now_monotonic - last_reauth_time >= settings.SSE_REAUTH_INTERVAL_SECONDS:
                    last_reauth_time = now_monotonic

                    try:
                        async with AsyncSessionLocal() as reauth_db:
                            from app.db.models.user import User as _User
                            u = (await reauth_db.execute(
                                select(_User).where(_User.id == current_user.id)
                            )).scalar_one_or_none()
                            if not u or not u.is_active:
                                yield "event: error\ndata: {\"error\": \"auth_expired\"}\n\n"
                                break

                            org = (await reauth_db.execute(
                                select(Organization).where(
                                    Organization.id == org_id,
                                    Organization.is_active == True,
                                )
                            )).scalar_one_or_none()
                            if not org:
                                yield "event: error\ndata: {\"error\": \"org_inactive\"}\n\n"
                                break

                            if not u.sees_all_orgs:
                                member = (await reauth_db.execute(
                                    select(OrganizationMember).where(
                                        OrganizationMember.user_id == current_user.id,
                                        OrganizationMember.org_id == org_id,
                                        OrganizationMember.is_active == True,
                                    )
                                )).scalar_one_or_none()
                                if not member:
                                    yield "event: error\ndata: {\"error\": \"auth_expired\"}\n\n"
                                    break
                                role_perms = ROLE_PERMISSIONS.get(member.role, set())
                                if "*" not in role_perms and "assessment:read" not in role_perms:
                                    yield "event: error\ndata: {\"error\": \"permission_revoked\"}\n\n"
                                    break
                    except Exception:
                        yield "event: error\ndata: {\"error\": \"auth_check_failed\"}\n\n"
                        break

                try:
                    async with AsyncSessionLocal() as db:
                        result = await db.execute(
                            select(Scan)
                            .options(selectinload(Scan.findings))
                            .where(Scan.id == scan_id, Scan.org_id == org_id)
                        )
                        scan = result.scalar_one_or_none()
                        if not scan:
                            payload = json.dumps({"error": "not_found"})
                            yield f"event: error\ndata: {payload}\n\n"
                            break

                        payload = json.dumps({
                            "id": str(scan.id),
                            "status": scan.status.value,
                            "progress_pct": scan.progress_pct,
                            "current_engine": scan.current_engine,
                            "finding_count": len(scan.findings) if scan.findings else 0,
                        })
                        is_terminal = scan.status in _TERMINAL
                except Exception:
                    yield "event: error\ndata: {\"error\": \"db_unavailable\"}\n\n"
                    break

                event_seq += 1
                events_sent += 1
                yield f"id: {event_seq}\nevent: scan_update\ndata: {payload}\n\n"

                if is_terminal:
                    yield "event: done\ndata: {}\n\n"
                    break
        finally:
            await release_sse_slot(str(org_id), conn_id)

    return StreamingResponse(
        _event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ── Helpers ───────────────────────────────────────────────────────────────────


def _parse_domains_from_text(text: str) -> List[str]:
    """Extract domains from plain text or CSV. Skips blank lines and comment lines."""
    domains: List[str] = []
    reader = csv.reader(io.StringIO(text))
    header_skipped = False
    for row in reader:
        if not row:
            continue
        cell = row[0].strip()
        if not cell or cell.startswith("#"):
            continue
        # Skip a header row whose first cell looks like a column name
        if not header_skipped and cell.lower() in ("domain", "domains", "hostname", "host", "target"):
            header_skipped = True
            continue
        header_skipped = True
        domains.append(cell)
    return domains


async def _run_batch(
    domains: List[str],
    profile_id: Optional[uuid.UUID],
    org_id: uuid.UUID,
    verified_org: uuid.UUID,
    user_id: uuid.UUID,
    db: AsyncSession,
) -> List[BatchScanItem]:
    if not domains:
        raise HTTPException(status_code=400, detail="No domains provided")

    # Quota guard
    if len(domains) > _BATCH_MAX_DOMAINS:
        raise HTTPException(
            status_code=400,
            detail=f"Too many domains: {len(domains)} submitted, max is {_BATCH_MAX_DOMAINS}",
        )

    service = ScanService(db)
    results: List[BatchScanItem] = []

    for raw_domain in domains:
        domain = raw_domain.strip().lower()
        if not domain:
            continue

        if not _BATCH_DOMAIN_RE.match(domain):
            results.append(BatchScanItem(
                domain=raw_domain,
                status="rejected",
                reason="Invalid domain format",
            ))
            continue

        try:
            scan = await service.create_and_run_scan(
                org_id=verified_org,
                target_domain=domain,
                created_by=user_id,
                idempotency_key=None,
                project_id=None,
                profile_id=profile_id,
            )
            results.append(BatchScanItem(
                domain=domain,
                scan_id=str(scan.id),
                status="queued",
            ))
        except HTTPException as exc:
            results.append(BatchScanItem(
                domain=domain,
                status="rejected",
                reason=str(exc.detail),
            ))
        except Exception as exc:
            # Never echo internal errors (SQL, broker host) to the client, and
            # reset the session so the next domains do not hit PendingRollback.
            _batch_logger.error("scan.batch.item_failed", domain=domain, error=type(exc).__name__)
            await db.rollback()
            results.append(BatchScanItem(
                domain=domain,
                status="rejected",
                reason="internal_error",
            ))

    return results


def _to_response(scan, finding_count: int = 0) -> ScanResponse:
    return ScanResponse(
        id=str(scan.id),
        org_id=str(scan.org_id),
        target_domain=scan.target_domain,
        status=scan.status,
        created_by=str(scan.created_by) if scan.created_by is not None else None,
        created_at=scan.created_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        error_msg=scan.error_msg,
        finding_count=finding_count,
        risk_score=scan.risk_score,
        progress_pct=scan.progress_pct if scan.progress_pct is not None else 0,
        current_engine=scan.current_engine,
        attempt_number=getattr(scan, "attempt_number", 0) or 0,
        project_id=scan.project_id,
    )


def _to_response_with_findings(scan) -> ScanWithFindingsResponse:
    engine_runs = []
    _engine_runs = scan.__dict__.get("engine_runs") or []
    if _engine_runs:
        engine_runs = [EngineRunResponse.model_validate(r) for r in _engine_runs]
    return ScanWithFindingsResponse(
        id=str(scan.id),
        org_id=str(scan.org_id),
        target_domain=scan.target_domain,
        status=scan.status,
        created_by=str(scan.created_by) if scan.created_by is not None else None,
        created_at=scan.created_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        error_msg=scan.error_msg,
        finding_count=len(scan.__dict__.get("findings") or []),
        progress_pct=scan.progress_pct if scan.progress_pct is not None else 0,
        current_engine=scan.current_engine,
        attempt_number=getattr(scan, "attempt_number", 0) or 0,
        project_id=scan.project_id,
        risk_score=scan.risk_score,
        findings=[ScanFindingResponse.model_validate(f) for f in (scan.__dict__.get("findings") or [])],
        engine_runs=engine_runs,
    )
