"""
Asset Registry & Scope API.

GET    /orgs/{org_id}/assets                           list org assets
GET    /orgs/{org_id}/assets/{asset_id}                get asset
POST   /orgs/{org_id}/projects/{project_id}/scope      add target to project scope
DELETE /orgs/{org_id}/projects/{project_id}/scope/{asset_id}  remove
GET    /orgs/{org_id}/projects/{project_id}/scope      list project scope
GET    /orgs/{org_id}/scans/{scan_id}/scope            scope snapshot
"""
import uuid
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import RequirePermission, get_current_user, get_verified_org
from app.db.models.asset import Asset, ProjectAsset, ScopeSnapshot
from app.db.models.project import Project
from app.db.models.scan import Scan
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.asset import (
    AddScopeTargetRequest,
    AssetResponse,
    ProjectAssetResponse,
    ScopeSnapshotResponse,
)

router = APIRouter(tags=["assets"])


# ── Org-level asset registry ──────────────────────────────────────────────────


@router.get("/assets", response_model=List[AssetResponse])
async def list_assets(
    org_id: uuid.UUID,
    asset_type: str | None = None,
    db: AsyncSession = Depends(get_db),
    _: object = Depends(RequirePermission("assessment:read")),
    org=Depends(get_verified_org),
):
    q = select(Asset).where(Asset.org_id == org_id)
    if asset_type:
        q = q.where(Asset.asset_type == asset_type)
    q = q.order_by(Asset.last_seen_at.desc())
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/assets/{asset_id}", response_model=AssetResponse)
async def get_asset(
    org_id: uuid.UUID,
    asset_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: object = Depends(RequirePermission("assessment:read")),
    org=Depends(get_verified_org),
):
    result = await db.execute(
        select(Asset).where(Asset.id == asset_id, Asset.org_id == org_id)
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return asset


# ── Project scope ─────────────────────────────────────────────────────────────


async def _get_project_or_404(db: AsyncSession, org_id: uuid.UUID, project_id: uuid.UUID) -> Project:
    result = await db.execute(
        select(Project).where(Project.id == project_id, Project.org_id == org_id)
    )
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return project


@router.get("/projects/{project_id}/scope", response_model=List[ProjectAssetResponse])
async def list_project_scope(
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: object = Depends(RequirePermission("project:read")),
    org=Depends(get_verified_org),
):
    await _get_project_or_404(db, org_id, project_id)
    result = await db.execute(
        select(ProjectAsset)
        .options(selectinload(ProjectAsset.asset))
        .where(ProjectAsset.project_id == project_id)
    )
    return result.scalars().all()


@router.post("/projects/{project_id}/scope", response_model=ProjectAssetResponse, status_code=status.HTTP_201_CREATED)
async def add_scope_target(
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    body: AddScopeTargetRequest,
    db: AsyncSession = Depends(get_db),
    _: object = Depends(RequirePermission("project:write")),
    current_user: User = Depends(get_current_user),
    org=Depends(get_verified_org),
):
    await _get_project_or_404(db, org_id, project_id)
    now = datetime.now(timezone.utc)

    # Upsert asset
    existing = await db.execute(
        select(Asset).where(
            Asset.org_id == org_id,
            Asset.asset_type == body.asset_type,
            Asset.value == body.value,
        )
    )
    asset = existing.scalar_one_or_none()
    if not asset:
        asset = Asset(
            id=uuid.uuid4(),
            org_id=org_id,
            asset_type=body.asset_type,
            value=body.value,
            asset_metadata={},
            first_seen_at=now,
            last_seen_at=now,
        )
        db.add(asset)
        await db.flush()
    else:
        asset.last_seen_at = now

    # Check existing link
    link_result = await db.execute(
        select(ProjectAsset).where(
            ProjectAsset.project_id == project_id,
            ProjectAsset.asset_id == asset.id,
        )
    )
    link = link_result.scalar_one_or_none()
    if link:
        link.authorized = body.authorized
        link.authorized_by = current_user.id
        link.authorized_at = now
    else:
        link = ProjectAsset(
            project_id=project_id,
            asset_id=asset.id,
            authorized=body.authorized,
            authorized_by=current_user.id,
            authorized_at=now,
        )
        db.add(link)

    await db.commit()
    await db.refresh(link)
    await db.refresh(asset)
    link.asset = asset
    return link


@router.delete("/projects/{project_id}/scope/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_scope_target(
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    asset_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: object = Depends(RequirePermission("project:write")),
    org=Depends(get_verified_org),
):
    await _get_project_or_404(db, org_id, project_id)
    result = await db.execute(
        select(ProjectAsset).where(
            ProjectAsset.project_id == project_id,
            ProjectAsset.asset_id == asset_id,
        )
    )
    link = result.scalar_one_or_none()
    if not link:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    await db.delete(link)
    await db.commit()


# ── Scope snapshot ────────────────────────────────────────────────────────────


@router.get("/scans/{scan_id}/scope", response_model=ScopeSnapshotResponse)
async def get_scope_snapshot(
    org_id: uuid.UUID,
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: object = Depends(RequirePermission("assessment:read")),
    org=Depends(get_verified_org),
):
    # Verify scan belongs to org
    scan_result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.org_id == org_id)
    )
    if not scan_result.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    result = await db.execute(
        select(ScopeSnapshot).where(ScopeSnapshot.scan_id == scan_id)
    )
    snapshot = result.scalar_one_or_none()
    if not snapshot:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No scope snapshot for this scan")
    return snapshot
