"""
Secrets API — Module 07: file upload endpoint + findings management.

POST /secrets/scan   — upload file/archive, scan for SMTP credentials
GET  /secrets        — list findings for the org
GET  /secrets/{id}   — get single finding
PATCH /secrets/{id}/status — update triage status
"""
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import RequirePermission, get_current_user, get_verified_org
from app.core.config import settings
from app.db.models.secrets import (
    ExposedSecret, ExposedSecretStatus, SecretSourceType, SecretType,
)
from app.db.models.user import User
from app.db.session import get_db
from app.engines.secrets import SecretsEngine
from app.schemas.phase4 import (
    ExposedSecretOut, SecretListResponse, SecretScanResponse, SecretStatusUpdate,
)

router = APIRouter(prefix="/secrets", tags=["secrets"])

_ARCHIVE_EXTENSIONS = {".zip"}
_MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB hard cap on upload


@router.post(
    "/scan",
    response_model=SecretScanResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("assessment:write"))],
)
async def scan_file_for_secrets(
    org_id: uuid.UUID,
    file: UploadFile = File(...),
    scan_id: Optional[uuid.UUID] = Query(default=None),
    current_user: User = Depends(get_current_user),
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> SecretScanResponse:
    """
    Upload a file or ZIP archive and scan it for exposed SMTP credentials.
    Secrets are never stored in plaintext — only masked values are persisted.
    """
    if file.size and file.size > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File too large. Maximum upload size is {_MAX_UPLOAD_BYTES // 1024 // 1024} MB.",
        )

    content = await file.read()
    if len(content) > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File too large after read.",
        )

    filename = file.filename or "upload"
    engine = SecretsEngine()
    warnings: list[str] = []

    ext = _file_ext(filename)
    if ext in _ARCHIVE_EXTENSIONS:
        hits = engine.scan_archive(
            content,
            filename,
            max_archive_mb=settings.SECRET_SCAN_MAX_ARCHIVE_SIZE_MB,
            max_files=settings.SECRET_SCAN_MAX_FILES,
            max_file_mb=settings.SECRET_SCAN_MAX_FILE_SIZE_MB,
        )
        files_scanned = len({h.source_path for h in hits}) if hits else 0
        if not hits:
            warnings.append(f"No text files with recognized extensions found in archive '{filename}'.")
    else:
        hits = engine.scan_bytes(content, filename, settings.SECRET_SCAN_MAX_FILE_SIZE_MB)
        files_scanned = 1 if hits else 0

    # Persist findings (masked only) and return
    persisted: list[ExposedSecret] = []
    for hit in hits:
        secret_type = _map_secret_type(hit.secret_type)
        source_type = _map_source_type(filename)
        row = ExposedSecret(
            id=uuid.uuid4(),
            org_id=org_id,
            scan_id=scan_id,
            created_by=current_user.id,
            source_type=source_type,
            source_name=filename,
            source_path=hit.source_path,
            secret_type=secret_type,
            masked_value=hit.masked_value,
            risk_level=hit.risk,
            confidence=hit.confidence,
            line_number=hit.line_number,
            context_snippet=hit.context_snippet,
            detection_rule=hit.rule_id,
            status=ExposedSecretStatus.OPEN,
        )
        db.add(row)
        persisted.append(row)

    if persisted:
        await db.commit()
        for row in persisted:
            await db.refresh(row)

    return SecretScanResponse(
        total_hits=len(persisted),
        files_scanned=files_scanned,
        secrets=[ExposedSecretOut.model_validate(row) for row in persisted],
        warnings=warnings,
    )


@router.get(
    "",
    response_model=SecretListResponse,
    dependencies=[Depends(RequirePermission("assessment:read"))],
)
async def list_secrets(
    org_id: uuid.UUID,
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    secret_type: Optional[SecretType] = Query(default=None),
    secret_status: Optional[ExposedSecretStatus] = Query(default=None),
) -> SecretListResponse:
    """List exposed secrets for the organization (paginated)."""
    base_q = select(ExposedSecret).where(ExposedSecret.org_id == org_id)
    if secret_type:
        base_q = base_q.where(ExposedSecret.secret_type == secret_type)
    if secret_status:
        base_q = base_q.where(ExposedSecret.status == secret_status)

    count_q = select(func.count()).select_from(base_q.subquery())
    total_result = await db.execute(count_q)
    total = total_result.scalar_one()

    rows_q = (
        base_q
        .order_by(ExposedSecret.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    rows_result = await db.execute(rows_q)
    rows = rows_result.scalars().all()

    return SecretListResponse(
        items=[ExposedSecretOut.model_validate(r) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/{secret_id}",
    response_model=ExposedSecretOut,
    dependencies=[Depends(RequirePermission("assessment:read"))],
)
async def get_secret(
    org_id: uuid.UUID,
    secret_id: uuid.UUID,
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> ExposedSecretOut:
    result = await db.execute(
        select(ExposedSecret).where(
            ExposedSecret.id == secret_id,
            ExposedSecret.org_id == org_id,
        )
    )
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret finding not found.")
    return ExposedSecretOut.model_validate(row)


@router.patch(
    "/{secret_id}/status",
    response_model=ExposedSecretOut,
    dependencies=[Depends(RequirePermission("assessment:write"))],
)
async def update_secret_status(
    org_id: uuid.UUID,
    secret_id: uuid.UUID,
    body: SecretStatusUpdate,
    verified_org: uuid.UUID = Depends(get_verified_org),
    db: AsyncSession = Depends(get_db),
) -> ExposedSecretOut:
    """Triage a secret finding: mark as confirmed, false_positive, or remediated."""
    result = await db.execute(
        select(ExposedSecret).where(
            ExposedSecret.id == secret_id,
            ExposedSecret.org_id == org_id,
        )
    )
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret finding not found.")

    row.status = body.status
    await db.commit()
    await db.refresh(row)
    return ExposedSecretOut.model_validate(row)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _file_ext(filename: str) -> str:
    import os
    return os.path.splitext(filename.lower())[1]


def _map_secret_type(secret_type_str: str) -> SecretType:
    try:
        return SecretType(secret_type_str)
    except ValueError:
        return SecretType.GENERIC_PASSWORD


def _map_source_type(filename: str) -> SecretSourceType:
    fn = filename.lower()
    if fn.endswith(".env") or ".env." in fn:
        return SecretSourceType.ENV_FILE
    if any(fn.endswith(ext) for ext in (".zip", ".tar", ".gz", ".7z", ".rar")):
        return SecretSourceType.ARCHIVE
    if fn.endswith((".log",)):
        return SecretSourceType.LOG_FILE
    if fn.endswith((".bak", ".backup", ".sql")):
        return SecretSourceType.BACKUP
    if fn.endswith((".py", ".rb", ".php", ".js", ".ts", ".go", ".java", ".cs")):
        return SecretSourceType.SOURCE_CODE
    return SecretSourceType.CONFIG_FILE
