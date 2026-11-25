"""
Merge org-level OrgSettings overrides with global .env settings.

Usage:
    eff = await get_effective_settings(db, org_id)
    token = eff.github_token   # org override or global fallback
"""
import uuid
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings as global_settings
from app.db.models.org_settings import OrgSettings


class EffectiveSettings:
    """Merges org-level overrides with global .env settings."""

    def __init__(self, org_row: Optional[OrgSettings]) -> None:
        self._org = org_row

    def _decrypt(self, val: Optional[str]) -> Optional[str]:
        if not val:
            return None
        try:
            from app.core.encryption import decrypt_secret
            return decrypt_secret(val)
        except Exception:
            return None

    @property
    def github_token(self) -> Optional[str]:
        if self._org:
            v = self._decrypt(self._org.github_token_enc)
            if v:
                return v
        return getattr(global_settings, "GITHUB_TOKEN", None)

    @property
    def intelx_api_key(self) -> Optional[str]:
        if self._org:
            v = self._decrypt(self._org.intelx_api_key_enc)
            if v:
                return v
        return getattr(global_settings, "INTELX_API_KEY", None)

    @property
    def nvd_api_key(self) -> Optional[str]:
        if self._org:
            v = self._decrypt(self._org.nvd_api_key_enc)
            if v:
                return v
        return getattr(global_settings, "NVD_API_KEY", None)

    @property
    def canary_email(self) -> Optional[str]:
        if self._org and self._org.canary_email:
            return self._org.canary_email
        return getattr(global_settings, "CANARY_EMAIL", None)

    @property
    def cred_probe_enabled(self) -> bool:
        if self._org and self._org.cred_probe_enabled is not None:
            return self._org.cred_probe_enabled
        return getattr(global_settings, "CRED_PROBE_ENABLED", False)

    @property
    def scan_timeout(self) -> int:
        if self._org and self._org.scan_timeout_seconds:
            return self._org.scan_timeout_seconds
        return getattr(global_settings, "SCAN_TASK_TIMEOUT_SECONDS", 120)


async def get_effective_settings(db: AsyncSession, org_id: uuid.UUID) -> EffectiveSettings:
    result = await db.execute(
        select(OrgSettings).where(OrgSettings.org_id == org_id)
    )
    row = result.scalar_one_or_none()
    return EffectiveSettings(row)
