"""Domain ownership proof (DNS TXT) for the SaaS edition.

An organization adds a domain and gets a token. It publishes
    <domain>  TXT  "mailox-verify=<token>"
and asks for a check. Once verified, the domain and all its subdomains may be scanned.
"""
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import dns.asyncresolver
import dns.exception
import dns.resolver
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.models.access import VerifiedDomain

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$")


def normalize_domain(value: str) -> str:
    d = value.strip().lower().rstrip(".")
    for prefix in ("https://", "http://"):
        if d.startswith(prefix):
            d = d[len(prefix):]
    d = d.split("/")[0].split(":")[0]
    try:
        d = d.encode("idna").decode()
    except UnicodeError:
        pass
    if not _DOMAIN_RE.match(d):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid domain name")
    return d


def covers(verified: str, target: str) -> bool:
    return target == verified or target.endswith("." + verified)


async def _txt_values(domain: str) -> list[str]:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 8.0
    try:
        answer = await resolver.resolve(domain, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    return ["".join(s.decode(errors="replace") for s in r.strings) for r in answer]


class DomainVerificationService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def list_domains(self, org_id: uuid.UUID) -> list[VerifiedDomain]:
        q = select(VerifiedDomain).where(VerifiedDomain.org_id == org_id).order_by(VerifiedDomain.domain)
        return list((await self.db.execute(q)).scalars())

    async def add(self, org_id: uuid.UUID, domain: str, user_id: uuid.UUID) -> VerifiedDomain:
        domain = normalize_domain(domain)
        existing = (await self.db.execute(
            select(VerifiedDomain).where(VerifiedDomain.org_id == org_id, VerifiedDomain.domain == domain)
        )).scalar_one_or_none()
        if existing:
            return existing
        record = VerifiedDomain(org_id=org_id, domain=domain, token=secrets.token_hex(16), created_by=user_id)
        self.db.add(record)
        await self.db.flush()
        return record

    async def _get(self, org_id: uuid.UUID, domain_id: uuid.UUID) -> VerifiedDomain:
        record = await self.db.get(VerifiedDomain, domain_id)
        if record is None or record.org_id != org_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
        return record

    async def verify(self, org_id: uuid.UUID, domain_id: uuid.UUID) -> tuple[VerifiedDomain, list[str]]:
        """Look the TXT record up now. Returns the record and the TXT values seen."""
        record = await self._get(org_id, domain_id)
        values = await _txt_values(record.domain)
        expected = settings.DOMAIN_VERIFY_PREFIX + record.token
        record.last_checked_at = datetime.now(timezone.utc)
        if any(v.strip() == expected for v in values):
            record.verified_at = record.verified_at or record.last_checked_at
        return record, values

    async def remove(self, org_id: uuid.UUID, domain_id: uuid.UUID) -> None:
        record = await self._get(org_id, domain_id)
        await self.db.delete(record)

    async def verified_parent(self, org_id: uuid.UUID, target: str) -> Optional[VerifiedDomain]:
        """Verified domain of the org that covers ``target``, or None.

        A proof is not permanent: when the last check is older than
        DOMAIN_VERIFY_RECHECK_DAYS the TXT record is read again, and a domain whose
        record is gone (removed, or the domain changed hands) loses its verification.
        """
        target = target.strip().lower().rstrip(".")
        rows = (await self.db.execute(
            select(VerifiedDomain).where(VerifiedDomain.org_id == org_id, VerifiedDomain.verified_at.is_not(None))
        )).scalars()
        record = next((r for r in rows if covers(r.domain, target)), None)
        if record is None:
            return None
        now = datetime.now(timezone.utc)
        last = record.last_checked_at or record.verified_at
        if last and now - last > timedelta(days=settings.DOMAIN_VERIFY_RECHECK_DAYS):
            values = await _txt_values(record.domain)
            record.last_checked_at = now
            # flush, not commit: the caller may hold the quota row lock in this transaction
            if not any(v.strip() == settings.DOMAIN_VERIFY_PREFIX + record.token for v in values):
                record.verified_at = None
                await self.db.flush()
                return None
            await self.db.flush()
        return record
