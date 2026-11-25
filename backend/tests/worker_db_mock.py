"""
Statement-aware AsyncSession.execute() fake for _run_scan unit tests.

The worker issues dozens of queries whose order changes every time an engine
or a pre-flight step (SaaS gate, scope snapshot, org config, profile) is added.
Positional side_effect lists broke on each such change, so this fake answers
by inspecting the SQLAlchemy statement instead:

  UPDATE ... RETURNING attempt_number, ...   lease acquisition  -> lease_row
  UPDATE ... RETURNING id                     final guarded write -> final
  SELECT scans.id                             lease check         -> (lease id,) / None
  SELECT cancel_requested, status             cancel checkpoint   -> cancel_row
  SELECT project_id, org_id                   scan meta           -> (None, org_id)
  SELECT pentest_config, offensive_allowed    org config          -> ({}, offensive_allowed)
                                                                   (False by default: offensive
                                                                   modules stay off in unit tests)
  SELECT profile_id / AssessmentProfile       scan profile        -> profile limited to `engines`
                                                                   (the engines the tests patch, so
                                                                   nothing touches the network)
  SaaS gate (settings.IS_SAAS, the default edition):
    SELECT scans.org_id                       scan org            -> org_id
    SELECT organization_members.id            active member       -> a member id
    SELECT organizations.is_active            org active          -> True
    SELECT verified_domains                   ownership proof     -> one verified record
                                                                   covering the target
  (saas_gate_ok=False answers "org deactivated" so the gate blocks the scan)
  anything else                               no-op result
"""
import types
import uuid
from datetime import datetime, timezone
from contextlib import ExitStack, contextmanager
from unittest.mock import AsyncMock, MagicMock, patch

from sqlalchemy.sql.dml import Update
from sqlalchemy.sql.selectable import Select

from app.db.models.scan import ScanStatus


def make_result(fetchone=None):
    r = MagicMock()
    r.fetchone = MagicMock(return_value=fetchone)
    r.scalar_one_or_none = MagicMock(return_value=None)
    r.scalar_one = MagicMock(return_value=None)
    r.scalar = MagicMock(return_value=None)
    r.one_or_none = MagicMock(return_value=None)
    r.first = MagicMock(return_value=None)
    r.all = MagicMock(return_value=[])
    r.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
    r.rowcount = 0
    return r


def _names(cols):
    return [getattr(c, "name", None) for c in cols]


def make_worker_execute(
    *,
    lease_row=(1, False, "example.com"),
    lease_valid=True,
    cancel_row=(False, ScanStatus.RUNNING),
    final=None,
    engines=("dns_auth", "smtp_discovery", "webmail", "vuln_intel"),
    offensive_allowed=False,
    saas_gate_ok=True,
):
    """
    Returns an async side_effect for db.execute.

    final: MagicMock result returned by the guarded final UPDATE ... RETURNING
           (default: a row, i.e. lease still held), or an Exception instance to
           raise at that point.
    """
    org_id = uuid.uuid4()
    profile_id = uuid.uuid4()
    profile = types.SimpleNamespace(id=profile_id, engines=list(engines), time_limit_seconds=None)
    if final is None:
        final = make_result((uuid.uuid4(),))
    calls = []

    async def _execute(stmt, *args, **kwargs):
        calls.append(stmt)
        if isinstance(stmt, Update):
            returning = _names(getattr(stmt, "_returning", ()) or ())
            if "attempt_number" in returning:
                return make_result(lease_row)
            if returning == ["id"]:
                if isinstance(final, BaseException):
                    raise final
                return final
            return make_result(None)
        if isinstance(stmt, Select):
            cols = _names(stmt.selected_columns)
            sql = str(stmt)
            # ── SaaS gate (org active, active member, verified domain) ──
            if cols == ["org_id"] and "FROM scans" in sql:
                r = make_result((org_id,))
                r.scalar_one.return_value = org_id
                r.scalar_one_or_none.return_value = org_id
                return r
            if cols == ["id"] and "organization_members" in sql:
                r = make_result(None)
                r.scalar_one_or_none.return_value = uuid.uuid4() if saas_gate_ok else None
                return r
            if cols == ["is_active"] and "FROM organizations" in sql:
                r = make_result((saas_gate_ok,))
                r.scalar_one_or_none.return_value = saas_gate_ok
                return r
            if "FROM verified_domains" in sql:
                now = datetime.now(timezone.utc)
                record = types.SimpleNamespace(
                    domain=lease_row[2] if lease_row else "example.com",
                    token="test-token", verified_at=now, last_checked_at=now,
                )
                r = make_result(None)
                r.scalars.return_value = [record] if saas_gate_ok else []
                return r
            if cols == ["id"] and "worker_lease_id" in str(stmt):
                return make_result(("lease-id",) if lease_valid else None)
            if cols == ["cancel_requested", "status"]:
                return make_result(cancel_row)
            if cols == ["project_id", "org_id"]:
                return make_result((None, org_id))
            if cols == ["pentest_config", "offensive_modules_allowed"]:
                row = ({}, offensive_allowed)
                r = make_result(row)
                r.one_or_none.return_value = row
                r.first.return_value = row
                return r
            if cols and cols[0] == "profile_id":
                row = (profile_id,) + (None,) * (len(cols) - 1)
                r = make_result(row)
                r.one_or_none.return_value = row
                r.first.return_value = row
                r.scalar_one_or_none.return_value = profile_id
                return r
            if "assessment_profiles" in str(stmt):
                r = make_result(None)
                r.scalar_one_or_none.return_value = profile
                return r
        return make_result(None)

    _execute.calls = calls
    return _execute


# Engines _run_scan runs regardless of the profile (offensive / always-on
# passive modules). Unit tests stub them so _run_scan never hits the network.
_AUX_ENGINES = (
    "app.engines.smtp_security.SMTPSecurityEngine",
    "app.engines.secrets.SecretsEngine",
    "app.engines.web_security.WebSecurityEngine",
    "app.engines.active_probes.ActiveProbesEngine",
    "app.engines.canary_probes.CanaryProbesEngine",
    "app.engines.credential_probes.CredentialProbesEngine",
    "app.engines.web_pentest.WebPentestEngine",
)


@contextmanager
def stub_aux_engines():
    with ExitStack() as stack:
        for target in _AUX_ENGINES:
            mock_cls = stack.enter_context(patch(target))
            empty = MagicMock(findings=[], success=True, error=None, metadata={})
            mock_cls.return_value.run = AsyncMock(return_value=empty)
            mock_cls.return_value.run_from_findings = AsyncMock(return_value=empty)
        yield
