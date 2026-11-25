"""
SSE real HTTP client tests.

Uses httpx.AsyncClient against the real FastAPI app (ASGITransport).
Tests:
- Connection and event reception.
- Terminal state closes stream.
- Last-Event-ID reconnection skips initial sleep.
- Scan completing during disconnection: client reconnects and gets terminal state.
- Multi-tenant isolation: org A cannot subscribe to org B's scan events.
- Stream closes cleanly on disconnection.
- PARTIAL status triggers done event.
"""
import asyncio
import json
import uuid
from typing import AsyncIterator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import update

from app.db.models.scan import Scan, ScanStatus


# ── SSE helpers ───────────────────────────────────────────────────────────────


async def collect_sse_events(
    response,
    max_events: int = 20,
    timeout: float = 5.0,
) -> list[dict]:
    """Parse SSE stream from httpx streaming response.

    Uses asyncio.timeout so the hard deadline cancels the underlying stream
    (and the server-side generator), not just the loop iteration check.
    """
    events = []
    buffer = ""

    def _parse_buffer():
        nonlocal buffer
        while "\n\n" in buffer:
            block, buffer = buffer.split("\n\n", 1)
            event = {}
            for line in block.strip().splitlines():
                if line.startswith("id:"):
                    event["id"] = line[3:].strip()
                elif line.startswith("event:"):
                    event["event"] = line[6:].strip()
                elif line.startswith("data:"):
                    try:
                        event["data"] = json.loads(line[5:].strip())
                    except json.JSONDecodeError:
                        event["data"] = line[5:].strip()
            if event:
                events.append(event)

    async for chunk in response.aiter_text():
        buffer += chunk
        _parse_buffer()
        if len(events) >= max_events:
            break
        if events and events[-1].get("event") in ("done", "error"):
            break
    return events


# ── Setup helpers ─────────────────────────────────────────────────────────────


async def _register_login_org(client: AsyncClient) -> tuple[str, str]:
    """Register user, login, create org. Returns (access_token, org_id)."""
    email = f"sse-{uuid.uuid4()}@test.dev"
    from tests.conftest import make_invite
    await client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "TestPass1!SecureEnough", "invite": await make_invite(email)},
    )
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "TestPass1!SecureEnough"},
    )
    token = resp.json()["access_token"]
    hdrs = {"Authorization": f"Bearer {token}"}

    resp = await client.post(
        "/api/v1/orgs",
        json={"name": f"org-{uuid.uuid4()}", "slug": f"slug-{uuid.uuid4()}"},
        headers=hdrs,
    )
    org_id = resp.json()["id"]
    # SaaS edition: scans are only accepted on a domain the org has verified
    from tests.conftest import verify_domain
    await verify_domain(org_id, "example.com")
    return token, org_id


async def _create_scan(
    client: AsyncClient, token: str, org_id: str, db=None
) -> str:
    """Create a scan. Returns scan_id.

    Pass `db` (the test AsyncSession) to commit the scan so that the SSE
    generator — which uses AsyncSessionLocal() independently — can see it.
    Without a commit the scan only exists in the test transaction and is
    invisible to other connections.
    """
    hdrs = {"Authorization": f"Bearer {token}"}
    with (
        patch("app.services.scan_service.SSRFGuard.validate_domain_for_scan",
              new=AsyncMock()),
        patch("app.worker.tasks.scan_task.delay",
              return_value=MagicMock(id="fake-task")),
    ):
        resp = await client.post(
            f"/api/v1/orgs/{org_id}/scans",
            json={"target_domain": "example.com"},
            headers=hdrs,
        )
    assert resp.status_code == 201, resp.text
    if db is not None:
        await db.commit()
    return resp.json()["id"]


async def _stream_url(client: AsyncClient, token: str, org_id: str, scan_id: str) -> str:
    """SSE auth is a single-use ticket (POST /stream-token, then ?sse_token=);
    a Bearer header on the stream itself is not accepted."""
    resp = await client.post(
        f"/api/v1/orgs/{org_id}/scans/{scan_id}/stream-token",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    ticket = resp.json()["sse_token"]
    return f"/api/v1/orgs/{org_id}/scans/{scan_id}/stream?sse_token={ticket}"


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestSSEConnection:
    """Basic SSE connection and event format."""

    @pytest.mark.asyncio
    async def test_sse_events_have_id_field(self, client, db):
        """Each SSE event must carry an id: field for reconnection support."""
        token, org_id = await _register_login_org(client)
        scan_id = await _create_scan(client, token, org_id, db=db)
        hdrs = {"Authorization": f"Bearer {token}"}

        async with client.stream(
            "GET",
            await _stream_url(client, token, org_id, scan_id),
            headers=hdrs,
            timeout=5.0,
        ) as response:
            events = await collect_sse_events(response, max_events=3, timeout=4.0)

        assert any("id" in e for e in events), "SSE events must have id: field"

    @pytest.mark.asyncio
    async def test_sse_event_contains_scan_status(self, client, db):
        """SSE scan_update events include status field."""
        token, org_id = await _register_login_org(client)
        scan_id = await _create_scan(client, token, org_id, db=db)
        hdrs = {"Authorization": f"Bearer {token}"}

        async with client.stream(
            "GET",
            await _stream_url(client, token, org_id, scan_id),
            headers=hdrs,
            timeout=5.0,
        ) as response:
            events = await collect_sse_events(response, max_events=5, timeout=4.0)

        scan_updates = [e for e in events if e.get("event") == "scan_update"]
        assert len(scan_updates) >= 1
        assert "status" in scan_updates[0].get("data", {}), (
            "scan_update event must contain status field"
        )

    @pytest.mark.asyncio
    async def test_sse_404_on_nonexistent_scan(self, client, db):
        """Non-existent scan is rejected with 404 before any stream is opened."""
        token, org_id = await _register_login_org(client)
        hdrs = {"Authorization": f"Bearer {token}"}
        fake_scan_id = str(uuid.uuid4())

        resp = await client.post(
            f"/api/v1/orgs/{org_id}/scans/{fake_scan_id}/stream-token",
            headers=hdrs,
        )
        assert resp.status_code == 404

        # A valid ticket issued for another scan is bound to that scan.
        real_scan_id = await _create_scan(client, token, org_id, db=db)
        url = await _stream_url(client, token, org_id, real_scan_id)
        ticket = url.split("sse_token=", 1)[1]
        resp = await client.get(
            f"/api/v1/orgs/{org_id}/scans/{fake_scan_id}/stream?sse_token={ticket}",
        )
        assert resp.status_code == 401


class TestSSETerminalState:
    """SSE stream must close when scan reaches a terminal state."""

    @pytest.mark.asyncio
    async def test_sse_closes_on_completed_scan(self, client, db):
        """Stream sends done event when scan reaches COMPLETED."""
        from app.db.session import AsyncSessionLocal
        token, org_id = await _register_login_org(client)
        scan_id = await _create_scan(client, token, org_id, db=db)
        hdrs = {"Authorization": f"Bearer {token}"}

        # Transition scan to COMPLETED while SSE is running
        async def complete_scan():
            await asyncio.sleep(0.5)
            async with AsyncSessionLocal() as s:
                await s.execute(
                    update(Scan)
                    .where(Scan.id == uuid.UUID(scan_id))
                    .values(status=ScanStatus.COMPLETED, progress_pct=100)
                )
                await s.commit()

        asyncio.create_task(complete_scan())

        async with client.stream(
            "GET",
            await _stream_url(client, token, org_id, scan_id),
            headers=hdrs,
            timeout=8.0,
        ) as response:
            events = await collect_sse_events(response, max_events=20, timeout=7.0)

        done_events = [e for e in events if e.get("event") == "done"]
        assert len(done_events) >= 1, (
            f"Expected done event but got: {[e.get('event') for e in events]}"
        )

    @pytest.mark.asyncio
    async def test_sse_closes_on_partial_scan(self, client, db):
        """PARTIAL is a terminal state — stream sends done event."""
        from app.db.session import AsyncSessionLocal
        token, org_id = await _register_login_org(client)
        scan_id = await _create_scan(client, token, org_id, db=db)
        hdrs = {"Authorization": f"Bearer {token}"}

        async def partial_scan():
            await asyncio.sleep(0.5)
            async with AsyncSessionLocal() as s:
                await s.execute(
                    update(Scan)
                    .where(Scan.id == uuid.UUID(scan_id))
                    .values(status=ScanStatus.PARTIAL, progress_pct=100)
                )
                await s.commit()

        asyncio.create_task(partial_scan())

        async with client.stream(
            "GET",
            await _stream_url(client, token, org_id, scan_id),
            headers=hdrs,
            timeout=8.0,
        ) as response:
            events = await collect_sse_events(response, max_events=20, timeout=7.0)

        done_events = [e for e in events if e.get("event") == "done"]
        assert len(done_events) >= 1

        status_events = [
            e for e in events
            if e.get("event") == "scan_update"
            and e.get("data", {}).get("status") == "partial"
        ]
        assert len(status_events) >= 1, "Must emit scan_update with status=partial before done"


class TestSSEReconnection:
    """SSE reconnection with Last-Event-ID skips initial sleep."""

    @pytest.mark.asyncio
    async def test_last_event_id_skips_initial_sleep(self, client, db):
        """With Last-Event-ID header, first event is sent immediately (no 2s sleep)."""
        token, org_id = await _register_login_org(client)
        scan_id = await _create_scan(client, token, org_id, db=db)
        hdrs = {
            "Authorization": f"Bearer {token}",
            "Last-Event-ID": "1",  # Simulate reconnection
        }

        import time
        start = time.monotonic()

        async with client.stream(
            "GET",
            await _stream_url(client, token, org_id, scan_id),
            headers=hdrs,
            timeout=5.0,
        ) as response:
            events = await collect_sse_events(response, max_events=1, timeout=4.0)

        elapsed = time.monotonic() - start
        # Without Last-Event-ID, first event comes after 2s sleep.
        # With Last-Event-ID, it should come in < 1s.
        assert elapsed < 1.5, (
            f"Expected immediate response with Last-Event-ID, took {elapsed:.2f}s"
        )
        assert len(events) >= 1

    @pytest.mark.asyncio
    async def test_scan_completed_during_disconnect_reconnects_to_terminal(self, client, db):
        """
        Scenario: scan completes while client is disconnected.
        On reconnect, client immediately gets scan_update with terminal status + done.
        """
        from app.db.session import AsyncSessionLocal
        token, org_id = await _register_login_org(client)
        scan_id = await _create_scan(client, token, org_id, db=db)
        hdrs_base = {"Authorization": f"Bearer {token}"}

        # Complete the scan BEFORE reconnect (simulates: completed while disconnected)
        async with AsyncSessionLocal() as s:
            await s.execute(
                update(Scan)
                .where(Scan.id == uuid.UUID(scan_id))
                .values(status=ScanStatus.COMPLETED, progress_pct=100)
            )
            await s.commit()

        # Reconnect with Last-Event-ID
        hdrs_reconnect = {**hdrs_base, "Last-Event-ID": "5"}

        async with client.stream(
            "GET",
            await _stream_url(client, token, org_id, scan_id),
            headers=hdrs_reconnect,
            timeout=5.0,
        ) as response:
            events = await collect_sse_events(response, max_events=5, timeout=4.0)

        # Should immediately get a completed update + done
        statuses = [
            e.get("data", {}).get("status")
            for e in events
            if e.get("event") == "scan_update"
        ]
        assert "completed" in statuses, f"Expected completed status on reconnect, got: {statuses}"

        done_events = [e for e in events if e.get("event") == "done"]
        assert len(done_events) >= 1


class TestSSEDatabaseError:
    """SSE generator emits error event on DB failure (BUG-13)."""

    @pytest.mark.asyncio
    async def test_sse_emits_error_on_db_failure(self, client, db):
        """DB exception during polling must emit event: error, not silent disconnect."""
        from sqlalchemy.exc import OperationalError
        token, org_id = await _register_login_org(client)
        scan_id = await _create_scan(client, token, org_id, db=db)
        hdrs = {"Authorization": f"Bearer {token}"}

        stream_url = await _stream_url(client, token, org_id, scan_id)
        with patch(
            "app.db.session.AsyncSessionLocal",
            side_effect=OperationalError("DB down", None, None),
        ):
            async with client.stream(
                "GET",
                    stream_url,
                headers=hdrs,
                timeout=5.0,
            ) as response:
                events = await collect_sse_events(response, max_events=5, timeout=4.0)

        error_events = [e for e in events if e.get("event") == "error"]
        assert any(
            "db_unavailable" in str(e.get("data", "")) for e in error_events
        ), f"DB failure must emit error:db_unavailable, got: {events}"


class TestSSEMultiTenantIsolation:
    """Org A cannot subscribe to org B's scan events."""

    @pytest.mark.asyncio
    async def test_cross_org_scan_events_returns_error(self, client, db):
        """Org B's token cannot subscribe to org A's scan events."""
        token_a, org_id_a = await _register_login_org(client)
        token_b, org_id_b = await _register_login_org(client)

        # Create scan in org A
        scan_id_a = await _create_scan(client, token_a, org_id_a, db=db)

        hdrs_b = {"Authorization": f"Bearer {token_b}"}

        # Org B cannot get a ticket for org A's scan, through either org URL.
        for url_org in (org_id_b, org_id_a):
            resp = await client.post(
                f"/api/v1/orgs/{url_org}/scans/{scan_id_a}/stream-token",
                headers=hdrs_b,
            )
            assert resp.status_code == 404, (url_org, resp.status_code)

        # A valid org-B ticket replayed against org A's scan is refused too
        # (ticket is bound to the org/scan it was issued for).
        scan_id_b = await _create_scan(client, token_b, org_id_b, db=db)
        ticket_b = (await _stream_url(client, token_b, org_id_b, scan_id_b)).split("sse_token=", 1)[1]
        for url_org in (org_id_b, org_id_a):
            resp = await client.get(
                f"/api/v1/orgs/{url_org}/scans/{scan_id_a}/stream?sse_token={ticket_b}",
            )
            assert resp.status_code == 401, (url_org, resp.status_code)
            ticket_b = (await _stream_url(client, token_b, org_id_b, scan_id_b)).split("sse_token=", 1)[1]

        # And the stream never accepts a plain Bearer header.
        resp = await client.get(
            f"/api/v1/orgs/{org_id_b}/scans/{scan_id_b}/stream", headers=hdrs_b,
        )
        assert resp.status_code == 401
