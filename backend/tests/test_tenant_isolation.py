"""AT-06: Tenant isolation — IDOR tests on every resource."""
import pytest
from httpx import AsyncClient

from tests.conftest import auth_headers, login_user, register_user


@pytest.fixture(autouse=True, params=["saas", "selfhosted"])
def edition(request, monkeypatch):
    """Tenant isolation must hold in both editions (users are never platform admin)."""
    from app.core.config import settings
    monkeypatch.setattr(settings, "MAILOX_EDITION", request.param)
    return request.param


async def _setup_two_orgs(client: AsyncClient) -> tuple[str, str, str, str]:
    """
    Returns (org_a_id, org_b_id, token_a, token_b).
    Two separate users, each in their own org.
    """
    await register_user(client, email="user_a@tenant-test.dev")
    await register_user(client, email="user_b@tenant-test.dev")
    tokens_a = await login_user(client, email="user_a@tenant-test.dev")
    tokens_b = await login_user(client, email="user_b@tenant-test.dev")

    resp_a = await client.post(
        "/api/v1/orgs",
        json={"name": "Org A", "slug": "tenant-org-a"},
        headers=auth_headers(tokens_a["access_token"]),
    )
    resp_b = await client.post(
        "/api/v1/orgs",
        json={"name": "Org B", "slug": "tenant-org-b"},
        headers=auth_headers(tokens_b["access_token"]),
    )

    return (
        resp_a.json()["id"],
        resp_b.json()["id"],
        tokens_a["access_token"],
        tokens_b["access_token"],
    )


class TestOrganizationIDOR:
    async def test_user_a_cannot_get_org_b(self, client: AsyncClient):
        org_a_id, org_b_id, token_a, token_b = await _setup_two_orgs(client)

        resp = await client.get(
            f"/api/v1/orgs/{org_b_id}",
            headers=auth_headers(token_a),
        )
        # Must be 404, not 403 (prevents confirming that the resource exists)
        assert resp.status_code == 404

    async def test_user_b_cannot_get_org_a(self, client: AsyncClient):
        org_a_id, org_b_id, token_a, token_b = await _setup_two_orgs(client)

        resp = await client.get(
            f"/api/v1/orgs/{org_a_id}",
            headers=auth_headers(token_b),
        )
        assert resp.status_code == 404

    async def test_user_a_cannot_list_org_b_members(self, client: AsyncClient):
        org_a_id, org_b_id, token_a, token_b = await _setup_two_orgs(client)

        resp = await client.get(
            f"/api/v1/orgs/{org_b_id}/members",
            headers=auth_headers(token_a),
        )
        assert resp.status_code == 404

    async def test_user_a_cannot_invite_to_org_b(self, client: AsyncClient):
        org_a_id, org_b_id, token_a, token_b = await _setup_two_orgs(client)
        await register_user(client, email="victim@tenant-test.dev")

        resp = await client.post(
            f"/api/v1/orgs/{org_b_id}/members/invite",
            json={"email": "victim@tenant-test.dev", "role": "auditor"},
            headers=auth_headers(token_a),
        )
        assert resp.status_code == 404

    async def test_list_orgs_does_not_leak_other_orgs(self, client: AsyncClient):
        org_a_id, org_b_id, token_a, token_b = await _setup_two_orgs(client)

        resp = await client.get(
            "/api/v1/orgs",
            headers=auth_headers(token_a),
        )
        assert resp.status_code == 200
        ids = [o["id"] for o in resp.json()]
        assert org_b_id not in ids

    async def test_org_id_in_body_cannot_override_jwt(self, client: AsyncClient):
        """
        Sending a different org_id in body must not grant access.
        Routes extract org_id from path params, not body.
        """
        org_a_id, org_b_id, token_a, token_b = await _setup_two_orgs(client)
        await register_user(client, email="override_victim@tenant-test.dev")

        # Attempt: user A hits Org B's invite endpoint
        resp = await client.post(
            f"/api/v1/orgs/{org_b_id}/members/invite",
            json={
                "email": "override_victim@tenant-test.dev",
                "role": "auditor",
                "org_id": str(org_a_id),  # injected org_id — must be ignored
            },
            headers=auth_headers(token_a),
        )
        assert resp.status_code == 404

    async def test_nonexistent_org_returns_404_not_500(self, client: AsyncClient):
        await register_user(client, email="probe@tenant-test.dev")
        tokens = await login_user(client, email="probe@tenant-test.dev")

        resp = await client.get(
            "/api/v1/orgs/00000000-0000-0000-0000-000000000000",
            headers=auth_headers(tokens["access_token"]),
        )
        assert resp.status_code == 404
        assert resp.status_code != 500
