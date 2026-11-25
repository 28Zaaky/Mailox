"""AT-05: Organizations + RBAC."""
import pytest
from httpx import AsyncClient

from tests.conftest import TEST_EMAIL, TEST_PASSWORD, auth_headers, login_user, register_user

ORG_PAYLOAD = {"name": "Acme Security", "slug": "acme-security"}


class TestOrganizationCRUD:
    async def test_create_organization(self, client: AsyncClient):
        await register_user(client)
        tokens = await login_user(client)
        resp = await client.post(
            "/api/v1/orgs",
            json=ORG_PAYLOAD,
            headers=auth_headers(tokens["access_token"]),
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "Acme Security"
        assert data["slug"] == "acme-security"
        assert "id" in data

    async def test_create_duplicate_slug_rejected(self, client: AsyncClient):
        # Two accounts: in SaaS one account may own only SAAS_MAX_ORGS_PER_USER (1)
        # org, so the second create by the same account would hit the quota first.
        await register_user(client)
        tokens = await login_user(client)
        first = await client.post(
            "/api/v1/orgs",
            json=ORG_PAYLOAD,
            headers=auth_headers(tokens["access_token"]),
        )
        assert first.status_code == 201, first.text
        other_email = "slug-other@example.com"
        await register_user(client, email=other_email)
        other = await login_user(client, email=other_email)
        resp = await client.post(
            "/api/v1/orgs",
            json=ORG_PAYLOAD,
            headers=auth_headers(other["access_token"]),
        )
        assert resp.status_code == 409

    async def test_saas_org_quota_per_account(self, client: AsyncClient):
        from app.core.config import settings

        assert settings.IS_SAAS and settings.SAAS_MAX_ORGS_PER_USER == 1
        await register_user(client)
        tokens = await login_user(client)
        first = await client.post(
            "/api/v1/orgs",
            json=ORG_PAYLOAD,
            headers=auth_headers(tokens["access_token"]),
        )
        assert first.status_code == 201, first.text
        resp = await client.post(
            "/api/v1/orgs",
            json={"name": "Second Org", "slug": "second-org"},
            headers=auth_headers(tokens["access_token"]),
        )
        assert resp.status_code == 403

    async def test_list_orgs_returns_only_user_orgs(self, client: AsyncClient):
        await register_user(client)
        tokens = await login_user(client)
        await client.post(
            "/api/v1/orgs",
            json={"name": "My Org", "slug": "my-unique-org"},
            headers=auth_headers(tokens["access_token"]),
        )
        resp = await client.get(
            "/api/v1/orgs",
            headers=auth_headers(tokens["access_token"]),
        )
        assert resp.status_code == 200
        orgs = resp.json()
        assert len(orgs) >= 1
        slugs = [o["slug"] for o in orgs]
        assert "my-unique-org" in slugs

    async def test_creator_becomes_org_admin(self, client: AsyncClient):
        await register_user(client)
        tokens = await login_user(client)
        create_resp = await client.post(
            "/api/v1/orgs",
            json={"name": "Admin Test Org", "slug": "admin-test-org"},
            headers=auth_headers(tokens["access_token"]),
        )
        org_id = create_resp.json()["id"]

        members = await client.get(
            f"/api/v1/orgs/{org_id}/members",
            headers=auth_headers(tokens["access_token"]),
        )
        assert members.status_code == 200
        member_list = members.json()
        assert len(member_list) == 1
        assert member_list[0]["role"] == "org_admin"

    async def test_invite_member(self, client: AsyncClient):
        await register_user(client)
        tokens = await login_user(client)
        await register_user(client, email="analyst@example.com")

        create_resp = await client.post(
            "/api/v1/orgs",
            json={"name": "Invite Test", "slug": "invite-test-org"},
            headers=auth_headers(tokens["access_token"]),
        )
        org_id = create_resp.json()["id"]

        resp = await client.post(
            f"/api/v1/orgs/{org_id}/members/invite",
            json={"email": "analyst@example.com", "role": "analyst"},
            headers=auth_headers(tokens["access_token"]),
        )
        assert resp.status_code == 201
        assert resp.json()["role"] == "analyst"

    async def test_unauthenticated_access_rejected(self, client: AsyncClient):
        resp = await client.get("/api/v1/orgs")
        assert resp.status_code == 401

    async def test_invalid_slug_rejected(self, client: AsyncClient):
        await register_user(client)
        tokens = await login_user(client)
        resp = await client.post(
            "/api/v1/orgs",
            json={"name": "Bad Slug", "slug": "-invalid-slug-"},
            headers=auth_headers(tokens["access_token"]),
        )
        assert resp.status_code == 422


class TestRBAC:
    async def _create_org_with_role(
        self, client: AsyncClient, member_role: str
    ) -> tuple[str, str, str]:
        """Returns (org_id, admin_token, member_token)."""
        # Admin
        await register_user(client, email="rbac_admin@example.com")
        admin_tokens = await login_user(client, email="rbac_admin@example.com")

        # Member
        await register_user(client, email=f"rbac_{member_role}@example.com")
        member_tokens = await login_user(client, email=f"rbac_{member_role}@example.com")

        create_resp = await client.post(
            "/api/v1/orgs",
            json={"name": f"RBAC {member_role}", "slug": f"rbac-{member_role}-org"},
            headers=auth_headers(admin_tokens["access_token"]),
        )
        org_id = create_resp.json()["id"]

        await client.post(
            f"/api/v1/orgs/{org_id}/members/invite",
            json={"email": f"rbac_{member_role}@example.com", "role": member_role},
            headers=auth_headers(admin_tokens["access_token"]),
        )

        return org_id, admin_tokens["access_token"], member_tokens["access_token"]

    async def test_auditor_cannot_invite_members(self, client: AsyncClient):
        org_id, _, auditor_token = await self._create_org_with_role(client, "auditor")
        await register_user(client, email="new_target@example.com")

        resp = await client.post(
            f"/api/v1/orgs/{org_id}/members/invite",
            json={"email": "new_target@example.com", "role": "auditor"},
            headers=auth_headers(auditor_token),
        )
        assert resp.status_code == 403


class TestInactiveOrganization:
    async def test_deleted_org_not_reachable_by_members(self, client: AsyncClient):
        """A soft-deleted org (is_active=False) must 404 on every org-scoped route."""
        await register_user(client, email="inactive_org@example.com")
        tokens = await login_user(client, email="inactive_org@example.com")
        hdrs = auth_headers(tokens["access_token"])
        resp = await client.post(
            "/api/v1/orgs", json={"name": "Gone Org", "slug": "gone-org"}, headers=hdrs
        )
        assert resp.status_code == 201
        org_id = resp.json()["id"]

        assert (await client.get(f"/api/v1/orgs/{org_id}/projects", headers=hdrs)).status_code == 200
        assert (await client.delete(f"/api/v1/orgs/{org_id}", headers=hdrs)).status_code == 204

        assert (await client.get(f"/api/v1/orgs/{org_id}/projects", headers=hdrs)).status_code == 404
        resp = await client.post(
            f"/api/v1/orgs/{org_id}/projects", json={"name": "after-delete"}, headers=hdrs
        )
        assert resp.status_code == 404
