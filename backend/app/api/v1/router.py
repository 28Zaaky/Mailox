from fastapi import APIRouter

from app.api.v1.endpoints.access import admin_router, domains_router, public_router as edition_router
from app.api.v1.endpoints.auth import router as auth_router
from app.api.v1.endpoints.canonical_findings import router as canonical_findings_router
from app.api.v1.endpoints.findings import router as findings_router
from app.api.v1.endpoints.organizations import router as org_router
from app.api.v1.endpoints.projects import router as projects_router
from app.api.v1.endpoints.reports import router as reports_router
from app.api.v1.endpoints.scans import router as scans_router
from app.api.v1.endpoints.secrets import router as secrets_router
from app.api.v1.endpoints.assets import router as assets_router
from app.api.v1.endpoints.reports_v2 import router as reports_v2_router
from app.api.v1.endpoints.monitoring import router as monitoring_router
from app.api.v1.endpoints.profiles import router as profiles_router
from app.api.v1.endpoints.intel.router import router as intel_router
from app.api.v1.endpoints.schedules import router as schedules_router
from app.api.v1.endpoints.webhooks import router as webhooks_router
from app.api.v1.endpoints.org_settings import router as org_settings_router

api_router = APIRouter()
api_router.include_router(auth_router)
api_router.include_router(edition_router)
api_router.include_router(admin_router)
api_router.include_router(domains_router, prefix="/orgs/{org_id}")
api_router.include_router(org_router)
api_router.include_router(scans_router, prefix="/orgs/{org_id}")
api_router.include_router(secrets_router)
api_router.include_router(findings_router, prefix="/orgs/{org_id}")
api_router.include_router(reports_router, prefix="/orgs/{org_id}")
api_router.include_router(reports_v2_router, prefix="/orgs/{org_id}")
api_router.include_router(projects_router, prefix="/orgs/{org_id}")
api_router.include_router(canonical_findings_router, prefix="/orgs/{org_id}")
api_router.include_router(assets_router, prefix="/orgs/{org_id}")
api_router.include_router(monitoring_router, prefix="/orgs/{org_id}")
api_router.include_router(profiles_router, prefix="/orgs/{org_id}")
api_router.include_router(schedules_router, prefix="/orgs/{org_id}")
api_router.include_router(webhooks_router, prefix="/orgs/{org_id}")
api_router.include_router(org_settings_router, prefix="/orgs/{org_id}")
api_router.include_router(intel_router)
