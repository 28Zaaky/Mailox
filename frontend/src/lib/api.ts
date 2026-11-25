import axios, { AxiosError, type InternalAxiosRequestConfig } from 'axios'
import type {
  VulnListResponse,
  VulnerabilityDetail,
  VulnerabilityOut,
  ProductOut,
  SyncStatusOut,
  VulnFilters,
} from '../types/intel'
import type {
  AssessmentProfile,
  BatchScanResult,
  ExposedSecret,
  FindingListResponse,
  FindingSummary,
  FindingStatus,
  LoginResponse,
  MFASetupResult,
  Organization,
  OrgMember,
  OrgSettings,
  OrgSettingsUpdate,
  OrgStats,
  Project,
  ProjectMember,
  Scan,
  ScanDetail,
  ScanAssets,
  ScanFinding,
  SessionInfo,
  TokenResponse,
  User,
} from '../types'

const client = axios.create({
  baseURL: '/api/v1',
  withCredentials: true,
})

/** Exposed for tests (adapter injection). App code goes through the typed helpers below. */
export const apiClient = client

// ── Token management ──────────────────────────────────────────────────────────

let _accessToken: string | null = null
// Set once a refresh has failed: further 401s fail fast instead of hammering
// /auth/refresh (and redirecting) once per in-flight request.
let _sessionExpired = false

export function setAccessToken(token: string | null) {
  _accessToken = token
  if (token) _sessionExpired = false
}

export function getAccessToken() {
  return _accessToken
}

// Called once when the session cannot be refreshed. AuthProvider replaces it to
// clear its state (ProtectedRoute then redirects); the default is a hard redirect.
type AuthFailureHandler = () => void
const defaultAuthFailureHandler: AuthFailureHandler = () => {
  if (window.location.pathname !== '/login') window.location.assign('/login')
}
let _onAuthFailure: AuthFailureHandler = defaultAuthFailureHandler

export function setAuthFailureHandler(handler: AuthFailureHandler | null) {
  _onAuthFailure = handler ?? defaultAuthFailureHandler
}

// ── Single-flight refresh ────────────────────────────────────────────────────
// The backend rotates refresh tokens and revokes the whole session family when a
// consumed token is replayed. Two concurrent POST /auth/refresh would send the same
// cookie twice → family revoked → user logged out everywhere. Every caller (401
// interceptor, AuthProvider bootstrap) therefore shares one in-flight promise.

let _refreshPromise: Promise<string> | null = null

export function refreshAccessToken(): Promise<string> {
  if (!_refreshPromise) {
    _refreshPromise = client
      .post<TokenResponse>('/auth/refresh', {})
      .then((r) => {
        setAccessToken(r.data.access_token)
        return r.data.access_token
      })
      .finally(() => {
        _refreshPromise = null
      })
  }
  return _refreshPromise
}

// Endpoints that must never trigger a refresh-and-retry: they either establish the
// session themselves or a 401 from them is a real answer (bad password, bad TOTP).
const NO_REFRESH_PATHS = [
  '/auth/login',
  '/auth/register',
  '/auth/refresh',
  '/auth/local-session',
  '/auth/mfa/authenticate',
  '/auth/forgot-password',
  '/auth/reset-password',
]

function isNoRefreshUrl(url: string | undefined): boolean {
  const u = url ?? ''
  return NO_REFRESH_PATHS.some((p) => u.includes(p))
}

type RetriableConfig = InternalAxiosRequestConfig & { _retry?: boolean }

client.interceptors.request.use((config) => {
  if (_accessToken) {
    config.headers.Authorization = `Bearer ${_accessToken}`
  }
  return config
})

client.interceptors.response.use(
  (res) => res,
  async (error: unknown) => {
    if (!(error instanceof AxiosError) || error.response?.status !== 401 || !error.config) {
      return Promise.reject(error)
    }
    const original = error.config as RetriableConfig
    if (original._retry || isNoRefreshUrl(original.url)) {
      return Promise.reject(error)
    }
    if (_sessionExpired) return Promise.reject(error)
    original._retry = true

    // The request left with a token that has since been replaced (a refresh
    // completed while it was in flight): just replay it with the current one.
    const sentAuth = original.headers?.Authorization
    if (_accessToken && sentAuth !== `Bearer ${_accessToken}`) {
      return client(original)
    }

    const ownsRefresh = _refreshPromise === null
    try {
      await refreshAccessToken()
    } catch {
      // Only the request that started the refresh tears the session down, so the
      // state clear + redirect happen exactly once per failed refresh.
      if (ownsRefresh && !_sessionExpired) {
        _sessionExpired = true
        _accessToken = null
        _onAuthFailure()
      }
      return Promise.reject(error)
    }
    return client(original)
  }
)

// ── Auth ─────────────────────────────────────────────────────────────────────

export const auth = {
  /** First factor. Returns either tokens or an MFA challenge (`mfa_required`). */
  login: (email: string, password: string) =>
    client.post<LoginResponse>('/auth/login', { email, password }).then((r) => r.data),

  /** Second factor: exchange the short-lived mfa_token + TOTP/backup code for tokens. */
  mfaAuthenticate: (mfa_token: string, code: string) =>
    client.post<TokenResponse>('/auth/mfa/authenticate', { mfa_token, code }).then((r) => r.data),

  register: (email: string, password: string, full_name?: string, invite?: string) =>
    client.post<User>('/auth/register', { email, password, full_name, invite }).then((r) => r.data),

  logout: (allDevices = false) =>
    client.post('/auth/logout', { all_devices: allDevices }).then(() => setAccessToken(null)),

  me: () =>
    client.get<User>('/auth/me').then((r) => r.data),

  updateMe: (full_name: string | null) =>
    client.patch<User>('/auth/me', { full_name }).then((r) => r.data),

  forgotPassword: (email: string) =>
    client.post('/auth/forgot-password', { email }),

  resetPassword: (token: string, new_password: string) =>
    client.post('/auth/reset-password', { token, new_password }),

  /** Single-flight: concurrent callers share one POST /auth/refresh. */
  refresh: () => refreshAccessToken(),

  // Self-hosted edition: the app opens its own session, there are no accounts
  localSession: () =>
    client.post<TokenResponse>('/auth/local-session', {}).then((r) => r.data),

  mfaSetup: () =>
    client.post<MFASetupResult>('/auth/mfa/setup').then((r) => r.data),

  mfaVerify: (code: string) =>
    client.post('/auth/mfa/verify', { code }).then((r) => r.data),

  listSessions: () =>
    client.get<SessionInfo[]>('/auth/sessions').then((r) => r.data),

  revokeSession: (sessionId: string) =>
    client.delete(`/auth/sessions/${sessionId}`),
}

// ── Organizations ─────────────────────────────────────────────────────────────

export const orgs = {
  list: () =>
    client.get<Organization[]>('/orgs').then((r) => r.data),

  get: (orgId: string) =>
    client.get<Organization>(`/orgs/${orgId}`).then((r) => r.data),

  create: (name: string) =>
    client.post<Organization>('/orgs', { name }).then((r) => r.data),

  members: (orgId: string) =>
    client.get<OrgMember[]>(`/orgs/${orgId}/members`).then((r) => r.data),

  inviteMember: (orgId: string, email: string, role: string) =>
    client.post(`/orgs/${orgId}/members/invite`, { email, role }).then((r) => r.data),

  removeMember: (orgId: string, userId: string) =>
    client.delete(`/orgs/${orgId}/members/${userId}`).then((r) => r.data),

  stats: (orgId: string) =>
    client.get<OrgStats>(`/orgs/${orgId}/stats`).then((r) => r.data),

  update: (orgId: string, name: string) =>
    client.patch<Organization>(`/orgs/${orgId}`, { name }).then((r) => r.data),

  delete: (orgId: string) =>
    client.delete(`/orgs/${orgId}`),

  auditLogs: (
    orgId: string,
    params?: { action?: string; resource_type?: string; user_id?: string; page?: number; page_size?: number }
  ) =>
    client
      .get<{ items: AuditLogEntry[]; total: number; page: number; page_size: number }>(
        `/orgs/${orgId}/audit`,
        { params }
      )
      .then((r) => r.data),

  getPentestConfig: (orgId: string) =>
    client
      .get<{ cred_probe_enabled: boolean; web_active_probe_enabled: boolean; canary_email: string | null }>(
        `/orgs/${orgId}/pentest-config`
      )
      .then((r) => r.data),

  updatePentestConfig: (
    orgId: string,
    cfg: { cred_probe_enabled?: boolean; web_active_probe_enabled?: boolean; canary_email?: string | null }
  ) =>
    client
      .patch<{ cred_probe_enabled: boolean; web_active_probe_enabled: boolean; canary_email: string | null }>(
        `/orgs/${orgId}/pentest-config`,
        cfg
      )
      .then((r) => r.data),

  testCanary: (orgId: string) =>
    client
      .post<{ sent: boolean; reason?: string }>(`/orgs/${orgId}/pentest-config/test-canary`)
      .then((r) => r.data),

  getSettings: (orgId: string) =>
    client
      .get<OrgSettings>(`/orgs/${orgId}/settings`)
      .then((r) => r.data),

  updateSettings: (orgId: string, body: OrgSettingsUpdate) =>
    client
      .patch<OrgSettings>(`/orgs/${orgId}/settings`, body)
      .then((r) => r.data),
}

// ── Scans ─────────────────────────────────────────────────────────────────────

export const scans = {
  list: (orgId: string, limit = 20, offset = 0) =>
    client
      .get<Scan[]>(`/orgs/${orgId}/scans`, { params: { limit, offset } })
      .then((r) => r.data),

  get: (orgId: string, scanId: string) =>
    client.get<ScanDetail>(`/orgs/${orgId}/scans/${scanId}`).then((r) => r.data),

  create: (orgId: string, target_domain: string, project_id?: string, profile_id?: string) =>
    client
      .post<ScanDetail>(`/orgs/${orgId}/scans`, { target_domain, project_id, profile_id })
      .then((r) => r.data),

  cancel: (orgId: string, scanId: string) =>
    client.post(`/orgs/${orgId}/scans/${scanId}/cancel`).then((r) => r.data),

  delete: (orgId: string, scanId: string) =>
    client.delete(`/orgs/${orgId}/scans/${scanId}`).then((r) => r.data),

  assets: (orgId: string, scanId: string) =>
    client.get<ScanAssets>(`/orgs/${orgId}/scans/${scanId}/assets`).then((r) => r.data),

  createStreamToken: (orgId: string, scanId: string) =>
    client.post<{ sse_token: string }>(`/orgs/${orgId}/scans/${scanId}/stream-token`).then((r) => r.data),

  streamUrl: (orgId: string, scanId: string, sseToken: string) =>
    `/api/v1/orgs/${orgId}/scans/${scanId}/stream?sse_token=${sseToken}`,

  engineStats: (orgId: string, engine: string) =>
    client
      .get<{ engine: string; run_count: number; finding_total: number; last_run_at: string | null; last_status: string | null }>
      (`/orgs/${orgId}/scans/engine-stats`, { params: { engine } })
      .then((r) => r.data),

  batchScanJson: (orgId: string, domains: string[], profileId?: string) =>
    client
      .post<BatchScanResult[]>(`/orgs/${orgId}/scans/batch/json`, {
        domains,
        profile_id: profileId ?? null,
      })
      .then((r) => r.data),
}

// ── Findings ─────────────────────────────────────────────────────────────────

export const findings = {
  list: (
    orgId: string,
    params?: {
      scan_id?: string
      engine?: string
      check_id_prefix?: string
      risk_level?: string
      status?: string
      page?: number
      page_size?: number
    }
  ) =>
    client
      .get<FindingListResponse>(`/orgs/${orgId}/findings`, { params })
      .then((r) => r.data),

  summary: (orgId: string, scanId?: string) =>
    client
      .get<FindingSummary>(`/orgs/${orgId}/findings/summary`, {
        params: scanId ? { scan_id: scanId } : undefined,
      })
      .then((r) => r.data),

  get: (orgId: string, findingId: string) =>
    client.get<ScanFinding>(`/orgs/${orgId}/findings/${findingId}`).then((r) => r.data),

  updateStatus: (orgId: string, findingId: string, status: FindingStatus) =>
    client
      .patch<ScanFinding>(`/orgs/${orgId}/findings/${findingId}`, { status })
      .then((r) => r.data),
}

// ── Secrets ──────────────────────────────────────────────────────────────────

export const secrets = {
  list: (orgId: string, params?: { page?: number; page_size?: number }) =>
    client
      .get<{ items: ExposedSecret[]; total: number }>(`/orgs/${orgId}/secrets`, { params })
      .then((r) => r.data),

  get: (orgId: string, secretId: string) =>
    client.get<ExposedSecret>(`/orgs/${orgId}/secrets/${secretId}`).then((r) => r.data),

  updateStatus: (orgId: string, secretId: string, status: string) =>
    client
      .patch(`/orgs/${orgId}/secrets/${secretId}/status`, { status })
      .then((r) => r.data),

  upload: (orgId: string, file: File) => {
    const form = new FormData()
    form.append('file', file)
    return client
      .post(`/orgs/${orgId}/secrets/scan`, form, {
        headers: { 'Content-Type': 'multipart/form-data' },
      })
      .then((r) => r.data)
  },
}

// ── Projects ──────────────────────────────────────────────────────────────────

export const projects = {
  list: (orgId: string) =>
    client.get<Project[]>(`/orgs/${orgId}/projects`).then((r) => r.data),

  get: (orgId: string, projectId: string) =>
    client.get<Project>(`/orgs/${orgId}/projects/${projectId}`).then((r) => r.data),

  create: (orgId: string, name: string, description?: string) =>
    client.post<Project>(`/orgs/${orgId}/projects`, { name, description }).then((r) => r.data),

  update: (orgId: string, projectId: string, data: { name?: string; description?: string; status?: string }) =>
    client.patch<Project>(`/orgs/${orgId}/projects/${projectId}`, data).then((r) => r.data),

  archive: (orgId: string, projectId: string) =>
    client.delete(`/orgs/${orgId}/projects/${projectId}`),

  members: (orgId: string, projectId: string) =>
    client.get<ProjectMember[]>(`/orgs/${orgId}/projects/${projectId}/members`).then((r) => r.data),

  addMember: (orgId: string, projectId: string, userId: string, role = 'analyst') =>
    client
      .post<ProjectMember>(`/orgs/${orgId}/projects/${projectId}/members`, { user_id: userId, role })
      .then((r) => r.data),

  removeMember: (orgId: string, projectId: string, userId: string) =>
    client.delete(`/orgs/${orgId}/projects/${projectId}/members/${userId}`),
}

// ── Canonical Findings ────────────────────────────────────────────────────────

export const canonicalFindings = {
  listByProject: (
    orgId: string,
    projectId: string,
    params?: { status?: string; risk_level?: string; limit?: number; offset?: number }
  ) =>
    client
      .get(`/orgs/${orgId}/projects/${projectId}/findings`, { params })
      .then((r) => r.data),

  getSummary: (orgId: string, projectId: string) =>
    client
      .get(`/orgs/${orgId}/projects/${projectId}/findings/summary`)
      .then((r) => r.data),

  get: (orgId: string, findingId: string) =>
    client.get(`/orgs/${orgId}/findings/${findingId}`).then((r) => r.data),

  patch: (
    orgId: string,
    findingId: string,
    body: { status?: string; assigned_to?: string; reason?: string; comment?: string }
  ) =>
    client.patch(`/orgs/${orgId}/findings/${findingId}`, body).then((r) => r.data),

  getHistory: (orgId: string, findingId: string) =>
    client.get(`/orgs/${orgId}/findings/${findingId}/history`).then((r) => r.data),
}

// ── Assets ────────────────────────────────────────────────────────────────────

export const assets = {
  list: (orgId: string, assetType?: string) =>
    client.get(`/orgs/${orgId}/assets`, { params: assetType ? { asset_type: assetType } : {} }).then((r) => r.data),

  get: (orgId: string, assetId: string) =>
    client.get(`/orgs/${orgId}/assets/${assetId}`).then((r) => r.data),

  listScope: (orgId: string, projectId: string) =>
    client.get(`/orgs/${orgId}/projects/${projectId}/scope`).then((r) => r.data),

  addScope: (orgId: string, projectId: string, body: { asset_type: string; value: string; authorized?: boolean }) =>
    client.post(`/orgs/${orgId}/projects/${projectId}/scope`, body).then((r) => r.data),

  removeScope: (orgId: string, projectId: string, assetId: string) =>
    client.delete(`/orgs/${orgId}/projects/${projectId}/scope/${assetId}`),

  getScopeSnapshot: (orgId: string, scanId: string) =>
    client.get(`/orgs/${orgId}/scans/${scanId}/scope`).then((r) => r.data),
}

// ── Assessment Profiles ───────────────────────────────────────────────────────

export const profiles = {
  list: (orgId: string, projectId?: string) =>
    client
      .get<AssessmentProfile[]>(`/orgs/${orgId}/profiles`, {
        params: projectId ? { project_id: projectId } : undefined,
      })
      .then((r) => r.data),

  get: (orgId: string, profileId: string) =>
    client.get<AssessmentProfile>(`/orgs/${orgId}/profiles/${profileId}`).then((r) => r.data),

  create: (orgId: string, body: { name: string; engines: string[]; time_limit_seconds?: number; project_id?: string }) =>
    client.post<AssessmentProfile>(`/orgs/${orgId}/profiles`, body).then((r) => r.data),

  delete: (orgId: string, profileId: string) =>
    client.delete(`/orgs/${orgId}/profiles/${profileId}`),
}

// ── CVE Intelligence ─────────────────────────────────────────────────────────

export const intel = {
  listVulnerabilities: (filters: VulnFilters = {}) => {
    const params: Record<string, unknown> = {
      page: filters.page ?? 1,
      per_page: filters.per_page ?? 50,
    }
    if (filters.severity?.length) params['severity'] = filters.severity
    if (filters.in_cisa_kev) params['in_cisa_kev'] = true
    if (filters.exploit_available) params['exploit_available'] = true
    if (filters.search) params['search'] = filters.search
    if (filters.product) params['product'] = filters.product
    return client.get<VulnListResponse>('/intel/vulnerabilities', { params }).then((r) => r.data)
  },

  getVulnerability: (cveId: string) =>
    client.get<VulnerabilityDetail>(`/intel/vulnerabilities/${cveId}`).then((r) => r.data),

  listProducts: () =>
    client.get<ProductOut[]>('/intel/products').then((r) => r.data),

  getSyncStatus: () =>
    client.get<SyncStatusOut[]>('/intel/sync/status').then((r) => r.data),

  triggerSync: (source: string) =>
    client
      .post<{ task_id: string; source: string; message: string }>(`/intel/sync/${source}`)
      .then((r) => r.data),

  // Backend: PATCH /intel/vulnerabilities/{cve_id}, body RelevancePatch { relevance, reason? },
  // admin only, responds with VulnerabilityOut.
  updateRelevance: (cveId: string, relevance: string, reason?: string) =>
    client
      .patch<VulnerabilityOut>(`/intel/vulnerabilities/${encodeURIComponent(cveId)}`, { relevance, reason })
      .then((r) => r.data),
}

// ── Monitoring ────────────────────────────────────────────────────────────────

export const monitoring = {
  list: (orgId: string, projectId: string) =>
    client.get(`/orgs/${orgId}/projects/${projectId}/monitoring`).then((r) => r.data),

  create: (orgId: string, projectId: string, body: { profile_id: string; cron_expression: string; enabled?: boolean }) =>
    client.post(`/orgs/${orgId}/projects/${projectId}/monitoring`, body).then((r) => r.data),

  update: (orgId: string, projectId: string, scheduleId: string, body: { cron_expression?: string; enabled?: boolean }) =>
    client.patch(`/orgs/${orgId}/projects/${projectId}/monitoring/${scheduleId}`, body).then((r) => r.data),

  delete: (orgId: string, projectId: string, scheduleId: string) =>
    client.delete(`/orgs/${orgId}/projects/${projectId}/monitoring/${scheduleId}`),

  history: (orgId: string, projectId: string, scheduleId: string) =>
    client.get(`/orgs/${orgId}/projects/${projectId}/monitoring/${scheduleId}/history`).then((r) => r.data),
}

// ── Reports (legacy — scan-level ephemeral) ───────────────────────────────────

export const reports = {
  download: (
    orgId: string,
    scanId: string,
    report_type: 'executive' | 'technical' | 'full' = 'full',
    format: 'json' | 'html' | 'csv' = 'json'
  ) =>
    client
      .get(`/orgs/${orgId}/scans/${scanId}/report`, {
        params: { report_type, format },
        responseType: format === 'json' ? 'json' : 'blob',
      })
      .then((r) => r.data),
}

// ── Reports V2 (persistent) ───────────────────────────────────────────────────

export interface ReportRecord {
  id: string
  org_id: string
  project_id: string | null
  scan_id: string | null
  report_type: string
  format: string
  title: string | null
  generated_by: string | null
  generated_at: string
  size_bytes: number | null
}

// ── Audit Log ─────────────────────────────────────────────────────────────────

export interface AuditLogEntry {
  id: string
  org_id: string | null
  user_id: string | null
  action: string
  resource_type: string | null
  resource_id: string | null
  details: Record<string, unknown> | null
  ip_address: string | null
  created_at: string
}

export const reportsV2 = {
  list: (orgId: string, params?: { project_id?: string; scan_id?: string; limit?: number; offset?: number }) =>
    client.get<ReportRecord[]>(`/orgs/${orgId}/reports`, { params }).then((r) => r.data),

  get: (orgId: string, reportId: string) =>
    client.get<ReportRecord>(`/orgs/${orgId}/reports/${reportId}`).then((r) => r.data),

  delete: (orgId: string, reportId: string) =>
    client.delete(`/orgs/${orgId}/reports/${reportId}`),

  generateFromScan: (
    orgId: string,
    scanId: string,
    body: { report_type?: string; format?: string; project_id?: string; title?: string }
  ) =>
    client
      .post(`/orgs/${orgId}/scans/${scanId}/report/generate`, body, {
        responseType: (body.format ?? 'json') === 'json' ? 'json' : 'blob',
      })
      .then((r) => ({ data: r.data, reportId: r.headers['x-report-id'] as string | undefined })),

  listProjectReports: (orgId: string, projectId: string, params?: { limit?: number; offset?: number }) =>
    client.get<ReportRecord[]>(`/orgs/${orgId}/projects/${projectId}/reports`, { params }).then((r) => r.data),

  createProjectReport: (
    orgId: string,
    projectId: string,
    body: { report_type?: string; format?: string; include_scan_ids?: string[]; title?: string }
  ) =>
    client.post<ReportRecord>(`/orgs/${orgId}/projects/${projectId}/reports`, body).then((r) => r.data),
}


// ── Edition, access control, domain ownership ────────────────────────────────

export interface EditionInfo {
  edition: 'selfhosted' | 'saas'
  auth: 'local' | 'accounts'
  registration: 'first_user' | 'open' | 'invite'
  domain_verification_required: boolean
  verify_prefix: string
}

export interface AccessRequest {
  id: string
  email: string
  name: string
  company: string
  role: string | null
  message: string | null
  topic: string
  status: 'pending' | 'approved' | 'rejected'
  ip_address: string | null
  created_at: string
  reviewed_at: string | null
}

export interface AccessInvite {
  id: string
  email: string
  request_id: string | null
  expires_at: string
  used_at: string | null
  revoked_at: string | null
  created_at: string
}

export interface InviteIssued extends AccessInvite {
  invite_url: string | null
  email_sent: boolean
}

export interface AdminUser {
  id: string
  email: string
  full_name: string | null
  is_active: boolean
  is_platform_admin: boolean
  mfa_enabled?: boolean
  locked_until?: string | null
  created_at: string
  orgs?: { id: string; name: string; role: string }[]
}

/** Organization metadata a platform admin may see: no targets, findings or domain names. */
export interface AdminOrg {
  id: string
  name: string
  slug: string
  is_active: boolean
  created_at: string
  daily_scan_quota: number | null
  effective_daily_scan_quota: number
  offensive_modules_allowed: boolean
  members: { email: string; role: string }[]
  scans_24h: number
  scans_30d: number
  verified_domains: number
}

export interface VerifiedDomain {
  id: string
  domain: string
  token: string
  verified_at: string | null
  last_checked_at: string | null
  created_at: string
  txt_name: string
  txt_value: string
}

export const edition = {
  info: () => client.get<EditionInfo>('/meta').then((r) => r.data),
  lookupInvite: (token: string) =>
    client.get<{ email: string | null; valid: boolean }>(`/invites/${encodeURIComponent(token)}`).then((r) => r.data),
}

export const admin = {
  requests: (status?: string) =>
    client.get<AccessRequest[]>('/admin/access-requests', { params: status ? { status } : {} }).then((r) => r.data),
  approve: (id: string) => client.post<InviteIssued>(`/admin/access-requests/${id}/approve`).then((r) => r.data),
  reject: (id: string) => client.post<AccessRequest>(`/admin/access-requests/${id}/reject`).then((r) => r.data),
  invites: () => client.get<AccessInvite[]>('/admin/invites').then((r) => r.data),
  invite: (email: string, name: string) =>
    client.post<InviteIssued>('/admin/invites', { email, name }).then((r) => r.data),
  revokeInvite: (id: string) => client.post<AccessInvite>(`/admin/invites/${id}/revoke`).then((r) => r.data),
  users: () => client.get<AdminUser[]>('/admin/users').then((r) => r.data),
  suspend: (id: string) => client.post<AdminUser>(`/admin/users/${id}/suspend`).then((r) => r.data),
  activate: (id: string) => client.post<AdminUser>(`/admin/users/${id}/activate`).then((r) => r.data),
  setPlatformAdmin: (id: string, enabled: boolean) =>
    client.post<AdminUser>(`/admin/users/${id}/platform-admin`, { enabled }).then((r) => r.data),
  revokeSessions: (id: string) => client.post<AdminUser>(`/admin/users/${id}/revoke-sessions`).then((r) => r.data),
  resetMfa: (id: string) => client.post<AdminUser>(`/admin/users/${id}/reset-mfa`).then((r) => r.data),
  orgs: () => client.get<AdminOrg[]>('/admin/orgs').then((r) => r.data),
  updateOrg: (
    id: string,
    body: Partial<{ daily_scan_quota: number | null; offensive_modules_allowed: boolean; is_active: boolean }>,
  ) => client.patch<AdminOrg>(`/admin/orgs/${id}`, body).then((r) => r.data),
  emailLogs: () => client.get<EmailLog[]>('/admin/email-logs').then((r) => r.data),
}

export interface EmailLog {
  id: string
  recipient: string
  subject: string
  template: string
  status: 'sent' | 'failed'
  error_message: string | null
  created_at: string
}

export const domains = {
  list: (orgId: string) => client.get<VerifiedDomain[]>(`/orgs/${orgId}/domains`).then((r) => r.data),
  add: (orgId: string, domain: string) =>
    client.post<VerifiedDomain>(`/orgs/${orgId}/domains`, { domain }).then((r) => r.data),
  verify: (orgId: string, id: string) =>
    client
      .post<{ domain: VerifiedDomain; verified: boolean; txt_found: string[] }>(`/orgs/${orgId}/domains/${id}/verify`)
      .then((r) => r.data),
  remove: (orgId: string, id: string) => client.delete(`/orgs/${orgId}/domains/${id}`),
}
