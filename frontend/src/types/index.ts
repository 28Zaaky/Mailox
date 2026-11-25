// ── Auth ─────────────────────────────────────────────────────────────────────

export interface User {
  id: string
  email: string
  full_name: string | null
  is_active: boolean
  mfa_enabled: boolean
  is_platform_admin: boolean
  created_at: string
}

export interface TokenResponse {
  access_token: string
  token_type: string
  expires_in: number
}

/** POST /auth/login when the account has MFA enabled (mfa_token lives ~5 min). */
export interface MFARequiredResponse {
  mfa_required: true
  mfa_token: string
}

export type LoginResponse = TokenResponse | MFARequiredResponse

export function isMfaRequired(r: LoginResponse): r is MFARequiredResponse {
  return 'mfa_required' in r && r.mfa_required === true
}

// ── Organization ──────────────────────────────────────────────────────────────

export interface Organization {
  id: string
  name: string
  slug: string
  created_at: string
  /** Caller's role in this org (OrganizationResponse.current_user_role). */
  current_user_role?: string | null
}

export interface OrgMember {
  user_id: string
  email: string
  full_name: string | null
  role: string
  joined_at: string
}

// ── Org Settings ─────────────────────────────────────────────────────────────

export interface OrgSettings {
  org_id: string
  github_token_set: boolean
  intelx_api_key_set: boolean
  nvd_api_key_set: boolean
  canary_email: string | null
  cred_probe_enabled: boolean | null
  scan_timeout_seconds: number | null
  updated_at: string | null
}

export interface OrgSettingsUpdate {
  github_token?: string
  intelx_api_key?: string
  nvd_api_key?: string
  canary_email?: string
  cred_probe_enabled?: boolean
  scan_timeout_seconds?: number
}

// ── Scan ─────────────────────────────────────────────────────────────────────

export type ScanStatus =
  | 'pending'
  | 'queued'
  | 'running'
  | 'completed'
  | 'partial'
  | 'failed'
  | 'cancelled'

export interface EngineRun {
  id: string
  engine: string
  status: string
  started_at: string | null
  finished_at: string | null
  finding_count: number
  error_msg: string | null
}

// Scan list item — matches ScanResponse (no findings array)
export interface Scan {
  id: string
  org_id: string
  target_domain: string
  status: ScanStatus
  progress_pct: number
  current_engine: string | null
  risk_score: number | null
  finding_count: number
  created_at: string
  started_at: string | null
  completed_at: string | null
  error_msg: string | null
}

export interface BatchScanResult {
  domain: string
  scan_id: string | null
  status: 'queued' | 'rejected'
  reason?: string
}

// Scan detail — matches ScanWithFindingsResponse
export interface ScanDetail extends Scan {
  findings: ScanFinding[]
  engine_runs: EngineRun[]
}

export interface ScanFinding {
  id: string
  scan_id: string
  engine: string
  check_id: string
  title: string
  description: string
  risk_level: RiskLevel
  confidence: number
  affected_asset: string | null
  status: FindingStatus
  cvss_score: number | null
  remediation: string
  evidence: Evidence[]
  references: string[]
  created_at: string
  last_seen_at: string | null
}

// ── Findings ─────────────────────────────────────────────────────────────────

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type FindingStatus =
  | 'open'
  | 'confirmed'
  | 'in_remediation'
  | 'accepted_risk'
  | 'resolved'
  | 'false_positive'

export interface Evidence {
  type: string
  observed_value: string
  source: string
  technical_details?: Record<string, unknown>
}

export interface FindingListResponse {
  items: ScanFinding[]
  total: number
  page: number
  page_size: number
}

export interface FindingSummary {
  total: number
  by_severity: Record<RiskLevel, number>
  by_status: Record<FindingStatus, number>
  by_engine: Record<string, number>
  open_critical: number
  open_high: number
}

// ── Org Stats ────────────────────────────────────────────────────────────────

export interface OrgStats {
  total_scans: number
  active_scans: number
  open_critical: number
  open_high: number
  latest_scan_id: string | null
  latest_risk_score: number | null
  latest_risk_posture: 'critical' | 'high' | 'medium' | 'low' | 'clean' | null
}

// ── Scan Assets ──────────────────────────────────────────────────────────────

export interface MXRecord {
  priority: number
  hostname: string
}

export interface WebmailHost {
  host: string
  product: string
  version: string | null
}

export interface SMTPHost {
  host: string
  port: number
}

export interface ScanAssets {
  mx_records: MXRecord[]
  webmail_hosts: WebmailHost[]
  smtp_hosts: SMTPHost[]
}

// ── Exposed Secrets ──────────────────────────────────────────────────────────

export interface ExposedSecret {
  id: string
  scan_id: string
  source: string
  secret_type: string
  masked_value: string
  confidence: number
  affected_asset: string | null
  discovered_at: string
  status?: string
}

// ── MFA ──────────────────────────────────────────────────────────────────────

export interface MFASetupResult {
  secret: string
  otpauth_uri: string
  backup_codes: string[]
}

export interface SessionInfo {
  id: string
  ip_address: string | null
  user_agent: string | null
  created_at: string
  expires_at: string
}

// ── Projects ─────────────────────────────────────────────────────────────────

export interface Project {
  id: string
  org_id: string
  name: string
  description: string | null
  status: 'active' | 'archived' | 'closed'
  created_by: string | null
  created_at: string
  updated_at: string
}

export interface ProjectMember {
  project_id: string
  user_id: string
  role: 'project_manager' | 'analyst' | 'auditor' | 'viewer'
  granted_at: string
}

// ── Assessment Profiles ───────────────────────────────────────────────────────

export interface AssessmentProfile {
  id: string
  org_id: string | null
  project_id: string | null
  name: string
  engines: string[]
  config: Record<string, unknown>
  time_limit_seconds: number
  created_by: string | null
  created_at: string
  is_builtin: boolean
}

// ── SSE events ───────────────────────────────────────────────────────────────

export interface ScanProgressEvent {
  type: 'progress' | 'complete' | 'error' | 'heartbeat'
  scan_id?: string
  status?: ScanStatus
  progress_pct?: number
  current_engine?: string
  risk_score?: number
  error_msg?: string
}
