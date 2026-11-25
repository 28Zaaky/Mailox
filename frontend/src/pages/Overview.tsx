import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate } from 'react-router-dom'
import {
  Activity,
  BarChart2,
  ChevronRight,
  RefreshCw,
  Shield,
  Zap,
  ArrowRight,
} from 'lucide-react'
import { useAuth } from '../lib/auth'
import { findings as findingsApi, orgs as orgsApi, scans as scansApi } from '../lib/api'
import { useScanMonitor, engineLabel } from '../lib/scan-monitor'
import type { FindingStatus, OrgStats, RiskLevel, Scan, ScanFinding } from '../types'

// ── Tokens ────────────────────────────────────────────────────────────────────

const SEV_COLOR: Record<RiskLevel, string> = {
  critical: '#EF4444', high: '#EA580C', medium: '#E5A93D', low: '#36B37E', info: '#60A5FA',
}
const SEV_LABEL: Record<RiskLevel, string> = {
  critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info',
}
const STATUS_COLOR: Record<FindingStatus, string> = {
  open: '#71717A', confirmed: '#EF4444', in_remediation: '#E5A93D',
  accepted_risk: '#8B5CF6', resolved: '#36B37E', false_positive: '#3a3a44',
}
const STATUS_LABEL: Record<FindingStatus, string> = {
  open: 'Open', confirmed: 'Confirmed', in_remediation: 'In remediation',
  accepted_risk: 'Accepted risk', resolved: 'Resolved', false_positive: 'False positive',
}
const POSTURE_DATA: Record<string, { label: string; color: string; bg: string; desc: string }> = {
  critical: { label: 'Critical', color: '#EF4444', bg: 'rgba(239,68,68,0.06)',   desc: 'Critical vulnerabilities detected. Immediate remediation required.' },
  high:     { label: 'High',     color: '#EA580C', bg: 'rgba(234,88,12,0.06)',    desc: 'High-severity issues detected. Prioritize remediation.' },
  medium:   { label: 'Elevated', color: '#E5A93D', bg: 'rgba(229,169,61,0.06)',   desc: 'Medium-risk issues detected. Review and prioritize.' },
  low:      { label: 'Guarded',  color: '#36B37E', bg: 'rgba(54,179,126,0.06)',   desc: 'Low-risk issues detected. Monitor and address.' },
  clean:    { label: 'Clean',    color: '#36B37E', bg: 'rgba(54,179,126,0.06)',   desc: 'No significant security issues detected in this assessment baseline.' },
}
const SCAN_STATUS_STYLE: Record<string, { color: string; bg: string; border: string }> = {
  queued:    { color: '#71717A', bg: 'rgba(113,113,122,0.06)', border: 'rgba(113,113,122,0.2)' },
  running:   { color: '#60A5FA', bg: 'rgba(96,165,250,0.08)',  border: 'rgba(96,165,250,0.25)' },
  completed: { color: '#36B37E', bg: 'rgba(54,179,126,0.08)', border: 'rgba(54,179,126,0.25)' },
  partial:   { color: '#E5A93D', bg: 'rgba(229,169,61,0.08)', border: 'rgba(229,169,61,0.25)' },
  failed:    { color: '#EF4444', bg: 'rgba(239,68,68,0.08)',  border: 'rgba(239,68,68,0.25)' },
  cancelled: { color: '#52525B', bg: 'rgba(82,82,91,0.06)',   border: 'rgba(82,82,91,0.2)' },
}
const ENGINE_LABEL: Record<string, string> = {
  dns_auth: 'DNS Auth', smtp_discovery: 'SMTP Discovery', smtp_security: 'SMTP Security',
  tls_analysis: 'TLS Analysis', webmail_security: 'Webmail', vuln_intel: 'Vuln Intel',
  credential_exposure: 'Credential', risk_correlation: 'Risk Correlation',
}
const SEVERITY_ORDER: RiskLevel[] = ['critical', 'high', 'medium', 'low', 'info']
const LIFECYCLE_ORDER: FindingStatus[] = ['open', 'confirmed', 'in_remediation', 'resolved', 'accepted_risk', 'false_positive']

// ── Helpers ───────────────────────────────────────────────────────────────────

function relativeTime(ts: number | undefined): string {
  if (!ts) return ''
  const d = Date.now() - ts
  if (d < 60_000) return 'just now'
  if (d < 3_600_000) return `${Math.round(d / 60_000)}m ago`
  if (d < 86_400_000) return `${Math.round(d / 3_600_000)}h ago`
  return `${Math.round(d / 86_400_000)}d ago`
}
function scanDuration(scan: Scan): string | null {
  if (!scan.started_at || !scan.completed_at) return null
  const ms = new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()
  return ms < 60_000 ? `${Math.round(ms / 1000)}s` : `${Math.round(ms / 60_000)}m`
}
function dateShort(iso: string | null | undefined): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
}
function dateFull(iso: string | null | undefined): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
}
function scoreColor(s: number): string {
  if (s >= 75) return '#EF4444'
  if (s >= 50) return '#EA580C'
  if (s >= 25) return '#E5A93D'
  return '#36B37E'
}
function scoreLabel(s: number): string {
  if (s >= 75) return 'Critical'
  if (s >= 50) return 'High'
  if (s >= 25) return 'Elevated'
  if (s > 0) return 'Guarded'
  return 'Clean'
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function Overview() {
  const { currentOrg } = useAuth()
  const orgId = currentOrg?.id ?? ''
  const qc = useQueryClient()
  const { activeScans } = useScanMonitor()

  const { data: stats, isLoading: statsLoading, isRefetching, dataUpdatedAt } = useQuery({
    queryKey: ['org-stats', orgId],
    queryFn: () => orgsApi.stats(orgId),
    enabled: !!orgId,
    staleTime: 5_000,
    refetchInterval: (query) => {
      const d = query.state.data
      return d?.active_scans ? 5_000 : 30_000
    },
  })
  const { data: scanList = [], isLoading: scansLoading } = useQuery({
    queryKey: ['scans', orgId],
    queryFn: () => scansApi.list(orgId, 20, 0),
    enabled: !!orgId,
    refetchInterval: (query) => {
      const data = query.state.data ?? []
      const hasActive = data.some((s) => s.status === 'running' || s.status === 'queued')
      return hasActive ? 2_000 : 15_000
    },
  })
  const { data: summary } = useQuery({
    queryKey: ['findings-summary', orgId],
    queryFn: () => findingsApi.summary(orgId),
    enabled: !!orgId,
    staleTime: 30_000,
  })
  const { data: recentFindings } = useQuery({
    queryKey: ['findings-recent', orgId],
    queryFn: () => findingsApi.list(orgId, { page_size: 10 }),
    enabled: !!orgId,
    staleTime: 30_000,
  })

  const hasCompletedScan = !!(stats?.latest_scan_id)
  const hasValidScore = stats?.latest_risk_score !== null && stats?.latest_risk_score !== undefined
  const posture = stats?.latest_risk_posture ? POSTURE_DATA[stats.latest_risk_posture] : null
  const latestScan = scanList.find((s) => s.id === stats?.latest_scan_id) ?? null

  const trendScans = scanList
    .filter((s) => (s.status === 'completed' || s.status === 'partial') && s.risk_score !== null && s.completed_at)
    .sort((a, b) => new Date(a.completed_at!).getTime() - new Date(b.completed_at!).getTime())

  // True only when both queries finished loading and confirm zero assessments exist
  const isFullyLoaded = !statsLoading && !scansLoading
  const hasZeroAssessments = isFullyLoaded && stats !== undefined && stats.total_scans === 0 && scanList.length === 0

  function handleRefresh() {
    qc.invalidateQueries({ queryKey: ['org-stats', orgId] })
    qc.invalidateQueries({ queryKey: ['scans', orgId] })
    qc.invalidateQueries({ queryKey: ['findings-summary', orgId] })
    qc.invalidateQueries({ queryKey: ['findings-recent', orgId] })
  }

  if (hasZeroAssessments) {
    return <WorkspaceEmptyState />
  }

  return (
    <div className="page-enter" style={{ width: '100%' }}>

      {/* ── Header ── */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '16px', marginBottom: '20px', flexWrap: 'wrap' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '4px', marginBottom: '5px' }}>
            <span style={{ fontSize: '11px', color: '#52525B' }}>Workspace</span>
            <ChevronRight size={11} style={{ color: '#3a3a44' }} />
            <span style={{ fontSize: '11px', color: '#71717A' }}>Overview</span>
          </div>
          <h1 style={{ fontSize: '20px', fontWeight: 600, color: '#F5F5F5', letterSpacing: '-0.02em', lineHeight: 1.2, fontFamily: "'Space Grotesk', sans-serif", marginBottom: '3px' }}>
            Overview
          </h1>
          {dataUpdatedAt > 0 && (
            <span style={{ fontSize: '12px', color: '#3a3a44' }}>Updated {relativeTime(dataUpdatedAt)}</span>
          )}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <button onClick={handleRefresh} disabled={isRefetching} className="btn-ghost" style={{ padding: '7px 10px' }} title="Refresh">
            <RefreshCw size={13} style={{ color: '#71717A', animation: isRefetching ? 'spin 1s linear infinite' : 'none' }} />
          </button>
          <Link to="/assessments" className="btn-secondary" style={{ padding: '7px 14px', fontSize: '12px' }}>All assessments</Link>
          <Link to="/assessments/new" className="btn-primary" style={{ padding: '7px 16px', fontSize: '12px' }}>
            <Activity size={12} />
            {stats && stats.total_scans > 0 ? 'New assessment' : 'Start assessment'}
          </Link>
        </div>
      </div>

      {/* ── Active scans banner (live, only when running) ── */}
      {activeScans.length > 0 && <ActiveScansWidget scans={activeScans} />}

      {/* ── Row 1: KPI strip ── */}
      <div className="kpi-compact" style={{ marginBottom: '16px' }}>
        <CompactKPI label="Assessments"  value={stats?.total_scans}   href="/assessments"                             loading={statsLoading} />
        <CompactKPI label="Running"      value={stats?.active_scans}  href="/assessments?status=running"              accent={stats?.active_scans ? '#60A5FA' : undefined} loading={statsLoading} />
        <CompactKPI label="Critical"     value={stats?.open_critical} href="/findings?status=open&risk_level=critical" accent={stats?.open_critical ? '#EF4444' : undefined} prominent={!!(stats?.open_critical)} loading={statsLoading} />
        <CompactKPI label="High"         value={stats?.open_high}     href="/findings?status=open&risk_level=high"     accent={stats?.open_high ? '#EA580C' : undefined}     prominent={!!(stats?.open_high)}     loading={statsLoading} />
        <CompactKPI label="Findings"     value={summary?.total}       href="/findings"                                loading={!summary && statsLoading} />
      </div>

      {/* ── Row 2: Posture (65%) + Findings analytics (35%) ── */}
      <div className="posture-row" style={{ marginBottom: '16px' }}>
        <PostureCard
          stats={stats}
          loading={statsLoading}
          hasCompletedScan={hasCompletedScan}
          hasValidScore={hasValidScore}
          posture={posture}
          latestScan={latestScan}
          trendScans={trendScans}
        />
        <FindingsAnalyticsCard summary={summary} />
      </div>

      {/* ── Row 3: Assessment table (full width) ── */}
      <Card style={{ marginBottom: '16px' }}>
        <CardHeader title="Assessments" count={scanList.length} href="/assessments" />
        {scansLoading ? (
          <SkeletonRows n={3} />
        ) : scanList.length === 0 ? (
          <EmptyState icon={<BarChart2 size={20} style={{ color: '#3a3a44' }} />} title="No assessments yet" desc="Run your first scan to establish a security baseline." cta="Start assessment" href="/assessments/new" />
        ) : (
          <div style={{ overflowX: 'auto', WebkitOverflowScrolling: 'touch' as const }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: '560px' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid #1B1B1F' }}>
                  {['Target', 'Status', 'Risk', 'Findings', 'Date', 'Duration'].map((h) => (
                    <th key={h} style={{ textAlign: 'left', padding: '0 10px 10px', fontSize: '10px', letterSpacing: '0.08em', color: '#52525B', fontWeight: 500, textTransform: 'uppercase' }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {scanList.map((scan) => <ScanRow key={scan.id} scan={scan} />)}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* ── Row 4: Recent findings (50%) + Engine activity (50%) ── */}
      <div className="intel-row">
        <Card fillHeight>
          <CardHeader title="Recent findings" count={recentFindings?.total} href="/findings" />
          {!recentFindings ? (
            <SkeletonRows n={4} />
          ) : recentFindings.items.length === 0 ? (
            <EmptyState icon={<Shield size={20} style={{ color: '#3a3a44' }} />} title="No findings recorded" desc="Complete an assessment to begin tracking security findings." />
          ) : (
            <div>
              {recentFindings.items.map((f) => <FindingRow key={f.id} finding={f} />)}
            </div>
          )}
        </Card>

        <Card fillHeight>
          <CardHeader title="Engine activity" />
          {!summary ? <SkeletonRows n={4} /> : <EngineContent summary={summary} />}
        </Card>
      </div>
    </div>
  )
}

// ── ActiveScansWidget ─────────────────────────────────────────────────────────

function ActiveScansWidget({ scans }: { scans: Scan[] }) {
  const navigate = useNavigate()
  return (
    <div style={{
      marginBottom: '16px',
      border: '1px solid rgba(96,165,250,0.2)',
      borderRadius: '8px',
      background: 'rgba(96,165,250,0.04)',
      padding: '14px 20px',
      display: 'flex',
      flexDirection: 'column',
      gap: '10px',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '2px' }}>
        <span
          style={{
            width: '7px', height: '7px', borderRadius: '50%',
            background: '#60A5FA', flexShrink: 0,
            boxShadow: '0 0 8px rgba(96,165,250,0.8)',
          }}
          className="dot-pulse"
        />
        <span style={{ fontSize: '11px', fontWeight: 600, letterSpacing: '0.08em', color: '#60A5FA', textTransform: 'uppercase' }}>
          {scans.length} active scan{scans.length > 1 ? 's' : ''}
        </span>
      </div>
      {scans.map((scan) => (
        <div
          key={scan.id}
          onClick={() => navigate(`/assessments/${scan.id}`)}
          style={{ display: 'flex', alignItems: 'center', gap: '12px', cursor: 'pointer' }}
        >
          <span style={{
            fontSize: '12px', color: '#F5F5F5',
            fontFamily: 'JetBrains Mono, monospace',
            minWidth: '160px', maxWidth: '220px',
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
            flexShrink: 0,
          }}>
            {scan.target_domain}
          </span>
          {scan.current_engine && (
            <span style={{ fontSize: '10px', color: '#60A5FA', fontFamily: 'JetBrains Mono, monospace', flexShrink: 0, minWidth: '100px' }}>
              {engineLabel(scan.current_engine)}
            </span>
          )}
          <div style={{ flex: 1, height: '3px', background: '#1C1C20', borderRadius: '2px', overflow: 'hidden' }}>
            <div style={{
              height: '100%',
              width: scan.progress_pct > 0 ? `${scan.progress_pct}%` : '25%',
              background: '#60A5FA',
              borderRadius: '2px',
              transition: 'width 600ms cubic-bezier(0.23,1,0.32,1)',
              boxShadow: '0 0 6px rgba(96,165,250,0.5)',
              ...(scan.progress_pct === 0 ? {} : {}),
            }}
              className={scan.progress_pct === 0 ? 'scan-progress-bar' : ''}
            />
          </div>
          <span style={{ fontSize: '11px', color: '#60A5FA', fontFamily: 'JetBrains Mono, monospace', flexShrink: 0, minWidth: '32px', textAlign: 'right' }}>
            {scan.progress_pct > 0 ? `${scan.progress_pct}%` : '…'}
          </span>
        </div>
      ))}
    </div>
  )
}

// ── WorkspaceEmptyState ───────────────────────────────────────────────────────

function WorkspaceEmptyState() {
  return (
    <div className="page-enter" style={{ width: '100%', flex: 1, display: 'flex', flexDirection: 'column' }}>

      {/* Page title */}
      <div style={{ marginBottom: '16px', flexShrink: 0 }}>
        <h1 style={{ fontSize: '20px', fontWeight: 600, color: '#F5F5F5', letterSpacing: '-0.02em', lineHeight: 1.2, fontFamily: "'Space Grotesk', sans-serif" }}>
          Workspace
        </h1>
      </div>

      {/* Main card — fills remaining screen */}
      <div style={{
        flex: 1,
        background: '#0A0A0D', border: '1px solid #1B1B1F', borderRadius: '12px',
        display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
        position: 'relative', overflow: 'hidden', padding: '48px 24px', boxSizing: 'border-box',
      }}>
        {/* Copy */}
        <div style={{ textAlign: 'center', maxWidth: '400px', position: 'relative' }}>
          <h2 className="ws-h2" style={{
            fontSize: '30px', fontWeight: 700, color: '#F5F5F5', letterSpacing: '-0.03em',
            fontFamily: "'Space Grotesk', sans-serif", lineHeight: 1.18, marginBottom: '14px',
          }}>
            Your first assessment<br />starts here.
          </h2>
          <p style={{ fontSize: '13px', color: '#71717A', lineHeight: 1.7, marginBottom: '28px' }}>
            Understand your email infrastructure exposure in minutes.
          </p>
          <Link to="/assessments/new" className="btn-primary"
            style={{ padding: '10px 24px', fontSize: '13px', gap: '8px', display: 'inline-flex', alignItems: 'center' }}>
            <Activity size={14} />
            Start your first assessment
            <ArrowRight size={13} />
          </Link>
        </div>
      </div>

      <style>{`
        @media (max-width: 768px) { .ws-h2 { font-size: 24px !important; } }
      `}</style>
    </div>
  )
}


// ── CompactKPI ────────────────────────────────────────────────────────────────

function CompactKPI({ label, value, href, accent, prominent, loading }: {
  label: string; value: number | undefined; href: string
  accent?: string; prominent?: boolean; loading?: boolean
}) {
  if (loading) {
    return (
      <div className="card" style={{ background: '#0D0D0F', borderRadius: '7px', padding: '16px 20px', height: '88px', boxSizing: 'border-box' }}>
        <div style={{ height: '7px', width: '64px', background: '#1C1C20', borderRadius: '3px', marginBottom: '12px' }} />
        <div style={{ height: '22px', width: '40px', background: '#1C1C20', borderRadius: '3px' }} />
      </div>
    )
  }
  const neonShadow = prominent && accent && (value ?? 0) > 0
    ? `0 0 0 1px ${accent}20, 0 0 20px ${accent}18, 0 0 40px ${accent}08`
    : undefined

  return (
    <Link to={href} className="card" style={{
      display: 'flex', flexDirection: 'column', justifyContent: 'space-between',
      background: '#0D0D0F',
      borderColor: prominent && accent ? `${accent}35` : undefined,
      borderRadius: '7px', padding: '16px 20px', textDecoration: 'none',
      height: '100%', boxSizing: 'border-box', position: 'relative', overflow: 'hidden',
      transition: 'border-color 200ms, background-color 200ms, box-shadow 200ms',
      boxShadow: neonShadow,
    }}
      onMouseEnter={(e) => {
        const el = e.currentTarget as HTMLElement
        el.style.borderColor = accent ? `${accent}55` : '#3a3a44'
        el.style.backgroundColor = '#111113'
        if (accent) el.style.boxShadow = `0 0 0 1px ${accent}30, 0 0 24px ${accent}25, 0 0 48px ${accent}10`
      }}
      onMouseLeave={(e) => {
        const el = e.currentTarget as HTMLElement
        el.style.borderColor = prominent && accent ? `${accent}25` : '#242428'
        el.style.backgroundColor = '#0D0D0F'
        el.style.boxShadow = neonShadow ?? ''
      }}
    >
      {prominent && accent && (
        <div style={{
          position: 'absolute', top: 0, left: 0, right: 0, height: '2px',
          background: `linear-gradient(90deg, transparent, ${accent}cc, ${accent}80, transparent)`,
          boxShadow: `0 0 8px ${accent}60`,
        }} />
      )}
      <span style={{ fontSize: '10px', fontWeight: 500, letterSpacing: '0.07em', color: '#52525B', textTransform: 'uppercase' }}>{label}</span>
      <span style={{
        fontSize: '28px', fontWeight: 700, color: accent ?? '#A1A1AA', lineHeight: 1,
        fontFamily: "'Space Grotesk', monospace", fontVariantNumeric: 'tabular-nums',
        textShadow: prominent && accent && (value ?? 0) > 0 ? `0 0 12px ${accent}80` : undefined,
      }}>
        {value ?? '—'}
      </span>
    </Link>
  )
}

// ── PostureCard ───────────────────────────────────────────────────────────────

interface PostureCardProps {
  stats: OrgStats | undefined
  loading: boolean
  hasCompletedScan: boolean
  hasValidScore: boolean
  posture: { label: string; color: string; bg: string; desc: string } | null
  latestScan: Scan | null
  trendScans: Scan[]
}

function PostureCard({ stats, loading, hasCompletedScan, hasValidScore, posture, latestScan, trendScans }: PostureCardProps) {
  return (
    <div className="card" style={{
      background: '#0D0D0F', borderRadius: '8px', padding: '24px',
      display: 'flex', flexDirection: 'column', height: '100%', boxSizing: 'border-box',
      position: 'relative', overflow: 'hidden',
    }}>
      {posture && hasValidScore && (
        <div style={{ position: 'absolute', top: 0, right: 0, width: '240px', height: '50%', background: `radial-gradient(ellipse at top right, ${posture.color}06, transparent 65%)`, pointerEvents: 'none' }} />
      )}

      <div style={{ marginBottom: '16px', flexShrink: 0 }}>
        <span style={{ fontSize: '11px', fontWeight: 600, letterSpacing: '0.08em', color: '#71717A', textTransform: 'uppercase' }}>Security Posture</span>
      </div>

      {loading ? (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ height: '48px', width: '160px', background: '#1C1C20', borderRadius: '5px' }} />
          <div style={{ height: '8px', width: '240px', background: '#1C1C20', borderRadius: '3px' }} />
          <div style={{ height: '8px', width: '180px', background: '#1C1C20', borderRadius: '3px' }} />
          <div style={{ flex: 1, background: '#1C1C20', borderRadius: '5px', marginTop: '12px' }} />
        </div>
      ) : !hasCompletedScan ? (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
          <div style={{ fontSize: '20px', fontWeight: 600, color: '#52525B', fontFamily: "'Space Grotesk', sans-serif", marginBottom: '8px' }}>
            Assessment baseline unavailable
          </div>
          <p style={{ fontSize: '12px', color: '#71717A', lineHeight: 1.6, maxWidth: '400px', marginBottom: '16px' }}>
            Complete an assessment to calculate your organization's security posture.
          </p>
          <Link to="/assessments/new" className="btn-primary" style={{ display: 'inline-flex', padding: '8px 18px', fontSize: '12px' }}>
            <Activity size={12} /> Start first assessment
          </Link>
        </div>
      ) : !hasValidScore ? (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
            <span style={{ fontSize: '20px', fontWeight: 600, color: '#52525B', fontFamily: "'Space Grotesk', sans-serif" }}>Score unavailable</span>
            <span style={{ fontSize: '10px', fontWeight: 600, color: '#E5A93D', background: 'rgba(229,169,61,0.1)', border: '1px solid rgba(229,169,61,0.2)', padding: '2px 8px', borderRadius: '20px' }}>INCOMPLETE</span>
          </div>
          <p style={{ fontSize: '12px', color: '#71717A', lineHeight: 1.6 }}>
            Assessment completed but risk correlation did not produce a score.
          </p>
        </div>
      ) : (
        <>
          {/* Score + gauge row */}
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '20px', marginBottom: '16px', flexShrink: 0 }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', marginBottom: '4px' }}>
                <span style={{
                  fontSize: '56px', fontWeight: 700, color: posture?.color ?? '#F5F5F5', lineHeight: 1,
                  fontFamily: "'Space Grotesk', 'JetBrains Mono', monospace", fontVariantNumeric: 'tabular-nums',
                  textShadow: posture ? `0 0 20px ${posture.color}60, 0 0 40px ${posture.color}25` : undefined,
                }}>
                  {Math.round(stats!.latest_risk_score!)}
                </span>
                <span style={{ fontSize: '18px', color: '#3a3a44', fontWeight: 400 }}>/100</span>
                {posture && (
                  <span style={{
                    fontSize: '10px', fontWeight: 700, color: posture.color,
                    background: posture.bg, border: `1px solid ${posture.color}40`,
                    padding: '3px 10px', borderRadius: '20px', letterSpacing: '0.08em',
                    boxShadow: `0 0 10px ${posture.color}30`,
                  }}>
                    {posture.label.toUpperCase()}
                  </span>
                )}
              </div>
              <p style={{ fontSize: '12px', color: '#71717A', lineHeight: 1.5, marginBottom: '8px', maxWidth: '320px' }}>
                {posture?.desc ?? 'Security assessment baseline established.'}
              </p>
              {latestScan && (
                <span style={{ fontSize: '11px', color: '#52525B' }}>
                  Last assessment: <span style={{ color: '#71717A', fontFamily: 'JetBrains Mono, monospace' }}>{dateFull(latestScan.completed_at ?? latestScan.created_at)}</span>
                </span>
              )}
            </div>
            <div style={{ flexShrink: 0 }}>
              <ScoreGauge score={Math.round(stats!.latest_risk_score!)} postureKey={stats!.latest_risk_posture!} size={148} />
            </div>
          </div>

          {/* Trend chart */}
          <div style={{ flexShrink: 0, borderTop: '1px solid #1B1B1F', paddingTop: '14px', marginTop: '4px' }}>
            <div style={{ fontSize: '9px', fontWeight: 600, letterSpacing: '0.1em', color: '#3a3a44', textTransform: 'uppercase', marginBottom: '8px' }}>
              Score trend
            </div>
            <TrendChart scans={trendScans} postureKey={stats!.latest_risk_posture!} />
          </div>
        </>
      )}
    </div>
  )
}

// ── TrendChart ────────────────────────────────────────────────────────────────

function TrendChart({ scans, postureKey }: { scans: Scan[]; postureKey: string }) {
  const [tooltip, setTooltip] = useState<{ xPct: number; yPct: number; label: string } | null>(null)

  if (scans.length < 2) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '56px' }}>
        <span style={{ fontSize: '11px', color: '#3a3a44' }}>
          {scans.length === 0
            ? 'No completed assessments yet'
            : '1 more assessment needed to show trend'}
        </span>
      </div>
    )
  }

  const colorMap: Record<string, string> = { critical: '#EF4444', high: '#EA580C', medium: '#E5A93D', low: '#36B37E', clean: '#36B37E' }
  const color = colorMap[postureKey] ?? '#36B37E'

  const W = 400, H = 80, PX = 8, PY = 8
  const dates = scans.map((s) => new Date(s.completed_at!).getTime())
  const minDate = Math.min(...dates), maxDate = Math.max(...dates)
  const dateRange = maxDate - minDate || 1
  const useEven = dateRange < 3_600_000

  const pts = scans.map((s, i) => {
    const xRaw = useEven ? (scans.length > 1 ? i / (scans.length - 1) : 0.5) : (dates[i] - minDate) / dateRange
    return {
      x: PX + xRaw * (W - PX * 2),
      y: PY + (1 - s.risk_score! / 100) * (H - PY * 2),
      score: s.risk_score!,
      date: s.completed_at!,
    }
  })

  const linePath = pts.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ')
  const areaPath = `${linePath} L${pts[pts.length - 1].x.toFixed(1)},${(H - PY).toFixed(1)} L${pts[0].x.toFixed(1)},${(H - PY).toFixed(1)} Z`
  const gridYs = [25, 50, 75].map((s) => PY + (1 - s / 100) * (H - PY * 2))

  return (
    <div style={{ position: 'relative', width: '100%' }}>
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" height="76" style={{ display: 'block', overflow: 'visible' }}
        onMouseLeave={() => setTooltip(null)}>
        {gridYs.map((y, i) => (
          <line key={i} x1={PX} y1={y} x2={W - PX} y2={y} stroke="#1C1C20" strokeWidth="1" />
        ))}
        <path d={areaPath} fill={color} opacity="0.04" />
        <path d={linePath} fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
          style={{ filter: `drop-shadow(0 0 4px ${color}80)` }} />
        {pts.map((p, i) => (
          <g key={i} onMouseEnter={() => setTooltip({ xPct: (p.x / W) * 100, yPct: (p.y / H) * 100, label: `${Math.round(p.score)} — ${dateShort(p.date)}` })}>
            <circle cx={p.x} cy={p.y} r="6" fill="transparent" />
            <circle cx={p.x} cy={p.y} r="2.5" fill={color} opacity="0.9" />
          </g>
        ))}
      </svg>
      {tooltip && (
        <div style={{
          position: 'absolute', left: `calc(${tooltip.xPct}% + 6px)`, top: `${tooltip.yPct}%`,
          transform: 'translateY(-50%)',
          background: '#161619', border: '1px solid #242428', borderRadius: '5px',
          padding: '4px 8px', fontSize: '11px', color: '#F5F5F5',
          pointerEvents: 'none', whiteSpace: 'nowrap', zIndex: 10,
          fontFamily: 'JetBrains Mono, monospace',
        }}>
          {tooltip.label}
        </div>
      )}
    </div>
  )
}

// ── ScoreGauge ────────────────────────────────────────────────────────────────

function ScoreGauge({ score, postureKey, size = 180 }: { score: number; postureKey: string; size?: number }) {
  const r = size * 0.39, cx = size / 2, cy = size / 2
  const circumference = 2 * Math.PI * r
  const arcLength = circumference * 0.75
  const fillLength = arcLength * (Math.min(Math.max(score, 0), 100) / 100)
  const fillGap = circumference - fillLength
  const colorMap: Record<string, string> = { critical: '#EF4444', high: '#EA580C', medium: '#E5A93D', low: '#36B37E', clean: '#36B37E' }
  const color = colorMap[postureKey] ?? '#36B37E'
  const label = (POSTURE_DATA[postureKey]?.label ?? postureKey).toUpperCase()
  const sw = size * 0.067

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}
      style={{ display: 'block', filter: score > 0 ? `drop-shadow(0 0 6px ${color}60)` : 'none' }}
      aria-label={`Security score: ${score}/100`}>
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="#1C1C20" strokeWidth={sw}
        strokeDasharray={`${arcLength} ${circumference - arcLength}`}
        transform={`rotate(135 ${cx} ${cy})`} strokeLinecap="round" />
      {score > 0 && (
        <circle cx={cx} cy={cy} r={r} fill="none" stroke={color} strokeWidth={sw}
          strokeDasharray={`${fillLength} ${fillGap}`}
          transform={`rotate(135 ${cx} ${cy})`} strokeLinecap="round"
          style={{ transition: 'stroke-dasharray 800ms cubic-bezier(0.23,1,0.32,1)' }} />
      )}
      <text x={cx} y={cy - size * 0.03} textAnchor="middle" dominantBaseline="middle"
        fill="#F5F5F5" fontSize={size * 0.165} fontWeight="700"
        fontFamily="'Space Grotesk', 'JetBrains Mono', monospace"
        style={{ fontVariantNumeric: 'tabular-nums' }}>
        {score}
      </text>
      <text x={cx} y={cy + size * 0.11} textAnchor="middle" dominantBaseline="middle"
        fill={color} fontSize={size * 0.05} fontWeight="600"
        fontFamily="'Space Grotesk', sans-serif" letterSpacing="2">
        {label}
      </text>
    </svg>
  )
}

// ── FindingsAnalyticsCard ─────────────────────────────────────────────────────

function FindingsAnalyticsCard({ summary }: { summary: ReturnType<typeof Object.create> | undefined }) {
  const hasData = summary && summary.total > 0
  return (
    <div className="card" style={{
      background: '#0D0D0F', borderRadius: '8px', padding: '24px',
      display: 'flex', flexDirection: 'column', height: '100%', boxSizing: 'border-box',
    }}>
      <div style={{ marginBottom: '16px', flexShrink: 0 }}>
        <span style={{ fontSize: '11px', fontWeight: 600, letterSpacing: '0.08em', color: '#71717A', textTransform: 'uppercase' }}>Severity</span>
      </div>
      <div style={{ flex: 1 }}>
        {!summary ? (
          <SkeletonRows n={5} />
        ) : !hasData ? (
          <EmptyState icon={<Zap size={18} style={{ color: '#3a3a44' }} />} title="No findings" desc="No security findings recorded." />
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px' }}>
            {SEVERITY_ORDER.map((sev) => {
              const count = summary.by_severity[sev] ?? 0
              const active = count > 0
              const col = SEV_COLOR[sev]
              return (
                <Link key={sev} to={`/findings?risk_level=${sev}`}
                  style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    padding: '10px 12px',
                    background: active ? `${col}09` : '#111113',
                    border: `1px solid ${active ? `${col}28` : '#1C1C20'}`,
                    borderRadius: '8px', textDecoration: 'none',
                    transition: 'border-color 150ms, background-color 150ms',
                    gridColumn: sev === 'info' ? '1 / -1' : undefined,
                  }}
                  onMouseEnter={(e) => {
                    const el = e.currentTarget as HTMLElement
                    el.style.backgroundColor = active ? `${col}14` : '#161619'
                    el.style.borderColor = active ? `${col}45` : '#242428'
                  }}
                  onMouseLeave={(e) => {
                    const el = e.currentTarget as HTMLElement
                    el.style.backgroundColor = active ? `${col}09` : '#111113'
                    el.style.borderColor = active ? `${col}28` : '#1C1C20'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <div style={{ width: '7px', height: '7px', borderRadius: '2px', background: col, opacity: active ? 1 : 0.2, flexShrink: 0 }} />
                    <span style={{ fontSize: '11px', fontWeight: 500, color: active ? '#A1A1AA' : '#52525B' }}>{SEV_LABEL[sev]}</span>
                  </div>
                  <span style={{
                    fontSize: '18px', fontWeight: 700,
                    color: active ? col : '#3a3a44',
                    fontFamily: "'Space Grotesk', monospace", fontVariantNumeric: 'tabular-nums', lineHeight: 1,
                  }}>
                    {count}
                  </span>
                </Link>
              )
            })}
          </div>
        )}
      </div>

      {hasData && (
        <>
          <div style={{ borderTop: '1px solid #1B1B1F', margin: '16px 0 14px', flexShrink: 0 }} />
          <div style={{ marginBottom: '12px', flexShrink: 0 }}>
            <span style={{ fontSize: '11px', fontWeight: 600, letterSpacing: '0.08em', color: '#71717A', textTransform: 'uppercase' }}>Lifecycle</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px' }}>
            {LIFECYCLE_ORDER
              .filter((s) => (summary.by_status?.[s] ?? 0) > 0)
              .map((s) => {
                const count = summary.by_status?.[s] ?? 0
                const col = STATUS_COLOR[s]
                return (
                  <Link key={s} to={`/findings?status=${s}`}
                    style={{
                      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                      padding: '8px 11px',
                      background: `${col}08`,
                      border: `1px solid ${col}25`,
                      borderRadius: '8px', textDecoration: 'none',
                      transition: 'border-color 150ms, background-color 150ms',
                    }}
                    onMouseEnter={(e) => {
                      const el = e.currentTarget as HTMLElement
                      el.style.backgroundColor = `${col}12`
                      el.style.borderColor = `${col}40`
                    }}
                    onMouseLeave={(e) => {
                      const el = e.currentTarget as HTMLElement
                      el.style.backgroundColor = `${col}08`
                      el.style.borderColor = `${col}25`
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: col, flexShrink: 0 }} />
                      <span style={{ fontSize: '10px', fontWeight: 500, color: '#A1A1AA', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{STATUS_LABEL[s]}</span>
                    </div>
                    <span style={{ fontSize: '14px', fontWeight: 700, color: col, fontFamily: "'Space Grotesk', monospace", fontVariantNumeric: 'tabular-nums', lineHeight: 1 }}>
                      {count}
                    </span>
                  </Link>
                )
              })}
          </div>
        </>
      )}
    </div>
  )
}

// ── EngineContent ─────────────────────────────────────────────────────────────

function EngineContent({ summary }: { summary: ReturnType<typeof Object.create> | undefined }) {
  const engines = summary?.by_engine
    ? Object.entries(summary.by_engine as Record<string, number>).sort(([, a], [, b]) => b - a)
    : []
  const max = engines.length > 0 ? Math.max(...engines.map(([, c]) => c)) : 0

  if (engines.length === 0) {
    return <EmptyState icon={<Zap size={18} style={{ color: '#3a3a44' }} />} title="No engine data" desc="Run an assessment to see finding distribution by engine." />
  }

  return (
    <div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
        {engines.slice(0, 8).map(([engine, count]) => {
          const pct = max > 0 ? Math.round((count / max) * 100) : 0
          return (
            <Link key={engine} to={`/findings?engine=${engine}`} style={{ display: 'flex', alignItems: 'center', gap: '10px', textDecoration: 'none' }}>
              <div style={{ width: '7px', height: '7px', borderRadius: '50%', background: '#E53935', opacity: 0.5, flexShrink: 0 }} />
              <span style={{ fontSize: '11px', color: '#A1A1AA', width: '120px', flexShrink: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {ENGINE_LABEL[engine] ?? engine}
              </span>
              <div style={{ flex: 1, height: '3px', background: '#1C1C20', borderRadius: '2px', overflow: 'hidden' }}>
                <div style={{ height: '100%', width: `${pct}%`, background: '#E53935', borderRadius: '2px', opacity: 0.4, transition: 'width 500ms cubic-bezier(0.23,1,0.32,1)' }} />
              </div>
              <span style={{ fontSize: '11px', color: '#A1A1AA', fontFamily: 'JetBrains Mono, monospace', width: '20px', textAlign: 'right', flexShrink: 0 }}>
                {count}
              </span>
            </Link>
          )
        })}
      </div>
      <p style={{ fontSize: '10px', color: '#3a3a44', marginTop: '14px', lineHeight: 1.5 }}>
        Finding distribution by detection engine. Does not reflect engine execution status.
      </p>
    </div>
  )
}

// ── Card & CardHeader ─────────────────────────────────────────────────────────

function Card({ children, style, fillHeight }: { children: React.ReactNode; style?: React.CSSProperties; fillHeight?: boolean }) {
  return (
    <div
      className="card glow-card"
      style={{
        background: '#0D0D0F', borderRadius: '8px', padding: '24px',
        display: fillHeight ? 'flex' : undefined,
        flexDirection: fillHeight ? 'column' as const : undefined,
        height: fillHeight ? '100%' : undefined,
        boxSizing: fillHeight ? 'border-box' as const : undefined,
        position: 'relative',
        ...style,
      }}
    >
      {children}
    </div>
  )
}

function CardHeader({ title, count, href }: { title: string; count?: number; href?: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px', flexShrink: 0 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        <span style={{ fontSize: '11px', fontWeight: 600, letterSpacing: '0.08em', color: '#71717A', textTransform: 'uppercase' }}>{title}</span>
        {count !== undefined && count > 0 && (
          <span style={{ fontSize: '10px', color: '#52525B', background: '#1C1C20', border: '1px solid #242428', padding: '1px 7px', borderRadius: '20px' }}>{count}</span>
        )}
      </div>
      {href && (
        <Link to={href} style={{ fontSize: '11px', color: '#52525B', textDecoration: 'none', transition: 'color 150ms' }}
          onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.color = '#A1A1AA' }}
          onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.color = '#52525B' }}
        >View all →</Link>
      )}
    </div>
  )
}

// ── ScanRow ───────────────────────────────────────────────────────────────────

function ScanRow({ scan }: { scan: Scan }) {
  const ss = SCAN_STATUS_STYLE[scan.status] ?? SCAN_STATUS_STYLE.queued
  const rScore = scan.risk_score !== null ? Math.round(scan.risk_score) : null
  const rColor = rScore !== null ? scoreColor(rScore) : '#52525B'
  const d = scanDuration(scan)
  const navigate = useNavigate()

  return (
    <tr className="table-row-neon" style={{ borderBottom: '1px solid #111113', cursor: 'pointer', transition: 'background-color 150ms' }}
      onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.backgroundColor = '#131316' }}
      onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.backgroundColor = '' }}
      onClick={() => navigate(`/assessments/${scan.id}`)}
    >
      <td style={{ padding: '12px 10px' }}>
        <span style={{ fontSize: '12px', color: '#F5F5F5', fontFamily: 'JetBrains Mono, monospace', display: 'block', maxWidth: '220px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {scan.target_domain}
        </span>
        {scan.status === 'running' && (
          <div style={{ marginTop: '5px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <div style={{ flex: 1, height: '3px', background: '#1C1C20', borderRadius: '2px', overflow: 'hidden', maxWidth: '140px' }}>
              <div
                className={scan.progress_pct > 0 ? '' : 'scan-progress-bar'}
                style={{
                  height: '100%',
                  width: scan.progress_pct > 0 ? `${scan.progress_pct}%` : '30%',
                  background: scan.progress_pct > 0 ? 'var(--color-accent)' : undefined,
                  borderRadius: '2px',
                  transition: 'width 600ms cubic-bezier(0.23,1,0.32,1)',
                  boxShadow: '0 0 6px rgba(var(--color-accent-rgb, 229,57,53), 0.6)',
                }}
              />
            </div>
            {scan.current_engine && <span style={{ fontSize: '10px', color: '#60A5FA', fontFamily: 'JetBrains Mono, monospace' }}>{scan.current_engine}</span>}
          </div>
        )}
      </td>
      <td style={{ padding: '12px 10px' }}>
        <span style={{ fontSize: '11px', fontWeight: 500, color: ss.color, background: ss.bg, border: `1px solid ${ss.border}`, padding: '4px 10px', borderRadius: '20px', display: 'inline-flex', alignItems: 'center', gap: '5px' }}>
          <span
            className={scan.status === 'running' ? 'dot-pulse' : ''}
            style={{ width: '6px', height: '6px', borderRadius: '50%', background: ss.color, flexShrink: 0, color: ss.color }}
          />
          {scan.status === 'running' && scan.progress_pct > 0 ? `${scan.status} ${scan.progress_pct}%` : scan.status}
        </span>
      </td>
      <td style={{ padding: '12px 10px' }}>
        {rScore !== null ? (
          <div style={{ display: 'flex', alignItems: 'baseline', gap: '4px' }}>
            <span style={{ fontSize: '13px', fontWeight: 700, color: rColor, fontFamily: 'JetBrains Mono, monospace', fontVariantNumeric: 'tabular-nums' }}>{rScore}</span>
            <span style={{ fontSize: '10px', color: rColor, opacity: 0.6 }}>{scoreLabel(rScore)}</span>
          </div>
        ) : <span style={{ fontSize: '12px', color: '#3a3a44' }}>—</span>}
      </td>
      <td style={{ padding: '12px 10px' }}>
        <span style={{ fontSize: '12px', color: scan.finding_count > 0 ? '#A1A1AA' : '#52525B', fontFamily: 'JetBrains Mono, monospace' }}>{scan.finding_count}</span>
      </td>
      <td style={{ padding: '12px 10px' }}>
        <span style={{ fontSize: '11px', color: '#52525B' }}>{dateShort(scan.started_at ?? scan.created_at)}</span>
      </td>
      <td style={{ padding: '12px 10px' }}>
        <span style={{ fontSize: '11px', color: '#3a3a44', fontFamily: 'JetBrains Mono, monospace' }}>{d ?? '—'}</span>
      </td>
    </tr>
  )
}

// ── FindingRow ────────────────────────────────────────────────────────────────

function FindingRow({ finding }: { finding: ScanFinding }) {
  const sevColor = SEV_COLOR[finding.risk_level as RiskLevel] ?? '#71717A'
  const ts = finding.last_seen_at ?? finding.created_at
  const rel = relativeTime(new Date(ts).getTime())

  return (
    <Link to={`/findings/${finding.id}`}
      style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', padding: '10px 10px', margin: '0 -10px', borderRadius: '5px', textDecoration: 'none', transition: 'background-color 150ms', borderBottom: '1px solid #111113' }}
      onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.backgroundColor = '#161619' }}
      onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.backgroundColor = '' }}
    >
      <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: sevColor, flexShrink: 0, marginTop: '5px' }} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: '12px', color: '#F5F5F5', marginBottom: '2px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {finding.title}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '5px', flexWrap: 'wrap' }}>
          {finding.affected_asset && <span style={{ fontSize: '10px', color: '#52525B', fontFamily: 'JetBrains Mono, monospace' }}>{finding.affected_asset}</span>}
          {finding.affected_asset && <span style={{ fontSize: '10px', color: '#3a3a44' }}>·</span>}
          <span style={{ fontSize: '10px', color: '#52525B' }}>{ENGINE_LABEL[finding.engine] ?? finding.engine}</span>
          <span style={{ fontSize: '10px', color: '#3a3a44' }}>·</span>
          <span style={{ fontSize: '10px', color: '#3a3a44' }}>{rel}</span>
        </div>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
        <span style={{ fontSize: '9px', fontWeight: 600, letterSpacing: '0.1em', color: sevColor, background: `${sevColor}10`, border: `1px solid ${sevColor}25`, padding: '2px 6px', borderRadius: '20px', textTransform: 'uppercase' }}>
          {finding.risk_level}
        </span>
        {finding.status && (
          <span style={{ fontSize: '10px', color: '#52525B' }}>{STATUS_LABEL[finding.status as FindingStatus] ?? finding.status}</span>
        )}
      </div>
    </Link>
  )
}

// ── EmptyState ────────────────────────────────────────────────────────────────

function EmptyState({ icon, title, desc, cta, href }: { icon: React.ReactNode; title: string; desc: string; cta?: string; href?: string }) {
  return (
    <div style={{ textAlign: 'center', padding: '20px 12px' }}>
      <div style={{ marginBottom: '8px', display: 'flex', justifyContent: 'center' }}>{icon}</div>
      <div style={{ fontSize: '12px', color: '#A1A1AA', marginBottom: '4px', fontWeight: 500 }}>{title}</div>
      <div style={{ fontSize: '11px', color: '#52525B', lineHeight: 1.6, marginBottom: cta ? '14px' : 0 }}>{desc}</div>
      {cta && href && (
        <Link to={href} className="btn-primary" style={{ display: 'inline-flex', padding: '7px 16px', fontSize: '12px' }}>
          <Activity size={12} />{cta}
        </Link>
      )}
    </div>
  )
}

// ── SkeletonRows ──────────────────────────────────────────────────────────────

function SkeletonRows({ n }: { n: number }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
      {Array.from({ length: n }, (_, i) => (
        <div key={i} style={{ display: 'flex', gap: '10px', padding: '7px 0', alignItems: 'center' }}>
          <div style={{ width: '120px', height: '9px', background: '#1C1C20', borderRadius: '3px' }} />
          <div style={{ width: '56px', height: '9px', background: '#1C1C20', borderRadius: '3px' }} />
          <div style={{ width: '36px', height: '9px', background: '#1C1C20', borderRadius: '3px' }} />
        </div>
      ))}
    </div>
  )
}
