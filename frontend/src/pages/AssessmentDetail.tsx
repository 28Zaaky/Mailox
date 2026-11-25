import React, { useEffect, useRef, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query'
import { ArrowLeft, Ban, ChevronDown, ChevronRight, FileText } from 'lucide-react'
import { toast } from 'sonner'
import { PageHeader } from '../components/Layout'
import { RiskScore } from '../components/RiskScore'
import { ScanStatusBadge, FindingStatusBadge } from '../components/StatusBadge'
import { SeverityBadge } from '../components/SeverityBadge'
import { ProviderPanel } from '../components/ProviderPanel'
import { ScanHistoryTimeline } from '../components/ScanHistoryTimeline'
import { useAuth } from '../lib/auth'
import { scans as scansApi, findings as findingsApi } from '../lib/api'
import type { ScanDetail, ScanFinding, ScanProgressEvent, EngineRun, FindingStatus } from '../types'

export default function AssessmentDetail() {
  const { scanId } = useParams<{ scanId: string }>()
  const { currentOrg } = useAuth()
  const orgId = currentOrg?.id ?? ''
  const qc = useQueryClient()

  const { data: scan, isLoading } = useQuery<ScanDetail>({
    queryKey: ['scan', orgId, scanId],
    queryFn: () => scansApi.get(orgId, scanId!),
    enabled: !!orgId && !!scanId,
    refetchInterval: (query) => {
      const s = query.state.data?.status
      return s === 'running' || s === 'queued' ? 3000 : false
    },
  })

  // SSE live progress
  const esRef = useRef<EventSource | null>(null)
  const [liveProgress, setLiveProgress] = useState<number | null>(null)
  const [liveEngine, setLiveEngine] = useState<string | null>(null)

  useEffect(() => {
    if (!scan || !orgId || !scanId) return
    if (scan.status !== 'running' && scan.status !== 'queued') return

    let cancelled = false
    let es: EventSource | null = null

    const startStream = async () => {
      let sseToken: string
      try {
        const result = await scansApi.createStreamToken(orgId, scanId)
        sseToken = result.sse_token
      } catch {
        return
      }
      if (cancelled) return

      const url = scansApi.streamUrl(orgId, scanId, sseToken)
      es = new EventSource(url)
      esRef.current = es

      es.onmessage = (e) => {
        try {
          const event: ScanProgressEvent = JSON.parse(e.data)
          if (event.type === 'progress') {
            setLiveProgress(event.progress_pct ?? null)
            setLiveEngine(event.current_engine ?? null)
          }
          if (event.type === 'complete' || event.type === 'error') {
            es!.close()
            qc.invalidateQueries({ queryKey: ['scan', orgId, scanId] })
            qc.invalidateQueries({ queryKey: ['scans', orgId] })
          }
        } catch {}
      }
      es.onerror = () => es!.close()
    }

    startStream()

    return () => {
      cancelled = true
      es?.close()
      esRef.current?.close()
    }
  }, [scan?.status, orgId, scanId, qc])

  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set())

  const cancelMutation = useMutation({
    mutationFn: () => scansApi.cancel(orgId, scanId!),
    onMutate: () => {
      qc.setQueryData(['scan', orgId, scanId], (old: ScanDetail | undefined) =>
        old ? { ...old, status: 'cancelled' as const } : old
      )
      qc.setQueryData(['scans', orgId], (old: ScanDetail[] | undefined) =>
        old?.map((s) => s.id === scanId ? { ...s, status: 'cancelled' as const } : s) ?? []
      )
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scan', orgId, scanId] })
      qc.invalidateQueries({ queryKey: ['scans', orgId] })
      qc.invalidateQueries({ queryKey: ['org-stats', orgId] })
      toast.success('Scan cancelled')
    },
    onError: () => {
      qc.invalidateQueries({ queryKey: ['scan', orgId, scanId] })
      toast.error('Failed to cancel scan')
    },
  })

  if (isLoading) return <AssessmentSkeleton />
  if (!scan) {
    return (
      <div className="card p-8 text-center">
        <div style={{ fontSize: '32px', marginBottom: '12px' }}>🔍</div>
        <div className="text-sm text-text-primary font-medium mb-1">Scan not found</div>
        <div className="text-xs text-text-muted mb-4">This scan may have been deleted or you lack access.</div>
        <Link to="/assessments" className="btn-secondary text-xs">← Back to Assessments</Link>
      </div>
    )
  }

  const progress = liveProgress ?? scan.progress_pct
  const engine = liveEngine ?? scan.current_engine
  const isActive = scan.status === 'running' || scan.status === 'queued'

  return (
    <div>
      <PageHeader
        title={scan.target_domain}
        subtitle={`Scan ID: ${scan.id}`}
        action={
          <div className="flex items-center gap-2">
            {isActive && (
              <button
                className="btn-secondary flex items-center gap-1.5 text-sm"
                onClick={() => cancelMutation.mutate()}
                disabled={cancelMutation.isPending}
                title="Cancel scan"
              >
                <Ban size={13} />
                Cancel
              </button>
            )}
            <Link
              to={`/reports?scan_id=${scan.id}`}
              className="btn-secondary flex items-center gap-1.5 text-sm"
            >
              <FileText size={13} />
              Report
            </Link>
            <Link to="/assessments" className="btn-ghost flex items-center gap-1.5 text-sm">
              <ArrowLeft size={13} />
              Back
            </Link>
          </div>
        }
      />

      {/* Summary cards */}
      <div className="card p-4 mb-4" style={{ display: 'flex', flexWrap: 'wrap', gap: '28px', alignItems: 'flex-start' }}>
        <StatCard label="Status"><ScanStatusBadge status={scan.status} /></StatCard>
        <StatCard label="Risk Score"><RiskScore score={scan.risk_score} size="md" showLabel /></StatCard>
        <StatCard label="Posture">
          <span style={{ fontWeight: 700, fontSize: '14px', color: postureColor(scan.risk_score) }}>
            {postureLabel(scan.risk_score)}
          </span>
        </StatCard>
        <StatCard label="Findings">
          <span className="font-mono text-lg font-bold text-text-primary">{scan.findings.length}</span>
        </StatCard>
        {(scan.started_at || scan.completed_at) && (
          <StatCard label="Duration">
            <span className="font-mono text-sm text-text-secondary">
              {fmtScanDuration(scan.started_at, scan.completed_at)}
            </span>
          </StatCard>
        )}
        {scan.completed_at && (
          <StatCard label="Completed">
            <span className="text-xs font-mono text-text-secondary">
              {new Date(scan.completed_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}
            </span>
          </StatCard>
        )}
      </div>

      {/* Findings by engine breakdown */}
      {scan.findings.length > 0 && <FindingsByEngine findings={scan.findings} />}

      {/* Provider / infrastructure panel */}
      <ProviderPanel findings={scan.findings} />

      {/* Scan history for this domain */}
      <ScanHistoryTimeline
        domain={scan.target_domain}
        orgId={orgId}
        currentScanId={scan.id}
      />

      {/* Engine runs — shown always (active + completed) */}
      {(isActive || scan.engine_runs.length > 0) && (
        <EngineRuns scan={scan} progress={progress ?? 0} isActive={isActive} engine={engine} />
      )}

      {/* Findings */}
      <div className="card">
        <div className="px-4 py-2.5 border-b border-border flex items-center justify-between">
          <span className="label">Findings ({scan.findings.length})</span>
          {scan.findings.length > 0 && (
            <div className="flex gap-2">
              <button
                onClick={() => setExpandedFindings(new Set(scan.findings.map(f => f.id)))}
                className="text-xs text-text-muted hover:text-text-primary transition-colors"
                style={{ letterSpacing: '0.5px' }}
              >
                expand all
              </button>
              <span className="text-text-muted" style={{ fontSize: '10px' }}>·</span>
              <button
                onClick={() => setExpandedFindings(new Set())}
                className="text-xs text-text-muted hover:text-text-primary transition-colors"
                style={{ letterSpacing: '0.5px' }}
              >
                collapse all
              </button>
            </div>
          )}
        </div>
        {scan.findings.length === 0 ? (
          <div className="px-4 py-8 text-center text-text-muted text-sm">
            {isActive ? 'Scan in progress…' : 'No findings'}
          </div>
        ) : (
          <div className="divide-y divide-border/50">
            {scan.findings
              .slice()
              .sort((a, b) => {
                const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
                return (order[a.risk_level] ?? 9) - (order[b.risk_level] ?? 9)
              })
              .map((f) => (
                <FindingRow
                  key={f.id}
                  finding={f}
                  orgId={orgId}
                  expanded={expandedFindings.has(f.id)}
                  onToggle={() =>
                    setExpandedFindings(prev => {
                      const next = new Set(prev)
                      next.has(f.id) ? next.delete(f.id) : next.add(f.id)
                      return next
                    })
                  }
                />
              ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function postureLabel(score: number | null): string {
  if (score === null) return '—'
  if (score >= 75) return 'Critical'
  if (score >= 50) return 'High'
  if (score >= 25) return 'Medium'
  if (score > 0) return 'Low'
  return 'Clean'
}

function postureColor(score: number | null): string {
  if (score === null) return '#6b7280'
  if (score >= 75) return '#dc2626'
  if (score >= 50) return '#ea580c'
  if (score >= 25) return '#d97706'
  if (score > 0) return '#2563eb'
  return '#16a34a'
}

function fmtScanDuration(start: string | null, end: string | null): string {
  if (!start) return '—'
  const ms = (end ? new Date(end).getTime() : Date.now()) - new Date(start).getTime()
  if (ms < 60000) return `${Math.round(ms / 1000)}s`
  const m = Math.floor(ms / 60000)
  const s = Math.floor((ms % 60000) / 1000)
  return s > 0 ? `${m}m ${s}s` : `${m}m`
}

// ── Skeleton ──────────────────────────────────────────────────────────────────

function AssessmentSkeleton() {
  const bar = (w: number, h = 14) => (
    <div style={{ width: w, height: h, borderRadius: 4, background: '#1a1a1f', flexShrink: 0 }} />
  )
  return (
    <div style={{ animation: 'pulse 1.6s ease-in-out infinite' }}>
      <style>{`@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.45} }`}</style>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        {bar(220, 22)}
        {bar(120, 32)}
      </div>
      <div className="card p-4 mb-4" style={{ display: 'flex', gap: 28 }}>
        {[70, 90, 60, 50, 80, 100].map((w, i) => (
          <div key={i} style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {bar(44, 8)}
            {bar(w, 20)}
          </div>
        ))}
      </div>
      <div className="card mb-4" style={{ height: 100 }} />
      <div className="card mb-4" style={{ height: 160 }} />
      <div className="card" style={{ height: 220 }} />
    </div>
  )
}

// ── Stat card ─────────────────────────────────────────────────────────────────

function StatCard({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="label mb-1.5">{label}</div>
      {children}
    </div>
  )
}

// ── Findings by Engine ────────────────────────────────────────────────────────

const SEV_PILL_COLORS: Record<string, { color: string; bg: string }> = {
  critical: { color: '#dc2626', bg: '#dc262620' },
  high:     { color: '#ea580c', bg: '#ea580c20' },
  medium:   { color: '#d97706', bg: '#d9770620' },
  low:      { color: '#2563eb', bg: '#2563eb20' },
  info:     { color: '#6b7280', bg: '#6b728020' },
}
const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

function FindingsByEngine({ findings }: { findings: ScanFinding[] }) {
  const groups = new Map<string, Record<string, number>>()
  for (const f of findings) {
    if (!groups.has(f.engine)) groups.set(f.engine, {})
    const g = groups.get(f.engine)!
    g[f.risk_level] = (g[f.risk_level] ?? 0) + 1
  }
  const sorted = [...groups.entries()].sort(([, a], [, b]) => {
    const aMin = Math.min(...Object.keys(a).map(k => SEV_ORDER[k] ?? 9))
    const bMin = Math.min(...Object.keys(b).map(k => SEV_ORDER[k] ?? 9))
    return aMin - bMin
  })

  return (
    <div className="card mb-4 p-4">
      <div className="label mb-3">By Engine</div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(190px, 1fr))', gap: 8 }}>
        {sorted.map(([engine, counts]) => (
          <div key={engine} style={{
            background: '#0d0d10', borderRadius: 8, padding: '10px 12px',
            border: '1px solid #1f1f26',
          }}>
            <div style={{
              fontSize: 11, color: '#71717a', fontFamily: '"JetBrains Mono", monospace',
              marginBottom: 8, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
            }}>
              {ENGINE_LABEL[engine] ?? engine}
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
              {(['critical', 'high', 'medium', 'low', 'info'] as const)
                .filter(sev => counts[sev])
                .map(sev => {
                  const c = SEV_PILL_COLORS[sev]
                  return (
                    <span key={sev} style={{
                      display: 'inline-flex', alignItems: 'center', gap: 3,
                      padding: '2px 7px', borderRadius: 4,
                      background: c.bg, color: c.color,
                      fontSize: 10, fontWeight: 700,
                      fontFamily: '"JetBrains Mono", monospace',
                      letterSpacing: '0.03em',
                    }}>
                      {sev[0].toUpperCase()} {counts[sev]}
                    </span>
                  )
                })}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Engine Runs ───────────────────────────────────────────────────────────────

const ENGINE_PIPELINE = [
  'dns_auth', 'smtp_discovery', 'smtp_security', 'webmail',
  'vuln_intel', 'secrets', 'web_security',
  'active_probes', 'canary_probes', 'credential_probes',
  'web_pentest', 'risk_correlation',
]

const ENGINE_LABEL: Record<string, string> = {
  dns_auth: 'DNS Auth',
  smtp_discovery: 'SMTP Discovery',
  smtp_security: 'SMTP Security',
  webmail: 'Webmail',
  vuln_intel: 'Vuln Intel',
  secrets: 'Secrets',
  web_security: 'Web Security',
  active_probes: 'Active Probes',
  canary_probes: 'Canary',
  credential_probes: 'Credential Probes',
  web_pentest: 'Web Pentest',
  risk_correlation: 'Risk Score',
}

function fmtDuration(start: string | null, end: string | null): string {
  if (!start) return ''
  const a = new Date(start).getTime()
  const b = end ? new Date(end).getTime() : Date.now()
  const ms = b - a
  if (ms < 1000) return `${ms}ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.floor(ms / 60000)}m${Math.floor((ms % 60000) / 1000)}s`
}

function EngineRuns({
  scan, progress, isActive, engine,
}: {
  scan: ScanDetail
  progress: number
  isActive: boolean
  engine: string | null
}) {
  const [tick, setTick] = useState(0)
  useEffect(() => {
    if (!isActive) return
    const id = setInterval(() => setTick(t => t + 1), 1000)
    return () => clearInterval(id)
  }, [isActive])
  void tick // tick drives live duration re-renders

  const runMap = new Map(scan.engine_runs.map(r => [r.engine, r]))
  const orderedRuns: Array<{ name: string; run: EngineRun | null }> = []

  for (const name of ENGINE_PIPELINE) {
    if (runMap.has(name)) orderedRuns.push({ name, run: runMap.get(name)! })
  }
  for (const run of scan.engine_runs) {
    if (!ENGINE_PIPELINE.includes(run.engine)) orderedRuns.push({ name: run.engine, run })
  }
  // Queued — no runs yet: show full pipeline as pending so UI isn't empty
  if (orderedRuns.length === 0 && isActive) {
    for (const name of ENGINE_PIPELINE) {
      orderedRuns.push({ name, run: null })
    }
  }

  const totalFindings = scan.findings.length
  const completedCount = scan.engine_runs.filter(r => r.status === 'completed').length
  const totalEngines = scan.engine_runs.length

  return (
    <div className="card mb-4 overflow-hidden">
      {/* Header */}
      <div className="px-4 py-3 border-b border-border flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="label">Engines</span>
          {isActive && (
            <div className="flex items-center gap-2">
              <span className="dot-pulse" style={{
                width: 6, height: 6, borderRadius: '50%',
                background: 'var(--color-accent)',
                display: 'inline-block', flexShrink: 0,
                color: 'var(--color-accent)',
              }} />
              <span className="text-xs text-text-muted">
                {engine
                  ? (ENGINE_LABEL[engine] ?? engine)
                  : scan.status === 'queued' ? 'Queued…' : 'Starting…'}
              </span>
            </div>
          )}
        </div>
        <div className="flex items-center gap-4">
          {isActive && (
            <div className="flex items-center gap-2">
              <div style={{
                width: 80, height: 3, background: '#1E1E22',
                borderRadius: 2, overflow: 'hidden',
              }}>
                <div style={{
                  height: '100%', width: `${progress}%`,
                  background: 'var(--color-accent)',
                  borderRadius: 2,
                  transition: 'width 600ms cubic-bezier(0.23,1,0.32,1)',
                }} />
              </div>
              <span className="font-mono text-xs" style={{ color: 'var(--color-accent)', minWidth: 30 }}>
                {progress}%
              </span>
            </div>
          )}
          <span className="text-xs text-text-muted tabular-nums">
            {completedCount}/{totalEngines}
          </span>
        </div>
      </div>

      {/* Engine list */}
      <div className="divide-y divide-border/30">
        {orderedRuns.map(({ name, run }) => {
          const isRunning = run?.status === 'running'
          const isCompleted = run?.status === 'completed'
          const isFailed = run?.status === 'failed'
          const isTimeout = run?.status === 'timeout'
          const findings = run?.finding_count ?? 0
          const duration = run ? fmtDuration(run.started_at, run.finished_at) : ''

          let dotColor = '#2a2a30'
          if (isRunning) dotColor = 'var(--color-accent)'
          else if (isCompleted) dotColor = '#36B37E'
          else if (isFailed || isTimeout) dotColor = '#EF4444'

          return (
            <div
              key={name}
              className="flex items-center gap-3 px-4"
              style={{ paddingTop: 9, paddingBottom: 9 }}
            >
              {/* Status dot */}
              <div style={{ width: 7, height: 7, borderRadius: '50%', background: dotColor, flexShrink: 0 }}
                className={isRunning ? 'dot-pulse' : ''} />

              {/* Engine label */}
              <span className={`text-sm flex-1 ${isRunning ? 'text-text-primary' : isCompleted ? 'text-text-secondary' : 'text-text-muted'}`}>
                {ENGINE_LABEL[name] ?? name}
              </span>

              {/* Finding count */}
              {isCompleted && findings > 0 && (
                <span className="text-xs font-mono tabular-nums" style={{ color: findings > 0 ? '#EF444488' : '#3a3a44' }}>
                  {findings} {findings === 1 ? 'finding' : 'findings'}
                </span>
              )}
              {isCompleted && findings === 0 && (
                <span className="text-xs text-text-muted tabular-nums opacity-40">—</span>
              )}
              {(isFailed || isTimeout) && (
                <span className="text-xs" style={{ color: '#EF4444', opacity: 0.7 }}>
                  {isTimeout ? 'timed out' : 'failed'}
                </span>
              )}
              {isRunning && (
                <span className="text-xs text-text-muted tabular-nums">{fmtDuration(run!.started_at, null)}</span>
              )}

              {/* Duration */}
              {(isCompleted || isFailed || isTimeout) && duration && (
                <span className="text-xs text-text-muted tabular-nums opacity-50 ml-2 font-mono">{duration}</span>
              )}
            </div>
          )
        })}
      </div>

      {/* Footer summary */}
      {!isActive && (
        <div className="px-4 py-2.5 border-t border-border/50 flex items-center gap-3">
          <span style={{
            width: 7, height: 7, borderRadius: '50%', flexShrink: 0,
            background: scan.status === 'completed' ? '#36B37E'
              : scan.status === 'failed' ? '#EF4444'
              : scan.status === 'partial' ? '#E5A93D' : '#3a3a44',
          }} />
          <span className="text-xs text-text-muted">
            {scan.status === 'completed' && 'Completed'}
            {scan.status === 'partial' && 'Partial — some engines timed out'}
            {scan.status === 'failed' && 'Failed'}
          </span>
          <span className="text-xs font-mono text-text-muted ml-auto tabular-nums">
            {totalFindings} {totalFindings === 1 ? 'finding' : 'findings'}
          </span>
        </div>
      )}
    </div>
  )
}

const STATUS_OPTIONS: FindingStatus[] = [
  'open',
  'confirmed',
  'in_remediation',
  'accepted_risk',
  'resolved',
  'false_positive',
]

function FindingRow({
  finding: f,
  orgId,
  expanded,
  onToggle,
}: {
  finding: ScanFinding
  orgId: string
  expanded: boolean
  onToggle: () => void
}) {
  const qc = useQueryClient()
  const currentStatus: FindingStatus = (f.status as FindingStatus) ?? 'open'
  const [localStatus, setLocalStatus] = useState<FindingStatus>(currentStatus)
  const [menuOpen, setMenuOpen] = useState(false)

  const { mutate: updateStatus, isPending } = useMutation({
    mutationFn: (next: FindingStatus) =>
      findingsApi.updateStatus(orgId, f.id, next),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scan', orgId, f.scan_id] })
    },
    onError: () => {
      // revert optimistic update on error
      setLocalStatus(currentStatus)
    },
  })

  function handleStatusChange(next: FindingStatus) {
    setLocalStatus(next)
    setMenuOpen(false)
    updateStatus(next)
  }

  const showBadge = localStatus !== 'open'

  return (
    <div>
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-3 px-4 py-3 hover:bg-bg-elevated/50 transition-colors text-left"
      >
        {expanded ? (
          <ChevronDown size={13} className="text-text-muted shrink-0" />
        ) : (
          <ChevronRight size={13} className="text-text-muted shrink-0" />
        )}
        <SeverityBadge level={f.risk_level} />
        <span className="text-sm text-text-primary flex-1 truncate">{f.title}</span>
        {showBadge && (
          <FindingStatusBadge status={localStatus} />
        )}
        <span className="text-xs font-mono text-text-muted shrink-0">{f.engine}</span>
        <span className="text-xs font-mono text-text-muted shrink-0">{f.check_id}</span>
      </button>
      {expanded && (
        <div className="px-4 pb-4 pl-10 space-y-3">
          <p className="text-sm text-text-secondary">{f.description}</p>
          {f.affected_asset && (
            <div>
              <div className="label mb-1">Affected asset</div>
              <span className="font-mono text-xs text-text-primary">{f.affected_asset}</span>
            </div>
          )}
          <div>
            <div className="label mb-1">Remediation</div>
            <p className="text-sm text-text-secondary">{f.remediation}</p>
          </div>
          {f.evidence.length > 0 && (
            <div>
              <div className="label mb-1">Evidence</div>
              <div className="space-y-1">
                {f.evidence.map((ev, i) => (
                  <div key={i} className="bg-bg-base px-3 py-2 border border-border">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-[10px] font-mono text-text-muted uppercase">
                        {ev.type}
                      </span>
                      <span className="text-[10px] text-text-muted truncate">{ev.source}</span>
                    </div>
                    <span className="font-mono text-xs text-text-primary break-all">
                      {ev.observed_value}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
          {/* Status selector */}
          <div>
            <div className="label mb-1">State</div>
            <div style={{ position: 'relative', display: 'inline-block' }}>
              <button
                disabled={isPending}
                onClick={(e) => { e.stopPropagation(); setMenuOpen(v => !v) }}
                style={{
                  display: 'inline-flex', alignItems: 'center', gap: '6px',
                  padding: '4px 10px', borderRadius: '20px', cursor: 'pointer',
                  fontSize: '11px', fontWeight: 500,
                  border: '1px solid #242428',
                  background: '#161619',
                  color: '#A1A1AA',
                  opacity: isPending ? 0.5 : 1,
                }}
              >
                <FindingStatusBadge status={localStatus} />
                <ChevronDown size={11} />
              </button>
              {menuOpen && (
                <div
                  style={{
                    position: 'absolute', top: 'calc(100% + 4px)', left: 0, zIndex: 50,
                    background: '#161619',
                    border: '1px solid #242428',
                    borderRadius: '8px',
                    boxShadow: '0 8px 24px rgba(0,0,0,0.4)',
                    padding: '4px',
                    minWidth: '160px',
                  }}
                >
                  {STATUS_OPTIONS.map(opt => (
                    <button
                      key={opt}
                      onClick={(e) => { e.stopPropagation(); handleStatusChange(opt) }}
                      style={{
                        display: 'flex', alignItems: 'center', gap: '8px',
                        width: '100%', padding: '6px 8px', borderRadius: '6px',
                        cursor: 'pointer', textAlign: 'left',
                        background: opt === localStatus ? '#090909' : 'transparent',
                        border: 'none',
                      }}
                      className="hover:bg-bg-base transition-colors"
                    >
                      <FindingStatusBadge status={opt} />
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
