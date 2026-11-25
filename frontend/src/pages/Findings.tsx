import { useState, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useSearchParams, Link } from 'react-router-dom'
import { ChevronDown, ChevronRight, ExternalLink, Search, X, ArrowUpDown, CheckSquare } from 'lucide-react'
import { toast } from 'sonner'
import { PageHeader } from '../components/Layout'
import { SeverityBadge } from '../components/SeverityBadge'
import { ScanStatusBadge } from '../components/StatusBadge'
import { useAuth } from '../lib/auth'
import { findings as findingsApi, scans as scansApi } from '../lib/api'
import type { FindingStatus, RiskLevel, Scan, ScanFinding } from '../types'

const RISK_LEVELS: RiskLevel[] = ['critical', 'high', 'medium', 'low', 'info']
const SEV_ORDER: Record<RiskLevel, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
const SEV_COLOR: Record<RiskLevel, string> = {
  critical: '#EF4444', high: '#EA580C', medium: '#E5A93D', low: '#36B37E', info: '#60A5FA',
}
const STATUSES: FindingStatus[] = [
  'open', 'confirmed', 'in_remediation', 'accepted_risk', 'resolved', 'false_positive',
]
const BULK_STATUSES: FindingStatus[] = ['accepted_risk', 'false_positive', 'resolved', 'confirmed', 'in_remediation']

export default function Findings() {
  const { currentOrg } = useAuth()
  const orgId = currentOrg?.id ?? ''
  const qc = useQueryClient()
  const [searchParams, setSearchParams] = useSearchParams()

  const filterLevel  = searchParams.get('level')  ?? ''
  const filterStatus = searchParams.get('status') ?? ''
  const filterQuery  = searchParams.get('q')      ?? ''
  const sortDir      = (searchParams.get('sort') ?? 'asc') as 'asc' | 'desc'

  // Bulk selection — transient state, not in URL
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [bulkTarget, setBulkTarget] = useState<FindingStatus>('accepted_risk')

  function setParam(key: string, val: string) {
    setSearchParams(p => { val ? p.set(key, val) : p.delete(key); return p }, { replace: true })
  }
  function clearFilters() { setSearchParams({}, { replace: true }) }
  const toggleSort = () => setParam('sort', sortDir === 'asc' ? 'desc' : 'asc')

  const toggleSelect = useCallback((id: string) => {
    setSelected(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }, [])

  const { data: summary } = useQuery({
    queryKey: ['findings-summary', orgId],
    queryFn: () => findingsApi.summary(orgId),
    enabled: !!orgId,
  })

  const { data: scanList = [], isLoading: scansLoading } = useQuery({
    queryKey: ['scans', orgId],
    queryFn: () => scansApi.list(orgId, 100, 0),
    enabled: !!orgId,
  })

  const relevantScans = scanList.filter(s => s.finding_count > 0 || s.status === 'running')
  const totalFindings = summary?.total ?? 0
  const hasFilters = !!(filterLevel || filterStatus || filterQuery)

  // Bulk update mutation — fires N parallel PATCH calls
  const bulkMutation = useMutation({
    mutationFn: async (ids: string[]) => {
      await Promise.all(ids.map(id => findingsApi.updateStatus(orgId, id, bulkTarget)))
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scan-findings', orgId] })
      qc.invalidateQueries({ queryKey: ['findings-summary', orgId] })
      qc.invalidateQueries({ queryKey: ['org-stats', orgId] })
      toast.success(`${selected.size} findings → ${bulkTarget.replace(/_/g, ' ')}`)
      setSelected(new Set())
    },
    onError: () => toast.error('Bulk update failed'),
  })

  return (
    <div style={{ paddingBottom: selected.size > 0 ? '72px' : '0' }}>
      <PageHeader title="Findings" subtitle={`${totalFindings} findings across ${relevantScans.length} scans`} />

      {/* Filter bar */}
      {summary && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px', flexWrap: 'wrap' }}>
          {/* Severity chips */}
          {RISK_LEVELS.map(l => {
            const count = summary.by_severity[l] ?? 0
            if (count === 0) return null
            const active = filterLevel === l
            return (
              <button
                key={l}
                onClick={() => setParam('level', active ? '' : l)}
                style={{
                  display: 'inline-flex', alignItems: 'center', gap: '5px',
                  padding: '4px 10px', borderRadius: '20px', border: 'none',
                  fontSize: '11px', fontWeight: 500, cursor: 'pointer',
                  background: active ? `${SEV_COLOR[l]}18` : '#111113',
                  color: active ? SEV_COLOR[l] : '#71717A',
                  outline: active ? `1px solid ${SEV_COLOR[l]}40` : 'none',
                  transition: 'all 150ms',
                }}
              >
                <span style={{ width: 5, height: 5, borderRadius: '50%', background: SEV_COLOR[l], flexShrink: 0 }} />
                {l}
                <span style={{ fontFamily: 'JetBrains Mono, monospace', fontWeight: 700 }}>{count}</span>
              </button>
            )
          })}

          {/* Status filter */}
          <select
            value={filterStatus}
            onChange={e => setParam('status', e.target.value)}
            className="input"
            style={{ height: '28px', fontSize: '11px', paddingTop: 0, paddingBottom: 0, width: 'auto' }}
          >
            <option value="">All statuses</option>
            {STATUSES.map(s => <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>)}
          </select>

          {/* Search */}
          <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
            <Search size={11} style={{ position: 'absolute', left: '8px', color: '#52525B', pointerEvents: 'none' }} />
            <input
              className="input"
              placeholder="Search title or asset…"
              value={filterQuery}
              onChange={e => setParam('q', e.target.value)}
              style={{ height: '28px', fontSize: '11px', paddingLeft: '24px', paddingTop: 0, paddingBottom: 0, minWidth: '200px' }}
            />
            {filterQuery && (
              <button
                onClick={() => setParam('q', '')}
                style={{ position: 'absolute', right: '6px', background: 'none', border: 'none', cursor: 'pointer', color: '#52525B', display: 'flex' }}
              >
                <X size={10} />
              </button>
            )}
          </div>

          {/* Sort toggle */}
          <button
            onClick={toggleSort}
            title={`Sort severity: ${sortDir === 'asc' ? 'critical first' : 'info first'}`}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: '4px',
              height: '28px', padding: '0 10px', borderRadius: '6px',
              border: '1px solid #1f1f1f', background: 'transparent',
              color: '#52525B', fontSize: '10px', cursor: 'pointer',
              transition: 'color 150ms',
            }}
            onMouseEnter={e => { (e.currentTarget as HTMLElement).style.color = '#c8ccd4' }}
            onMouseLeave={e => { (e.currentTarget as HTMLElement).style.color = '#52525B' }}
          >
            <ArrowUpDown size={10} />
            {sortDir === 'asc' ? 'Critical first' : 'Info first'}
          </button>

          {/* Clear */}
          {hasFilters && (
            <button
              onClick={clearFilters}
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#52525B', fontSize: '11px', letterSpacing: '0.4px' }}
            >
              × clear
            </button>
          )}
        </div>
      )}

      {/* Scan groups */}
      {scansLoading ? (
        <div style={{ textAlign: 'center', color: '#71717A', fontSize: '13px', padding: '48px 0' }}>Loading…</div>
      ) : relevantScans.length === 0 ? (
        <EmptyState hasFilters={hasFilters} onClear={clearFilters} />
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {relevantScans.map(scan => (
            <ScanGroup
              key={scan.id}
              scan={scan}
              orgId={orgId}
              filterLevel={filterLevel}
              filterStatus={filterStatus}
              filterQuery={filterQuery}
              sortDir={sortDir}
              selected={selected}
              onToggleSelect={toggleSelect}
              onSelectAll={(ids) => setSelected(prev => { const next = new Set(prev); ids.forEach(id => next.add(id)); return next })}
              onDeselectAll={(ids) => setSelected(prev => { const next = new Set(prev); ids.forEach(id => next.delete(id)); return next })}
              onStatusChange={(findingId, status) => {
                findingsApi.updateStatus(orgId, findingId, status)
                  .then(() => {
                    qc.invalidateQueries({ queryKey: ['scan-findings', orgId, scan.id] })
                    qc.invalidateQueries({ queryKey: ['findings-summary', orgId] })
                    qc.invalidateQueries({ queryKey: ['org-stats', orgId] })
                    toast.success(`Status → ${status.replace(/_/g, ' ')}`)
                  })
                  .catch(() => toast.error('Failed to update status'))
              }}
            />
          ))}
        </div>
      )}

      {/* Bulk action bar */}
      {selected.size > 0 && (
        <div
          style={{
            position: 'fixed', bottom: 0, left: 0, right: 0, zIndex: 50,
            background: '#111113', borderTop: '1px solid #1f1f1f',
            padding: '12px 24px',
            display: 'flex', alignItems: 'center', gap: '12px',
            animation: 'cardEnter 200ms var(--ease-out) both',
          }}
        >
          <CheckSquare size={14} style={{ color: 'var(--color-accent)', flexShrink: 0 }} />
          <span style={{ fontSize: '13px', color: '#c8ccd4', fontWeight: 500 }}>
            {selected.size} selected
          </span>
          <span style={{ color: '#1f1f1f' }}>·</span>
          <span style={{ fontSize: '12px', color: '#71717A' }}>Mark as</span>
          <select
            value={bulkTarget}
            onChange={e => setBulkTarget(e.target.value as FindingStatus)}
            className="input"
            style={{ height: '30px', fontSize: '11px', paddingTop: 0, paddingBottom: 0, width: 'auto' }}
          >
            {BULK_STATUSES.map(s => (
              <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>
            ))}
          </select>
          <button
            onClick={() => bulkMutation.mutate(Array.from(selected))}
            disabled={bulkMutation.isPending}
            className="btn-primary"
            style={{ height: '30px', fontSize: '12px', padding: '0 16px' }}
          >
            {bulkMutation.isPending ? 'Updating…' : 'Apply'}
          </button>
          <button
            onClick={() => setSelected(new Set())}
            style={{
              background: 'none', border: 'none', cursor: 'pointer',
              color: '#52525B', fontSize: '11px', marginLeft: 'auto',
            }}
          >
            Deselect all
          </button>
        </div>
      )}
    </div>
  )
}

// ── Empty State ───────────────────────────────────────────────────────────────

function EmptyState({ hasFilters, onClear }: { hasFilters: boolean; onClear: () => void }) {
  return (
    <div className="card" style={{ padding: '48px 24px', textAlign: 'center' }}>
      {hasFilters ? (
        <>
          <div style={{ fontSize: '32px', marginBottom: '12px' }}>🔍</div>
          <div style={{ fontSize: '14px', color: '#c8ccd4', fontWeight: 500, marginBottom: '6px' }}>
            No findings match your filters
          </div>
          <div style={{ fontSize: '12px', color: '#71717A', marginBottom: '20px' }}>
            Try loosening the severity or status filter.
          </div>
          <button onClick={onClear} className="btn-secondary" style={{ fontSize: '12px' }}>
            Clear filters
          </button>
        </>
      ) : (
        <>
          <div style={{ fontSize: '32px', marginBottom: '12px' }}>🛡️</div>
          <div style={{ fontSize: '14px', color: '#c8ccd4', fontWeight: 500, marginBottom: '6px' }}>
            No findings yet
          </div>
          <div style={{ fontSize: '12px', color: '#71717A', marginBottom: '20px' }}>
            Run an assessment to scan your domain and populate this page.
          </div>
          <Link to="/assessments/new" className="btn-primary" style={{ display: 'inline-block', fontSize: '12px' }}>
            Start a scan →
          </Link>
        </>
      )}
    </div>
  )
}

// ── Scan Group ────────────────────────────────────────────────────────────────

function ScanGroup({
  scan,
  orgId,
  filterLevel,
  filterStatus,
  filterQuery,
  sortDir,
  selected,
  onToggleSelect,
  onSelectAll,
  onDeselectAll,
  onStatusChange,
}: {
  scan: Scan
  orgId: string
  filterLevel: string
  filterStatus: string
  filterQuery: string
  sortDir: 'asc' | 'desc'
  selected: Set<string>
  onToggleSelect: (id: string) => void
  onSelectAll: (ids: string[]) => void
  onDeselectAll: (ids: string[]) => void
  onStatusChange: (id: string, s: FindingStatus) => void
}) {
  const [open, setOpen] = useState(false)

  const { data, isLoading } = useQuery({
    queryKey: ['scan-findings', orgId, scan.id, filterLevel, filterStatus],
    queryFn: () =>
      findingsApi.list(orgId, {
        scan_id: scan.id,
        risk_level: filterLevel || undefined,
        status: filterStatus || undefined,
        page: 1,
        page_size: 100,
      }),
    enabled: open && !!orgId,
  })

  const allFindings = data?.items ?? []

  const findings = allFindings
    .filter(f => {
      if (!filterQuery) return true
      const q = filterQuery.toLowerCase()
      return f.title.toLowerCase().includes(q) || (f.affected_asset ?? '').toLowerCase().includes(q)
    })
    .slice()
    .sort((a, b) => {
      const diff = (SEV_ORDER[a.risk_level] ?? 9) - (SEV_ORDER[b.risk_level] ?? 9)
      return sortDir === 'asc' ? diff : -diff
    })

  const severityCounts: Partial<Record<RiskLevel, number>> = {}
  allFindings.forEach(f => { severityCounts[f.risk_level] = (severityCounts[f.risk_level] ?? 0) + 1 })

  const findingIds = findings.map(f => f.id)
  const allSelected = findingIds.length > 0 && findingIds.every(id => selected.has(id))
  const someSelected = findingIds.some(id => selected.has(id))

  const timeAgo = (d: string) => {
    const diff = (Date.now() - new Date(d).getTime()) / 1000
    if (diff < 60) return `${Math.round(diff)}s ago`
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
    return `${Math.floor(diff / 86400)}d ago`
  }

  const date = scan.completed_at || scan.started_at || scan.created_at

  return (
    <div className="card" style={{ overflow: 'hidden' }}>
      {/* Header row */}
      <div style={{ display: 'flex', alignItems: 'center' }}>
        {/* Select-all checkbox (only when expanded and findings loaded) */}
        {open && findings.length > 0 && (
          <div
            onClick={e => { e.stopPropagation(); allSelected ? onDeselectAll(findingIds) : onSelectAll(findingIds) }}
            style={{
              paddingLeft: '12px', paddingRight: '0', display: 'flex', alignItems: 'center',
              cursor: 'pointer', flexShrink: 0,
            }}
          >
            <div style={{
              width: '14px', height: '14px', borderRadius: '3px', border: '1px solid',
              borderColor: allSelected || someSelected ? 'var(--color-accent)' : '#3a3a44',
              background: allSelected ? 'var(--color-accent)' : someSelected ? 'rgba(var(--color-accent-rgb),0.2)' : 'transparent',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              transition: 'all 150ms',
            }}>
              {(allSelected || someSelected) && (
                <svg width="8" height="6" viewBox="0 0 8 6" fill="none">
                  <path d={allSelected ? "M1 3l2 2 4-4" : "M1 3h6"} stroke="white" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              )}
            </div>
          </div>
        )}

        <button
          onClick={() => setOpen(o => !o)}
          style={{
            flex: 1, display: 'flex', alignItems: 'center', gap: '10px',
            padding: open && findings.length > 0 ? '10px 12px 10px 8px' : '10px 12px',
            background: 'transparent', border: 'none', cursor: 'pointer', textAlign: 'left',
          }}
        >
          {open
            ? <ChevronDown size={13} style={{ color: '#52525B', flexShrink: 0 }} />
            : <ChevronRight size={13} style={{ color: '#52525B', flexShrink: 0 }} />
          }

          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '13px', color: '#F5F5F5', fontWeight: 500, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {scan.target_domain}
          </span>

          {/* Severity dots */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            {RISK_LEVELS.filter(l => (severityCounts[l] ?? 0) > 0 || (!open && scan.finding_count > 0)).map(l => {
              const count = open ? (severityCounts[l] ?? 0) : null
              if (open && count === 0) return null
              if (!open) return (
                <span key={l} style={{ width: 6, height: 6, borderRadius: '50%', background: SEV_COLOR[l], opacity: 0.5 }} />
              )
              return (
                <span key={l} style={{ display: 'inline-flex', alignItems: 'center', gap: 3, fontSize: '10px', fontFamily: 'JetBrains Mono, monospace', color: SEV_COLOR[l] }}>
                  <span style={{ width: 5, height: 5, borderRadius: '50%', background: SEV_COLOR[l] }} />
                  {count}
                </span>
              )
            })}
          </div>

          <span style={{ fontSize: '11px', fontFamily: 'JetBrains Mono, monospace', color: '#52525B', flexShrink: 0, minWidth: '52px', textAlign: 'right' }}>
            {scan.finding_count} findings
          </span>
          <div style={{ flexShrink: 0 }}>
            <ScanStatusBadge status={scan.status} />
          </div>
          <span style={{ fontSize: '11px', color: '#52525B', flexShrink: 0, width: '56px', textAlign: 'right' }}>
            {timeAgo(date)}
          </span>
        </button>

        <Link
          to={`/assessments/${scan.id}`}
          onClick={e => e.stopPropagation()}
          style={{ color: '#3a3a44', flexShrink: 0, padding: '4px 12px 4px 4px', display: 'flex', transition: 'color 150ms' }}
          title="Open assessment"
          onMouseEnter={e => { (e.currentTarget as HTMLElement).style.color = 'var(--color-accent)' }}
          onMouseLeave={e => { (e.currentTarget as HTMLElement).style.color = '#3a3a44' }}
        >
          <ExternalLink size={12} />
        </Link>
      </div>

      {/* Findings list */}
      {open && (
        <div style={{ borderTop: '1px solid rgba(255,255,255,0.05)' }}>
          {isLoading ? (
            <div style={{ padding: '16px', fontSize: '12px', color: '#52525B' }}>Loading…</div>
          ) : findings.length === 0 ? (
            <div style={{ padding: '16px', fontSize: '12px', color: '#52525B', fontStyle: 'italic' }}>
              {filterLevel || filterStatus || filterQuery ? 'No findings match the active filters.' : 'No findings for this scan.'}
            </div>
          ) : (
            <div>
              {findings.map(f => (
                <FindingRow
                  key={f.id}
                  finding={f}
                  selected={selected.has(f.id)}
                  onToggleSelect={() => onToggleSelect(f.id)}
                  onStatusChange={onStatusChange}
                />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Finding Row ───────────────────────────────────────────────────────────────

function FindingRow({
  finding: f,
  selected,
  onToggleSelect,
  onStatusChange,
}: {
  finding: ScanFinding
  selected: boolean
  onToggleSelect: () => void
  onStatusChange: (id: string, s: FindingStatus) => void
}) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
      <div
        style={{
          display: 'flex', alignItems: 'center', gap: '8px',
          padding: '8px 12px',
          background: selected ? 'rgba(var(--color-accent-rgb),0.04)' : 'transparent',
          transition: 'background 150ms',
          cursor: 'default',
        }}
        onMouseEnter={e => { if (!selected) (e.currentTarget as HTMLElement).style.background = 'rgba(255,255,255,0.02)' }}
        onMouseLeave={e => { if (!selected) (e.currentTarget as HTMLElement).style.background = 'transparent' }}
      >
        {/* Checkbox */}
        <div
          onClick={onToggleSelect}
          style={{ width: '14px', height: '14px', borderRadius: '3px', border: '1px solid', flexShrink: 0, cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', transition: 'all 150ms', borderColor: selected ? 'var(--color-accent)' : '#2a2a2a', background: selected ? 'var(--color-accent)' : 'transparent' }}
        >
          {selected && (
            <svg width="8" height="6" viewBox="0 0 8 6" fill="none">
              <path d="M1 3l2 2 4-4" stroke="white" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          )}
        </div>

        {/* Expand toggle */}
        <button
          type="button"
          onClick={() => setExpanded(e => !e)}
          style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '1px', display: 'flex', color: '#3a3a44', flexShrink: 0 }}
        >
          {expanded ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
        </button>

        <SeverityBadge level={f.risk_level} />

        <span
          onClick={() => setExpanded(e => !e)}
          style={{ fontSize: '12px', color: '#c8ccd4', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', cursor: 'pointer' }}
        >
          {f.title}
        </span>

        {f.affected_asset && (
          <span style={{ fontSize: '11px', fontFamily: 'JetBrains Mono, monospace', color: '#52525B', flexShrink: 0, maxWidth: '180px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {f.affected_asset}
          </span>
        )}

        <span style={{ fontSize: '10px', fontFamily: 'JetBrains Mono, monospace', color: '#3a3a44', flexShrink: 0, opacity: 0.7, display: 'none' }}
          className="hidden md:block"
        >
          {f.check_id}
        </span>

        {/* Inline status selector */}
        <div onClick={e => e.stopPropagation()} style={{ flexShrink: 0 }}>
          <select
            value={f.status}
            onChange={e => onStatusChange(f.id, e.target.value as FindingStatus)}
            style={{
              background: 'transparent', border: 'none', cursor: 'pointer',
              fontSize: '10px', fontFamily: 'JetBrains Mono, monospace',
              textTransform: 'uppercase', letterSpacing: '0.08em',
              color: '#52525B', outline: 'none',
            }}
            onFocus={e => { (e.currentTarget as HTMLElement).style.color = '#c8ccd4' }}
            onBlur={e => { (e.currentTarget as HTMLElement).style.color = '#52525B' }}
          >
            {STATUSES.map(s => (
              <option key={s} value={s} style={{ background: '#111113', color: '#c8ccd4', textTransform: 'none', letterSpacing: 'normal' }}>
                {s.replace(/_/g, ' ')}
              </option>
            ))}
          </select>
        </div>

        <Link
          to={`/findings/${f.id}`}
          onClick={e => e.stopPropagation()}
          style={{ color: '#3a3a44', flexShrink: 0, padding: '2px', display: 'flex', transition: 'color 150ms' }}
          onMouseEnter={e => { (e.currentTarget as HTMLElement).style.color = 'var(--color-accent)' }}
          onMouseLeave={e => { (e.currentTarget as HTMLElement).style.color = '#3a3a44' }}
        >
          <ExternalLink size={11} />
        </Link>
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div style={{ padding: '10px 12px 12px 46px', borderTop: '1px solid rgba(255,255,255,0.03)', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <p style={{ fontSize: '12px', color: '#71717A', lineHeight: 1.7, margin: 0 }}>{f.description}</p>
          {f.remediation && (
            <div>
              <span style={{ fontSize: '9px', letterSpacing: '1.5px', textTransform: 'uppercase', color: '#3a3a44', marginRight: '6px' }}>Remediation</span>
              <span style={{ fontSize: '12px', color: '#52525B' }}>{f.remediation}</span>
            </div>
          )}
          {f.evidence.length > 0 && (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
              {f.evidence.map((ev, i) => (
                <div key={i} style={{ background: '#0d0d0f', border: '1px solid #1a1a1a', borderRadius: '4px', padding: '6px 10px', fontSize: '11px', fontFamily: 'JetBrains Mono, monospace' }}>
                  <span style={{ color: '#3a3a44', fontSize: '9px', textTransform: 'uppercase', marginRight: '8px' }}>{ev.type}</span>
                  <span style={{ color: '#c8ccd4', wordBreak: 'break-all' }}>{ev.observed_value}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
