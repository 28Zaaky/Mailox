import { useState, type FormEvent } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate } from 'react-router-dom'

// ── Empty state atoms ─────────────────────────────────────────────────────────

function EmptyNoScans({ onScan }: { onScan: () => void }) {
  return (
    <div style={{ textAlign: 'center', padding: '72px 24px' }}>
      <svg width="52" height="52" viewBox="0 0 52 52" fill="none" style={{ margin: '0 auto 18px', display: 'block' }}>
        <circle cx="26" cy="26" r="25" stroke="#27272a" strokeWidth="1.5" />
        <circle cx="26" cy="26" r="12" stroke="#3a3a44" strokeWidth="1.5" strokeDasharray="3 3" />
        <circle cx="26" cy="26" r="3" fill="#3a3a44" />
        <line x1="26" y1="1" x2="26" y2="13" stroke="#27272a" strokeWidth="1.5" strokeLinecap="round" />
        <line x1="26" y1="39" x2="26" y2="51" stroke="#27272a" strokeWidth="1.5" strokeLinecap="round" />
        <line x1="1" y1="26" x2="13" y2="26" stroke="#27272a" strokeWidth="1.5" strokeLinecap="round" />
        <line x1="39" y1="26" x2="51" y2="26" stroke="#27272a" strokeWidth="1.5" strokeLinecap="round" />
      </svg>
      <div style={{ fontSize: '15px', fontWeight: 600, color: '#71717a', marginBottom: '6px' }}>
        No scans yet
      </div>
      <div style={{ fontSize: '13px', color: '#52525b', marginBottom: '24px', maxWidth: '280px', margin: '0 auto 24px', lineHeight: 1.6 }}>
        Run your first assessment to surface findings for this module.
      </div>
      <button
        onClick={onScan}
        style={{
          display: 'inline-flex', alignItems: 'center', gap: '6px',
          padding: '8px 20px', borderRadius: '6px',
          background: 'var(--color-accent, #E53935)',
          color: '#fff', fontSize: '12px', fontWeight: 600,
          border: 'none', cursor: 'pointer', letterSpacing: '0.03em',
        }}
      >
        → Start a scan
      </button>
    </div>
  )
}

function EmptyClean({ filterLevel }: { filterLevel: string }) {
  return (
    <div style={{ textAlign: 'center', padding: '56px 24px' }}>
      <svg width="44" height="44" viewBox="0 0 44 44" fill="none" style={{ margin: '0 auto 14px', display: 'block' }}>
        <circle cx="22" cy="22" r="21" stroke="#1a3a2a" strokeWidth="1.5" />
        <path d="M13 22l6 7L31 15" stroke="#36B37E" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      <div style={{ fontSize: '14px', fontWeight: 600, color: '#52525b', marginBottom: '4px' }}>
        {filterLevel ? `No ${filterLevel} findings` : 'No findings detected'}
      </div>
      <div style={{ fontSize: '12px', color: '#3a3a44' }}>
        {filterLevel
          ? `Clear at ${filterLevel} severity for this module.`
          : 'This engine is clean across all scanned domains.'}
      </div>
    </div>
  )
}
import { toast } from 'sonner'
import { PageHeader } from '../../components/Layout'
import { SeverityBadge } from '../../components/SeverityBadge'

import { useAuth } from '../../lib/auth'
import { findings as findingsApi, scans as scansApi, orgs as orgsApi } from '../../lib/api'


import type { FindingStatus, RiskLevel, ScanFinding } from '../../types'

const ENGINE_CONFIG_WARNINGS: Record<string, { label: string; detail: string; settingsKey: string }> = {
  credential_probes: {
    label: 'Opt-in required',
    detail: 'Credential testing is disabled. Enable it in Settings → Pentest Modules.',
    settingsKey: 'cred_probe_enabled',
  },
  web_pentest: {
    label: 'Active injections disabled',
    detail: 'SQLi/XSS/SSTI/LFI probes are off. Enable Active Web Probes in Settings → Pentest Modules.',
    settingsKey: 'web_active_probe_enabled',
  },
  canary_probes: {
    label: 'No canary email set',
    detail: 'Configure a canary address in Settings → Pentest Modules to receive delivery confirmations.',
    settingsKey: 'canary_email',
  },
}

function fmtRelative(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

function ScanModal({
  orgId,
  onClose,
}: {
  orgId: string
  onClose: () => void
}) {
  const navigate = useNavigate()
  const [domain, setDomain] = useState('')
  const [launching, setLaunching] = useState(false)

  const { data: recentScans } = useQuery({
    queryKey: ['scans', orgId, 'recent-domains'],
    queryFn: () => scansApi.list(orgId, 10, 0),
    enabled: !!orgId,
    staleTime: 30_000,
  })

  const suggestions = Array.from(
    new Set((recentScans ?? []).map((s: { target_domain: string }) => s.target_domain))
  ).slice(0, 5)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    const target = domain.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '')
    if (!target) return
    setLaunching(true)
    try {
      const scan = await scansApi.create(orgId, target)
      onClose()
      navigate(`/assessments/${scan.id}`)
    } catch {
      toast.error('Failed to launch scan')
      setLaunching(false)
    }
  }

  return (
    <div
      style={{
        position: 'fixed', inset: 0, zIndex: 50,
        background: 'rgba(0,0,0,0.6)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        padding: '16px',
      }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose() }}
    >
      <div style={{
        background: 'var(--bg-elevated, #131316)',
        border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: '12px',
        padding: '24px',
        width: '100%',
        maxWidth: '420px',
        boxShadow: '0 20px 60px rgba(0,0,0,0.6)',
      }}>
        <div style={{ marginBottom: '20px' }}>
          <div style={{ fontSize: '15px', fontWeight: 600, color: '#F5F5F5', marginBottom: '4px' }}>
            New scan
          </div>
          <div style={{ fontSize: '12px', color: '#52525B' }}>
            Runs all engines including this module.
          </div>
        </div>

        <form onSubmit={handleSubmit}>
          <label style={{ fontSize: '11px', color: '#71717A', letterSpacing: '0.08em', textTransform: 'uppercase', display: 'block', marginBottom: '6px' }}>
            Target domain
          </label>
          <input
            className="input w-full"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="example.com"
            autoFocus
            required
            style={{ marginBottom: suggestions.length > 0 ? '8px' : '20px' }}
          />

          {suggestions.length > 0 && (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '5px', marginBottom: '20px' }}>
              {suggestions.map((d) => (
                <button
                  key={d}
                  type="button"
                  onClick={() => setDomain(d)}
                  style={{
                    fontSize: '11px', fontFamily: '"JetBrains Mono", monospace',
                    padding: '2px 10px', borderRadius: '20px',
                    border: `1px solid ${domain === d ? 'var(--color-accent)' : 'rgba(255,255,255,0.08)'}`,
                    background: domain === d ? 'rgba(var(--color-accent-rgb,229,57,53),0.1)' : 'transparent',
                    color: domain === d ? 'var(--color-accent)' : '#52525B',
                    cursor: 'pointer',
                    transition: 'all 150ms',
                  }}
                >
                  {d}
                </button>
              ))}
            </div>
          )}

          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              type="button"
              onClick={onClose}
              className="btn-secondary"
              style={{ flex: 1 }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={launching || !domain.trim()}
              className="btn-primary"
              style={{ flex: 1 }}
            >
              {launching ? 'Launching…' : '→ Scan'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function EngineStatusBanner({ engine, orgId }: { engine: string; orgId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ['engine-stats', orgId, engine],
    queryFn: () => scansApi.engineStats(orgId, engine),
    enabled: !!orgId,
    staleTime: 60_000,
  })

  const { data: pentestCfg } = useQuery({
    queryKey: ['pentest-config', orgId],
    queryFn: () => orgsApi.getPentestConfig(orgId),
    enabled: !!orgId,
    staleTime: 30_000,
  })

  const warnDef = ENGINE_CONFIG_WARNINGS[engine]

  // Only show warning if the relevant feature is actually disabled
  const showWarn = warnDef && pentestCfg && (() => {
    if (warnDef.settingsKey === 'cred_probe_enabled') return !pentestCfg.cred_probe_enabled
    if (warnDef.settingsKey === 'web_active_probe_enabled') return !pentestCfg.web_active_probe_enabled
    if (warnDef.settingsKey === 'canary_email') return !pentestCfg.canary_email
    return false
  })()

  if (isLoading) return null

  const neverRan = !data || data.run_count === 0

  return (
    <div style={{ marginBottom: '20px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
      {/* Run status pill row */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
        {neverRan ? (
          <span style={{
            display: 'inline-flex', alignItems: 'center', gap: '5px',
            padding: '3px 10px', borderRadius: '20px',
            border: '1px solid rgba(255,255,255,0.08)',
            background: 'rgba(255,255,255,0.03)',
            fontSize: '11px', color: '#52525B',
            fontFamily: '"JetBrains Mono", monospace',
          }}>
            <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#3a3a44', flexShrink: 0 }} />
            never ran
          </span>
        ) : (
          <>
            <span style={{
              display: 'inline-flex', alignItems: 'center', gap: '5px',
              padding: '3px 10px', borderRadius: '20px',
              border: '1px solid rgba(54,179,126,0.2)',
              background: 'rgba(54,179,126,0.06)',
              fontSize: '11px', color: '#36B37E',
              fontFamily: '"JetBrains Mono", monospace',
            }}>
              <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#36B37E', flexShrink: 0 }} />
              active
            </span>
            <span style={{ fontSize: '11px', color: '#52525B', fontFamily: '"JetBrains Mono", monospace' }}>
              {data.run_count} run{data.run_count !== 1 ? 's' : ''}
            </span>
            {data.last_run_at && (
              <span style={{ fontSize: '11px', color: '#3a3a44', fontFamily: '"JetBrains Mono", monospace' }}>
                · last {fmtRelative(data.last_run_at)}
              </span>
            )}
            {data.finding_total > 0 && (
              <span style={{
                fontSize: '11px', fontFamily: '"JetBrains Mono", monospace',
                color: '#EF4444', background: 'rgba(239,68,68,0.1)',
                padding: '1px 7px', borderRadius: '20px',
              }}>
                {data.finding_total} finding{data.finding_total !== 1 ? 's' : ''} total
              </span>
            )}
          </>
        )}
      </div>

      {/* Config warning */}
      {showWarn && warnDef && (
        <div style={{
          display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '8px',
          padding: '8px 12px', borderRadius: '6px',
          border: '1px solid rgba(251,191,36,0.2)',
          background: 'rgba(251,191,36,0.04)',
        }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', flex: 1 }}>
            <span style={{ color: '#FBBF24', fontSize: '12px', flexShrink: 0, marginTop: '1px' }}>⚠</span>
            <div>
              <span style={{ fontSize: '11px', color: '#FBBF24', fontWeight: 600, letterSpacing: '0.05em' }}>
                {warnDef.label}
              </span>
              <span style={{ fontSize: '11px', color: '#71717A', marginLeft: '6px' }}>
                {warnDef.detail}
              </span>
            </div>
          </div>
          <Link
            to="/settings"
            style={{
              fontSize: '11px', color: '#FBBF24', flexShrink: 0,
              textDecoration: 'none', opacity: 0.8,
              borderBottom: '1px solid rgba(251,191,36,0.3)',
              whiteSpace: 'nowrap',
            }}
          >
            → Settings
          </Link>
        </div>
      )}
    </div>
  )
}

const RISK_LEVELS: RiskLevel[] = ['critical', 'high', 'medium', 'low', 'info']
const SEV_COLOR: Record<RiskLevel, string> = {
  critical: '#EF4444', high: '#EA580C', medium: '#E5A93D', low: '#36B37E', info: '#60A5FA',
}

interface Props {
  engine: string
  title: string
  subtitle: string
  description: string
}

export default function ModuleBase({ engine, title, subtitle, description }: Props) {
  const { currentOrg } = useAuth()
  const orgId = currentOrg?.id ?? ''
  const qc = useQueryClient()

  const [filterLevel, setFilterLevel] = useState('')
  const [page, setPage] = useState(1)
  const [showScanModal, setShowScanModal] = useState(false)
  const pageSize = 25

  const { data, isLoading, isError, refetch, isFetching } = useQuery({
    queryKey: ['findings', orgId, engine, filterLevel, page],
    queryFn: () =>
      findingsApi.list(orgId, {
        engine,
        risk_level: filterLevel || undefined,
        page,
        page_size: pageSize,
      }),
    enabled: !!orgId,
  })

  const { data: engineStats } = useQuery({
    queryKey: ['engine-stats', orgId, engine],
    queryFn: () => scansApi.engineStats(orgId, engine),
    enabled: !!orgId,
    staleTime: 60_000,
  })
  const neverRan = !engineStats || engineStats.run_count === 0

  const patchMutation = useMutation({
    mutationFn: ({ findingId, status }: { findingId: string; status: FindingStatus }) =>
      findingsApi.updateStatus(orgId, findingId, status),
    onSuccess: (_, { status }) => {
      qc.invalidateQueries({ queryKey: ['findings', orgId, engine] })
      qc.invalidateQueries({ queryKey: ['org-stats', orgId] })
      toast.success(`Status → ${status.replace(/_/g, ' ')}`)
    },
    onError: () => toast.error('Failed to update status'),
  })

  const items = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.ceil(total / pageSize)

  const statusOptions: FindingStatus[] = [
    'open', 'confirmed', 'in_remediation', 'accepted_risk', 'resolved', 'false_positive',
  ]

  return (
    <div>
      {showScanModal && (
        <ScanModal orgId={orgId} onClose={() => setShowScanModal(false)} />
      )}
      <PageHeader
        title={title}
        subtitle={`${total} ${subtitle}`}
        action={
          <button
            onClick={() => setShowScanModal(true)}
            className="btn-primary"
            style={{ fontSize: '12px', padding: '6px 14px' }}
          >
            → New scan
          </button>
        }
      />

      <p className="text-xs mb-4" style={{ color: '#666672', letterSpacing: '0.5px', lineHeight: 1.8 }}>
        {description}
      </p>

      <EngineStatusBanner engine={engine} orgId={orgId} />

      {/* Severity filter chips */}
      <div className="flex gap-2 mb-5 flex-wrap">
        {RISK_LEVELS.map((l) => {
          const active = filterLevel === l
          return (
            <button
              key={l}
              onClick={() => { setFilterLevel(active ? '' : l); setPage(1) }}
              className="sev-chip"
              style={{
                gap: '6px', padding: '4px 11px', borderRadius: '20px',
                fontSize: '11px', fontWeight: 500,
                background: active ? `${SEV_COLOR[l]}18` : '#111113',
                color: active ? SEV_COLOR[l] : '#71717A',
                outline: active ? `1px solid ${SEV_COLOR[l]}40` : 'none',
              }}
            >
              <span style={{ width: 5, height: 5, borderRadius: '50%', background: SEV_COLOR[l], flexShrink: 0 }} />
              {l}
            </button>
          )
        })}
        {filterLevel && (
          <button
            onClick={() => { setFilterLevel(''); setPage(1) }}
            className="text-xs text-text-muted hover:text-text-primary ml-1"
            style={{ letterSpacing: '0.4px' }}
          >
            × clear
          </button>
        )}
      </div>

      {/* Table */}
      {isLoading ? (
        <div className="text-xs py-8 text-center" style={{ color: '#3a3a44', letterSpacing: '1px' }}>
          loading…
        </div>
      ) : isError ? (
        // Never fall through to the "clean" empty state on a failed fetch:
        // that would claim "no issues" when we simply don't know.
        <div
          role="alert"
          className="card py-10 px-6 text-center"
          style={{ borderColor: 'rgba(232,23,58,0.3)' }}
        >
          <div className="text-sm mb-1.5" style={{ color: '#E8173A', letterSpacing: '0.5px' }}>
            Could not load findings
          </div>
          <div className="text-xs mb-4" style={{ color: '#666672' }}>
            The request failed. Results for this module are unknown, not clean.
          </div>
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="btn-secondary disabled:opacity-50"
            style={{ fontSize: '12px', padding: '6px 14px' }}
          >
            {isFetching ? 'retrying…' : 'Retry'}
          </button>
        </div>
      ) : items.length === 0 ? (
        neverRan
          ? <EmptyNoScans onScan={() => setShowScanModal(true)} />
          : <EmptyClean filterLevel={filterLevel} />
      ) : (
        <div className="card">
          <table className="w-full text-sm">
            <thead className="border-b border-border">
              <tr>
                <th className="px-4 py-2.5 text-left label">Title</th>
                <th className="px-4 py-2.5 text-left label">Asset</th>
                <th className="px-4 py-2.5 text-left label">Severity</th>
                <th className="px-4 py-2.5 text-left label">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {items.map((f: ScanFinding) => (
                <tr key={f.id} className="hover:bg-bg-elevated transition-colors">
                  <td className="px-4 py-3">
                    <Link to={`/findings/${f.id}`} className="block group">
                      <div className="text-xs text-text-secondary group-hover:text-accent" style={{ transition: 'color 100ms var(--ease-out)' }}>{f.title}</div>
                      <div className="text-xs mt-0.5 line-clamp-1" style={{ color: '#3a3a44' }}>
                        {f.description}
                      </div>
                    </Link>
                  </td>
                  <td className="px-4 py-3 text-xs font-mono" style={{ color: '#52525B' }}>
                    {f.affected_asset ?? '—'}
                  </td>
                  <td className="px-4 py-3">
                    <SeverityBadge level={f.risk_level} />
                  </td>
                  <td className="px-4 py-3">
                    <select
                      value={f.status}
                      onChange={(e) =>
                        patchMutation.mutate({ findingId: f.id, status: e.target.value as FindingStatus })
                      }
                      className="text-xs focus:outline-none cursor-pointer"
                      style={{
                        background: '#111113',
                        border: '1px solid #242428',
                        borderRadius: '20px',
                        padding: '3px 10px',
                        color: '#A1A1AA',
                        appearance: 'none',
                      }}
                    >
                      {statusOptions.map((s) => (
                        <option key={s} value={s} style={{ background: '#161619' }}>
                          {s.replace(/_/g, ' ')}
                        </option>
                      ))}
                    </select>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex justify-between items-center mt-4 text-xs" style={{ color: '#3a3a44' }}>
          <span>{total} findings</span>
          <div className="flex gap-2">
            <button
              disabled={page <= 1}
              onClick={() => setPage((p) => p - 1)}
              className="px-3 py-1 border border-border disabled:opacity-30 hover:border-accent text-text-muted transition-colors"
              style={{ borderRadius: '6px' }}
            >
              prev
            </button>
            <span className="px-2 py-1">{page} / {totalPages}</span>
            <button
              disabled={page >= totalPages}
              onClick={() => setPage((p) => p + 1)}
              className="px-3 py-1 border border-border disabled:opacity-30 hover:border-accent text-text-muted transition-colors"
              style={{ borderRadius: '6px' }}
            >
              next
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
