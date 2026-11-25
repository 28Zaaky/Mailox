import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ChevronDown, ChevronRight, ShieldCheck, ShieldAlert } from 'lucide-react'
import { toast } from 'sonner'
import { PageHeader } from '../../components/Layout'
import { SeverityBadge } from '../../components/SeverityBadge'
import { useAuth } from '../../lib/auth'
import { findings as findingsApi } from '../../lib/api'
import type { FindingStatus, ScanFinding } from '../../types'
import clsx from 'clsx'

// ── technical_details narrowing ───────────────────────────────────────────────
// Evidence details are an untyped JSON bag (Record<string, unknown>); narrow each
// field before it reaches JSX.

type Details = Record<string, unknown>

function str(d: Details, key: string): string | undefined {
  const v = d[key]
  return typeof v === 'string' && v.length > 0 ? v : undefined
}

function num(d: Details, key: string): number | undefined {
  const v = d[key]
  return typeof v === 'number' && Number.isFinite(v) ? v : undefined
}

function flag(d: Details, key: string): boolean {
  return d[key] === true
}

function strList(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []
}

interface CheckedCve {
  cve_id: string
  severity: string
  cvss_score: number | null
  affected_versions: string[]
  patched_versions: string[]
}

function checkedCves(d: Details): CheckedCve[] {
  const raw = d.cves_checked
  if (!Array.isArray(raw)) return []
  return raw.flatMap((item): CheckedCve[] => {
    if (typeof item !== 'object' || item === null) return []
    const o = item as Details
    const cve_id = str(o, 'cve_id')
    if (!cve_id) return []
    return [{
      cve_id,
      severity: str(o, 'severity') ?? '',
      cvss_score: num(o, 'cvss_score') ?? null,
      affected_versions: strList(o.affected_versions),
      patched_versions: strList(o.patched_versions),
    }]
  })
}

const STATUSES: FindingStatus[] = [
  'open', 'confirmed', 'in_remediation', 'accepted_risk', 'resolved', 'false_positive',
]

export default function VulnIntel() {
  const { currentOrg } = useAuth()
  const orgId = currentOrg?.id ?? ''
  const qc = useQueryClient()

  const { data, isLoading } = useQuery({
    queryKey: ['findings', orgId, 'vuln_intel'],
    queryFn: () => findingsApi.list(orgId, { engine: 'vuln_intel', page: 1, page_size: 100 }),
    enabled: !!orgId,
  })

  const patchMutation = useMutation({
    mutationFn: ({ findingId, status }: { findingId: string; status: FindingStatus }) =>
      findingsApi.updateStatus(orgId, findingId, status),
    onSuccess: (_, { status }) => {
      qc.invalidateQueries({ queryKey: ['findings', orgId, 'vuln_intel'] })
      toast.success(`Status → ${status.replace(/_/g, ' ')}`)
    },
    onError: () => toast.error('Failed to update'),
  })

  const items = data?.items ?? []
  const total = data?.total ?? 0

  // Separate clean (INFO, no CVEs) from vulnerable
  const cleanFindings = items.filter(f => f.check_id.startsWith('VI-CLEAN-'))
  const cveFindings = items.filter(f => !f.check_id.startsWith('VI-CLEAN-'))
    .sort((a, b) => {
      const o = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
      return (o[a.risk_level] ?? 9) - (o[b.risk_level] ?? 9)
    })

  return (
    <div>
      <PageHeader
        title="Vulnerability Intelligence"
        subtitle={`${total} findings — ${cveFindings.length} CVEs, ${cleanFindings.length} patched`}
      />
      <p className="text-xs mb-6" style={{ color: '#666672', letterSpacing: '0.5px', lineHeight: 1.8 }}>
        CVE correlation for discovered software versions. Version ranges matched against local CVE database.
      </p>

      {isLoading ? (
        <div className="text-xs py-8 text-center" style={{ color: '#3a3a44', letterSpacing: '1px' }}>loading…</div>
      ) : items.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '72px 24px' }}>
          <svg width="52" height="52" viewBox="0 0 52 52" fill="none" style={{ margin: '0 auto 18px', display: 'block' }}>
            <circle cx="26" cy="26" r="25" stroke="#27272a" strokeWidth="1.5" />
            <path d="M20 20l12 12M32 20L20 32" stroke="#3a3a44" strokeWidth="2" strokeLinecap="round" />
            <path d="M26 10v4M26 38v4M10 26h4M38 26h4" stroke="#27272a" strokeWidth="1.5" strokeLinecap="round" />
          </svg>
          <div style={{ fontSize: '15px', fontWeight: 600, color: '#71717a', marginBottom: '6px' }}>
            No software version data
          </div>
          <div style={{ fontSize: '13px', color: '#52525b', maxWidth: '280px', margin: '0 auto 24px', lineHeight: 1.6 }}>
            Run an assessment to detect software versions and correlate against the CVE database.
          </div>
          <a
            href="/assessments/new"
            style={{
              display: 'inline-flex', alignItems: 'center', gap: '6px',
              padding: '8px 20px', borderRadius: '6px',
              background: 'var(--color-accent, #E53935)',
              color: '#fff', fontSize: '12px', fontWeight: 600,
              textDecoration: 'none', letterSpacing: '0.03em',
            }}
          >
            → Run assessment
          </a>
        </div>
      ) : (
        <div className="space-y-4">

          {/* Active CVEs */}
          {cveFindings.length > 0 && (
            <div>
              <div className="flex items-center gap-2 mb-2">
                <ShieldAlert size={13} style={{ color: '#EF4444' }} />
                <span className="label text-xs" style={{ color: '#EF4444' }}>Active CVEs ({cveFindings.length})</span>
              </div>
              <div className="card overflow-hidden divide-y divide-border/40">
                {cveFindings.map(f => (
                  <CVERow key={f.id} finding={f} onStatusChange={(s) => patchMutation.mutate({ findingId: f.id, status: s })} />
                ))}
              </div>
            </div>
          )}

          {/* Patched / clean software */}
          {cleanFindings.length > 0 && (
            <div>
              <div className="flex items-center gap-2 mb-2">
                <ShieldCheck size={13} style={{ color: '#36B37E' }} />
                <span className="label text-xs" style={{ color: '#36B37E' }}>Patched software ({cleanFindings.length})</span>
              </div>
              <div className="card overflow-hidden divide-y divide-border/40">
                {cleanFindings.map(f => (
                  <CleanRow key={f.id} finding={f} />
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── CVE Row ───────────────────────────────────────────────────────────────────

function CVERow({ finding: f, onStatusChange }: { finding: ScanFinding; onStatusChange: (s: FindingStatus) => void }) {
  const [open, setOpen] = useState(false)
  const td: Details = f.evidence?.[0]?.technical_details ?? {}
  const cveId = str(td, 'cve_id')
  const cvss = num(td, 'cvss_score')
  const cvssVector = str(td, 'cvss_vector')
  const affectedRange = str(td, 'affected_versions_range')

  return (
    <div>
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-3 px-4 py-3 hover:bg-bg-elevated/40 transition-colors text-left"
      >
        {open ? <ChevronDown size={12} className="text-text-muted shrink-0" /> : <ChevronRight size={12} className="text-text-muted shrink-0" />}
        <SeverityBadge level={f.risk_level} />
        <div className="flex-1 min-w-0">
          <div className="text-sm text-text-primary truncate">{f.title}</div>
          {cveId && (
            <div className="text-xs mt-0.5" style={{ color: '#52525B' }}>
              <span className="font-mono">{cveId}</span>
              {cvss !== undefined && cvss > 0 && <span className="ml-2">CVSS {cvss}</span>}
              {flag(td, 'in_cisa_kev') && <span className="ml-2 px-1 rounded text-[9px]" style={{ background: '#7F1D1D', color: '#FCA5A5' }}>CISA KEV</span>}
              {flag(td, 'exploit_available') && <span className="ml-1 px-1 rounded text-[9px]" style={{ background: '#431407', color: '#FED7AA' }}>exploit</span>}
            </div>
          )}
        </div>
        <span className="text-xs font-mono text-text-muted shrink-0 hidden md:block">
          {f.affected_asset}
        </span>
        <div onClick={e => e.stopPropagation()} className="shrink-0">
          <select
            value={f.status}
            onChange={e => onStatusChange(e.target.value as FindingStatus)}
            className="bg-transparent text-[10px] font-mono uppercase tracking-wider cursor-pointer focus:outline-none text-text-muted"
            style={{ letterSpacing: '0.08em' }}
          >
            {STATUSES.map(s => (
              <option key={s} value={s} className="bg-bg-elevated text-text-primary normal-case">
                {s.replace(/_/g, ' ')}
              </option>
            ))}
          </select>
        </div>
      </button>

      {open && (
        <div className="px-10 pb-4 pt-2 space-y-3 border-t border-border/20">
          <p className="text-xs text-text-secondary leading-relaxed">{f.description}</p>
          {f.remediation && (
            <p className="text-xs text-text-muted">{f.remediation}</p>
          )}
          {cvssVector && (
            <div>
              <span className="label text-[10px]">CVSS Vector — </span>
              <span className="font-mono text-xs text-text-muted">{cvssVector}</span>
            </div>
          )}
          {affectedRange && (
            <div>
              <span className="label text-[10px]">Affected — </span>
              <span className="text-xs text-text-muted">{affectedRange}</span>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Clean Row ─────────────────────────────────────────────────────────────────

function CleanRow({ finding: f }: { finding: ScanFinding }) {
  const [open, setOpen] = useState(false)
  const td: Details = f.evidence?.[0]?.technical_details ?? {}
  const cveChecked = checkedCves(td)

  const version = str(td, 'version') || f.evidence?.[0]?.observed_value || '?'
  const product = str(td, 'product') || f.affected_asset || '?'

  return (
    <div>
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-3 px-4 py-3 hover:bg-bg-elevated/40 transition-colors text-left"
      >
        {open ? <ChevronDown size={12} className="text-text-muted shrink-0" /> : <ChevronRight size={12} className="text-text-muted shrink-0" />}
        <ShieldCheck size={13} style={{ color: '#36B37E', flexShrink: 0 }} />
        <div className="flex-1 min-w-0">
          <span className="text-sm font-mono text-text-primary">{product}</span>
          <span className="ml-2 text-xs" style={{ color: '#36B37E' }}>{version}</span>
        </div>
        <span className="text-xs text-text-muted shrink-0">
          {cveChecked.length} CVE{cveChecked.length !== 1 ? 's' : ''} checked — all patched
        </span>
      </button>

      {open && cveChecked.length > 0 && (
        <div className="px-10 pb-4 pt-2 border-t border-border/20">
          <div className="space-y-1">
            {cveChecked.map(c => (
              <div key={c.cve_id} className="flex items-center gap-3 py-1.5 border-b border-border/20">
                <span className="font-mono text-xs text-text-muted w-32 shrink-0">{c.cve_id}</span>
                <span className={clsx(
                  'text-[10px] px-1.5 py-0.5 rounded shrink-0',
                  c.severity === 'CRITICAL' ? 'bg-red-950 text-red-400' :
                  c.severity === 'HIGH' ? 'bg-orange-950 text-orange-400' :
                  c.severity === 'MEDIUM' ? 'bg-yellow-950 text-yellow-400' :
                  'bg-bg-elevated text-text-muted'
                )}>
                  {c.severity} {c.cvss_score ? `${c.cvss_score}` : ''}
                </span>
                <span className="text-xs text-text-muted flex-1 truncate">
                  Affected: {c.affected_versions.join(', ') || '—'}
                </span>
                <span className="text-[10px] shrink-0 px-1.5 py-0.5 rounded" style={{ background: '#052e16', color: '#4ade80' }}>
                  ✓ patched
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
