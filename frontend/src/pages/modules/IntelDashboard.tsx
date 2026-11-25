import { useEffect, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import {
  Database,
  ExternalLink,
  RefreshCw,
  Search,
  Shield,
  X,
} from 'lucide-react'
import { PageHeader } from '../../components/Layout'
import { useAuth } from '../../lib/auth'
import { intel as intelApi } from '../../lib/api'
import type {
  AffectedRangeOut,
  ProductOut,
  SyncStatusOut,
  VulnerabilityDetail,
  VulnerabilityOut,
  VulnFilters,
} from '../../types/intel'

// ── Helpers ────────────────────────────────────────────────────────────────────

const SEV_STYLES: Record<string, { color: string; bg: string; border: string }> = {
  CRITICAL: { color: '#EF4444', bg: 'rgba(239,68,68,0.09)', border: 'rgba(239,68,68,0.28)' },
  HIGH:     { color: '#EA580C', bg: 'rgba(234,88,12,0.09)', border: 'rgba(234,88,12,0.28)' },
  MEDIUM:   { color: '#E5A93D', bg: 'rgba(229,169,61,0.09)', border: 'rgba(229,169,61,0.28)' },
  LOW:      { color: '#36B37E', bg: 'rgba(54,179,126,0.09)', border: 'rgba(54,179,126,0.28)' },
  INFO:     { color: '#60A5FA', bg: 'rgba(96,165,250,0.09)', border: 'rgba(96,165,250,0.28)' },
}
const FALLBACK_SEV = { color: '#71717A', bg: 'rgba(113,113,122,0.09)', border: 'rgba(113,113,122,0.28)' }

const CAT_COLORS: Record<string, string> = {
  smtp: '#60A5FA',
  webmail: '#A78BFA',
  imap_pop3: '#818CF8',
  tls_crypto: '#6B7280',
  php: '#8B5CF6',
  cms: '#EC4899',
  antispam: '#F59E0B',
  web_server: '#14B8A6',
  os: '#10B981',
  database: '#F97316',
  email_library: '#38BDF8',
  mail_gateway: '#FB923C',
}

function SevBadge({ severity }: { severity: string | null }) {
  const s = severity ? (SEV_STYLES[severity] ?? FALLBACK_SEV) : FALLBACK_SEV
  const label = severity ?? '—'
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '4px',
      fontSize: '11px', fontWeight: 500,
      padding: '2px 8px', borderRadius: '20px',
      color: s.color, background: s.bg, border: `1px solid ${s.border}`,
      whiteSpace: 'nowrap',
    }}>
      <span style={{ width: '5px', height: '5px', borderRadius: '50%', background: s.color, flexShrink: 0 }} />
      {label}
    </span>
  )
}

function CvssScore({ score }: { score: number | null }) {
  if (score === null) return <span style={{ color: '#3a3a44', fontSize: '12px' }}>—</span>
  const color = score >= 9 ? '#EF4444' : score >= 7 ? '#EA580C' : score >= 4 ? '#E5A93D' : '#36B37E'
  return (
    <span style={{ color, fontWeight: 600, fontSize: '12px', fontVariantNumeric: 'tabular-nums' }}>
      {score.toFixed(1)}
    </span>
  )
}

function KevBadge() {
  return (
    <span style={{
      fontSize: '10px', fontWeight: 600, padding: '2px 6px', borderRadius: '4px',
      background: 'rgba(239,68,68,0.15)', color: '#EF4444', border: '1px solid rgba(239,68,68,0.3)',
      whiteSpace: 'nowrap', letterSpacing: '0.3px',
    }}>KEV</span>
  )
}

function ExploitBadge() {
  return (
    <span style={{
      fontSize: '10px', fontWeight: 600, padding: '2px 6px', borderRadius: '4px',
      background: 'rgba(234,88,12,0.15)', color: '#EA580C', border: '1px solid rgba(234,88,12,0.3)',
      whiteSpace: 'nowrap', letterSpacing: '0.3px',
    }}>EXPLOIT</span>
  )
}

function formatDate(iso: string | null): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString('en-GB', { year: 'numeric', month: 'short', day: '2-digit' })
}

function useDebounce<T>(value: T, delay: number): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delay)
    return () => clearTimeout(t)
  }, [value, delay])
  return debounced
}

// ── Slide-over detail panel ────────────────────────────────────────────────────

function VulnDetailPanel({
  cveId,
  onClose,
}: {
  cveId: string
  onClose: () => void
}) {
  const { data, isLoading } = useQuery({
    queryKey: ['intel', 'vuln', cveId],
    queryFn: () => intelApi.getVulnerability(cveId),
    staleTime: 60_000,
  })

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div
      style={{
        position: 'fixed', inset: 0, zIndex: 50,
        display: 'flex', alignItems: 'stretch', justifyContent: 'flex-end',
      }}
    >
      {/* Backdrop */}
      <div
        style={{ position: 'absolute', inset: 0, background: 'rgba(0,0,0,0.45)' }}
        onClick={onClose}
      />
      {/* Panel */}
      <div
        style={{
          position: 'relative', width: '480px', maxWidth: '95vw',
          background: '#0d0d0f', borderLeft: '1px solid #1f1f1f',
          overflowY: 'auto', display: 'flex', flexDirection: 'column',
          zIndex: 1,
        }}
      >
        <div style={{ padding: '20px 24px', borderBottom: '1px solid #1f1f1f', display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: '13px', fontWeight: 600, color: '#c8ccd4', marginBottom: '4px', fontFamily: 'monospace' }}>
              {cveId}
            </div>
            {data && (
              <div style={{ fontSize: '12px', color: '#71717A', lineHeight: 1.5 }}>
                {data.title ?? 'No title'}
              </div>
            )}
          </div>
          <button
            onClick={onClose}
            style={{
              flexShrink: 0, padding: '4px', background: 'transparent', border: 'none',
              cursor: 'pointer', color: '#3a3a44', borderRadius: '4px',
            }}
          >
            <X size={16} />
          </button>
        </div>

        {isLoading ? (
          <div style={{ padding: '32px', textAlign: 'center', color: '#3a3a44', fontSize: '12px' }}>
            loading…
          </div>
        ) : data ? (
          <VulnDetailContent vuln={data} />
        ) : (
          <div style={{ padding: '32px', textAlign: 'center', color: '#3a3a44', fontSize: '12px' }}>
            Failed to load
          </div>
        )}
      </div>
    </div>
  )
}

function VulnDetailContent({ vuln }: { vuln: VulnerabilityDetail }) {
  return (
    <div style={{ padding: '20px 24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Badges row */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', alignItems: 'center' }}>
        <SevBadge severity={vuln.severity} />
        <CvssScore score={vuln.cvss_v3_score} />
        {vuln.in_cisa_kev && <KevBadge />}
        {vuln.exploit_available && <ExploitBadge />}
      </div>

      {/* Description */}
      {vuln.description && (
        <div>
          <div className="label" style={{ fontSize: '10px', marginBottom: '6px', color: '#3a3a44', letterSpacing: '1.5px' }}>
            DESCRIPTION
          </div>
          <p style={{ fontSize: '12px', color: '#71717A', lineHeight: 1.7 }}>{vuln.description}</p>
        </div>
      )}

      {/* CVSS Vector */}
      {vuln.cvss_v3_vector && (
        <div>
          <div className="label" style={{ fontSize: '10px', marginBottom: '6px', color: '#3a3a44', letterSpacing: '1.5px' }}>
            CVSS VECTOR
          </div>
          <code style={{ fontSize: '11px', color: '#c8ccd4', background: 'rgba(255,255,255,0.04)', padding: '4px 8px', borderRadius: '4px' }}>
            {vuln.cvss_v3_vector}
          </code>
        </div>
      )}

      {/* KEV info */}
      {vuln.in_cisa_kev && (
        <div style={{ background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.2)', borderRadius: '8px', padding: '12px 14px' }}>
          <div style={{ fontSize: '11px', fontWeight: 600, color: '#EF4444', marginBottom: '6px' }}>
            CISA Known Exploited Vulnerability
          </div>
          {vuln.kev_date_added && (
            <div style={{ fontSize: '11px', color: '#71717A' }}>Added: {formatDate(vuln.kev_date_added)}</div>
          )}
          {vuln.kev_due_date && (
            <div style={{ fontSize: '11px', color: '#71717A' }}>Due: {formatDate(vuln.kev_due_date)}</div>
          )}
          {vuln.kev_required_action && (
            <div style={{ fontSize: '11px', color: '#c8ccd4', marginTop: '6px' }}>{vuln.kev_required_action}</div>
          )}
        </div>
      )}

      {/* Affected ranges */}
      {vuln.affected_ranges.length > 0 && (
        <div>
          <div className="label" style={{ fontSize: '10px', marginBottom: '8px', color: '#3a3a44', letterSpacing: '1.5px' }}>
            AFFECTED VERSIONS ({vuln.affected_ranges.length})
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            {vuln.affected_ranges.map((r: AffectedRangeOut, i: number) => (
              <div
                key={i}
                style={{
                  background: 'rgba(255,255,255,0.03)', border: '1px solid #1f1f1f',
                  borderRadius: '6px', padding: '8px 12px',
                  display: 'flex', flexWrap: 'wrap', gap: '6px', alignItems: 'center',
                }}
              >
                <span style={{ fontSize: '12px', fontWeight: 500, color: '#c8ccd4' }}>{r.product_name}</span>
                <span style={{ fontSize: '11px', color: '#3a3a44' }}>·</span>
                {r.version_constraints.length > 0 ? (
                  r.version_constraints.map((c, j) => (
                    <code key={j} style={{ fontSize: '11px', color: '#E5A93D', background: 'rgba(229,169,61,0.08)', padding: '1px 6px', borderRadius: '3px' }}>
                      {c}
                    </code>
                  ))
                ) : (
                  <span style={{ fontSize: '11px', color: '#71717A' }}>
                    {r.introduced_version ? `≥ ${r.introduced_version}` : ''}
                    {r.introduced_version && r.fixed_version ? ' → ' : ''}
                    {r.fixed_version ? `< ${r.fixed_version}` : ''}
                    {!r.introduced_version && !r.fixed_version ? 'all versions' : ''}
                  </span>
                )}
                {r.fixed_version && (
                  <span style={{ fontSize: '10px', color: '#36B37E', background: 'rgba(54,179,126,0.09)', padding: '1px 6px', borderRadius: '3px', border: '1px solid rgba(54,179,126,0.2)' }}>
                    fix: {r.fixed_version}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Sources */}
      {vuln.sources.length > 0 && (
        <div>
          <div className="label" style={{ fontSize: '10px', marginBottom: '8px', color: '#3a3a44', letterSpacing: '1.5px' }}>
            SOURCES
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
            {vuln.sources.map((s, i) => (
              <span key={i} style={{
                fontSize: '10px', fontWeight: 500, padding: '2px 8px', borderRadius: '4px',
                background: 'rgba(255,255,255,0.05)', border: '1px solid #2a2a2a', color: '#71717A',
              }}>
                {s.source_name}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* References */}
      {vuln.references.length > 0 && (
        <div>
          <div className="label" style={{ fontSize: '10px', marginBottom: '8px', color: '#3a3a44', letterSpacing: '1.5px' }}>
            REFERENCES
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            {vuln.references.slice(0, 8).map((ref, i) => (
              <a
                key={i}
                href={ref}
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  fontSize: '11px', color: '#60A5FA', textDecoration: 'none',
                  display: 'flex', alignItems: 'center', gap: '4px',
                  overflow: 'hidden', whiteSpace: 'nowrap', textOverflow: 'ellipsis',
                }}
              >
                <ExternalLink size={10} style={{ flexShrink: 0 }} />
                {ref}
              </a>
            ))}
            {vuln.references.length > 8 && (
              <span style={{ fontSize: '11px', color: '#3a3a44' }}>+{vuln.references.length - 8} more</span>
            )}
          </div>
        </div>
      )}

      {/* CWEs */}
      {vuln.cwe_ids.length > 0 && (
        <div>
          <div className="label" style={{ fontSize: '10px', marginBottom: '8px', color: '#3a3a44', letterSpacing: '1.5px' }}>
            CWE
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
            {vuln.cwe_ids.map((cwe, i) => (
              <code key={i} style={{
                fontSize: '11px', padding: '2px 7px', borderRadius: '4px',
                background: 'rgba(255,255,255,0.04)', border: '1px solid #2a2a2a', color: '#c8ccd4',
              }}>{cwe}</code>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Tab 1: Vulnerabilities ─────────────────────────────────────────────────────

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const

function VulnerabilitiesTab({ initialProduct }: { initialProduct?: string }) {
  const [search, setSearch] = useState('')
  const [severities, setSeverities] = useState<string[]>([])
  const [kevOnly, setKevOnly] = useState(false)
  const [exploitOnly, setExploitOnly] = useState(false)
  const [page, setPage] = useState(1)
  const [selectedCveId, setSelectedCveId] = useState<string | null>(null)
  const [productFilter] = useState(initialProduct ?? '')

  const debouncedSearch = useDebounce(search, 400)
  const debouncedProduct = useDebounce(productFilter, 400)

  const filters: VulnFilters = {
    page,
    per_page: 50,
    ...(debouncedSearch && { search: debouncedSearch }),
    ...(severities.length && { severity: severities }),
    ...(kevOnly && { in_cisa_kev: true }),
    ...(exploitOnly && { exploit_available: true }),
    ...(debouncedProduct && { product: debouncedProduct }),
  }

  const { data, isLoading, isFetching } = useQuery({
    queryKey: ['intel', 'vulns', filters],
    queryFn: () => intelApi.listVulnerabilities(filters),
    staleTime: 30_000,
    placeholderData: (prev) => prev,
  })

  const items = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.ceil(total / 50)

  function toggleSeverity(sev: string) {
    setSeverities((prev) =>
      prev.includes(sev) ? prev.filter((s) => s !== sev) : [...prev, sev]
    )
    setPage(1)
  }

  return (
    <div>
      {/* Filter bar */}
      <div style={{
        display: 'flex', flexWrap: 'wrap', gap: '10px', alignItems: 'center',
        marginBottom: '16px', padding: '12px 14px',
        background: 'rgba(255,255,255,0.025)', border: '1px solid #1f1f1f', borderRadius: '8px',
      }}>
        {/* Severity toggles */}
        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
          {SEVERITIES.map((sev) => {
            const s = SEV_STYLES[sev] ?? FALLBACK_SEV
            const active = severities.includes(sev)
            return (
              <button
                key={sev}
                onClick={() => toggleSeverity(sev)}
                style={{
                  fontSize: '11px', fontWeight: 500, padding: '3px 9px',
                  borderRadius: '20px', cursor: 'pointer', border: `1px solid ${active ? s.border : '#2a2a2a'}`,
                  color: active ? s.color : '#3a3a44',
                  background: active ? s.bg : 'transparent',
                  transition: 'all 150ms',
                }}
              >
                {sev}
              </button>
            )
          })}
        </div>

        {/* KEV / Exploit toggles */}
        <button
          onClick={() => { setKevOnly(!kevOnly); setPage(1) }}
          style={{
            fontSize: '11px', fontWeight: 600, padding: '3px 9px',
            borderRadius: '4px', cursor: 'pointer',
            border: `1px solid ${kevOnly ? 'rgba(239,68,68,0.4)' : '#2a2a2a'}`,
            color: kevOnly ? '#EF4444' : '#3a3a44',
            background: kevOnly ? 'rgba(239,68,68,0.1)' : 'transparent',
          }}
        >
          KEV
        </button>
        <button
          onClick={() => { setExploitOnly(!exploitOnly); setPage(1) }}
          style={{
            fontSize: '11px', fontWeight: 600, padding: '3px 9px',
            borderRadius: '4px', cursor: 'pointer',
            border: `1px solid ${exploitOnly ? 'rgba(234,88,12,0.4)' : '#2a2a2a'}`,
            color: exploitOnly ? '#EA580C' : '#3a3a44',
            background: exploitOnly ? 'rgba(234,88,12,0.1)' : 'transparent',
          }}
        >
          EXPLOIT
        </button>

        {/* Search */}
        <div style={{ position: 'relative', marginLeft: 'auto' }}>
          <Search size={12} style={{ position: 'absolute', left: '9px', top: '50%', transform: 'translateY(-50%)', color: '#3a3a44', pointerEvents: 'none' }} />
          <input
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1) }}
            placeholder="Search CVE, product…"
            style={{
              paddingLeft: '28px', paddingRight: '10px', paddingTop: '5px', paddingBottom: '5px',
              background: 'rgba(255,255,255,0.04)', border: '1px solid #2a2a2a',
              borderRadius: '6px', fontSize: '12px', color: '#c8ccd4', outline: 'none', width: '200px',
            }}
          />
        </div>
      </div>

      {/* Count */}
      <div style={{ fontSize: '11px', color: '#3a3a44', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <span>{isLoading ? '…' : `${total} vulnerabilities`}</span>
        {isFetching && !isLoading && (
          <RefreshCw size={10} style={{ color: '#3a3a44', animation: 'spin 1s linear infinite' }} />
        )}
      </div>

      {/* Table */}
      {isLoading ? (
        <div style={{ textAlign: 'center', padding: '40px', color: '#3a3a44', fontSize: '12px' }}>loading…</div>
      ) : items.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '64px 24px' }}>
          <svg width="48" height="48" viewBox="0 0 48 48" fill="none" style={{ margin: '0 auto 16px', display: 'block' }}>
            <path d="M24 4l18 10v20L24 44 6 34V14L24 4z" stroke="#27272a" strokeWidth="1.5" strokeLinejoin="round" />
            <path d="M24 4v40M6 14l18 10 18-10" stroke="#27272a" strokeWidth="1.5" strokeLinecap="round" />
            <circle cx="24" cy="24" r="4" fill="#3a3a44" />
          </svg>
          <div style={{ fontSize: '14px', fontWeight: 600, color: '#71717a', marginBottom: '6px' }}>
            No CVEs in database
          </div>
          <div style={{ fontSize: '12px', color: '#52525b', maxWidth: '260px', margin: '0 auto 20px', lineHeight: 1.6 }}>
            Run an assessment to populate version data, or trigger a sync to pull the latest NVD feed.
          </div>
        </div>
      ) : (
        <div className="card overflow-hidden">
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #1f1f1f' }}>
                {['CVE ID', 'Severity', 'CVSS', 'Products', 'Flags', 'Published', 'Relevance'].map((h) => (
                  <th key={h} style={{
                    textAlign: 'left', fontSize: '10px', fontWeight: 600, letterSpacing: '1.2px',
                    color: '#3a3a44', padding: '10px 14px', whiteSpace: 'nowrap',
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {items.map((v: VulnerabilityOut, idx: number) => (
                <VulnRow
                  key={v.id}
                  vuln={v}
                  isEven={idx % 2 === 0}
                  onClick={() => setSelectedCveId(v.cve_id)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div style={{ display: 'flex', gap: '6px', justifyContent: 'center', marginTop: '16px', flexWrap: 'wrap' }}>
          <button
            disabled={page === 1}
            onClick={() => setPage(1)}
            className="btn"
            style={{ fontSize: '11px', padding: '4px 10px' }}
          >
            «
          </button>
          <button
            disabled={page === 1}
            onClick={() => setPage((p) => p - 1)}
            className="btn"
            style={{ fontSize: '11px', padding: '4px 10px' }}
          >
            ‹
          </button>
          <span style={{ fontSize: '11px', color: '#71717A', display: 'flex', alignItems: 'center', padding: '0 8px' }}>
            {page} / {totalPages}
          </span>
          <button
            disabled={page >= totalPages}
            onClick={() => setPage((p) => p + 1)}
            className="btn"
            style={{ fontSize: '11px', padding: '4px 10px' }}
          >
            ›
          </button>
          <button
            disabled={page >= totalPages}
            onClick={() => setPage(totalPages)}
            className="btn"
            style={{ fontSize: '11px', padding: '4px 10px' }}
          >
            »
          </button>
        </div>
      )}

      {/* Detail slide-over */}
      {selectedCveId && (
        <VulnDetailPanel
          cveId={selectedCveId}
          onClose={() => setSelectedCveId(null)}
        />
      )}
    </div>
  )
}

function VulnRow({
  vuln,
  isEven,
  onClick,
}: {
  vuln: VulnerabilityOut
  isEven: boolean
  onClick: () => void
}) {
  const [hovered, setHovered] = useState(false)
  return (
    <tr
      onClick={onClick}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        borderBottom: '1px solid rgba(255,255,255,0.03)',
        background: hovered ? 'rgba(255,255,255,0.03)' : isEven ? 'rgba(255,255,255,0.01)' : 'transparent',
        cursor: 'pointer', transition: 'background 100ms',
      }}
    >
      <td style={{ padding: '10px 14px', fontSize: '12px', fontFamily: 'monospace', fontWeight: 500, color: '#c8ccd4', whiteSpace: 'nowrap' }}>
        {vuln.cve_id}
      </td>
      <td style={{ padding: '10px 14px' }}>
        <SevBadge severity={vuln.severity} />
      </td>
      <td style={{ padding: '10px 14px' }}>
        <CvssScore score={vuln.cvss_v3_score} />
      </td>
      <td style={{ padding: '10px 14px', fontSize: '12px', color: '#71717A', textAlign: 'center' }}>
        {vuln.affected_product_count}
      </td>
      <td style={{ padding: '10px 14px' }}>
        <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
          {vuln.in_cisa_kev && <KevBadge />}
          {vuln.exploit_available && <ExploitBadge />}
        </div>
      </td>
      <td style={{ padding: '10px 14px', fontSize: '11px', color: '#3a3a44', whiteSpace: 'nowrap' }}>
        {formatDate(vuln.published_at)}
      </td>
      <td style={{ padding: '10px 14px' }}>
        <RelevanceBadge relevance={vuln.relevance} />
      </td>
    </tr>
  )
}

function RelevanceBadge({ relevance }: { relevance: string }) {
  const colors: Record<string, string> = {
    direct: '#EF4444',
    infrastructure: '#EA580C',
    application: '#E5A93D',
    dependency: '#60A5FA',
    environmental: '#71717A',
    indirect: '#3a3a44',
    not_relevant: '#2a2a2a',
  }
  const color = colors[relevance] ?? '#3a3a44'
  return (
    <span style={{ fontSize: '10px', color, fontWeight: 500, letterSpacing: '0.3px' }}>
      {relevance.replace(/_/g, ' ')}
    </span>
  )
}

// ── Tab 2: Products ───────────────────────────────────────────────────────────

function ProductsTab({ onProductClick }: { onProductClick: (name: string) => void }) {
  const { data, isLoading } = useQuery({
    queryKey: ['intel', 'products'],
    queryFn: () => intelApi.listProducts(),
    staleTime: 60_000,
  })

  const products = data ?? []

  return (
    <div>
      {isLoading ? (
        <div style={{ textAlign: 'center', padding: '40px', color: '#3a3a44', fontSize: '12px' }}>loading…</div>
      ) : products.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: '48px', color: '#3a3a44', fontSize: '12px' }}>
          No products in database — trigger a sync first
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: '10px' }}>
          {products.map((p: ProductOut) => (
            <ProductCard key={p.id} product={p} onClick={() => onProductClick(p.canonical_name)} />
          ))}
        </div>
      )}
    </div>
  )
}

function ProductCard({ product, onClick }: { product: ProductOut; onClick: () => void }) {
  const [hovered, setHovered] = useState(false)
  const catColor = CAT_COLORS[product.category] ?? '#71717A'
  return (
    <div
      onClick={onClick}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        background: hovered ? 'rgba(255,255,255,0.04)' : 'rgba(255,255,255,0.025)',
        border: `1px solid ${hovered ? '#2a2a2a' : '#1f1f1f'}`,
        borderRadius: '8px', padding: '14px 16px',
        cursor: 'pointer', transition: 'all 150ms',
        display: 'flex', flexDirection: 'column', gap: '8px',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '8px' }}>
        <div style={{ fontSize: '13px', fontWeight: 600, color: '#c8ccd4' }}>{product.canonical_name}</div>
        {product.cve_count > 0 && (
          <span style={{
            fontSize: '11px', fontWeight: 700, color: '#EF4444',
            background: 'rgba(239,68,68,0.12)', border: '1px solid rgba(239,68,68,0.25)',
            padding: '2px 7px', borderRadius: '20px', flexShrink: 0,
          }}>
            {product.cve_count}
          </span>
        )}
      </div>
      {product.vendor && (
        <div style={{ fontSize: '11px', color: '#71717A' }}>{product.vendor}</div>
      )}
      <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
        <span style={{
          fontSize: '10px', padding: '2px 7px', borderRadius: '4px',
          color: catColor, background: `${catColor}18`, border: `1px solid ${catColor}30`,
          fontWeight: 500,
        }}>
          {product.category.replace(/_/g, ' ')}
        </span>
        {product.aliases.slice(0, 2).map((a, i) => (
          <span key={i} style={{
            fontSize: '10px', padding: '2px 7px', borderRadius: '4px',
            color: '#3a3a44', background: 'rgba(255,255,255,0.04)', border: '1px solid #2a2a2a',
          }}>
            {a}
          </span>
        ))}
        {product.aliases.length > 2 && (
          <span style={{ fontSize: '10px', color: '#3a3a44' }}>+{product.aliases.length - 2}</span>
        )}
      </div>
    </div>
  )
}

// ── Tab 3: Sync Status ────────────────────────────────────────────────────────

function SyncTab() {
  const { user } = useAuth()
  const qc = useQueryClient()
  const isAdmin = user?.is_platform_admin ?? false

  const { data, isLoading } = useQuery({
    queryKey: ['intel', 'sync-status'],
    queryFn: () => intelApi.getSyncStatus(),
    staleTime: 10_000,
    refetchInterval: (query) => {
      const items = query.state.data ?? []
      return items.some((s: SyncStatusOut) => s.is_running) ? 10_000 : false
    },
  })

  const syncMutation = useMutation({
    mutationFn: (source: string) => intelApi.triggerSync(source),
    onSuccess: (_, source) => {
      toast.success(`Sync started: ${source}`)
      qc.invalidateQueries({ queryKey: ['intel', 'sync-status'] })
    },
    onError: () => toast.error('Failed to trigger sync'),
  })

  const statuses = data ?? []

  return (
    <div>
      {isAdmin && (
        <div style={{ marginBottom: '12px', display: 'flex', justifyContent: 'flex-end' }}>
          <button
            onClick={() => syncMutation.mutate('all')}
            disabled={syncMutation.isPending}
            className="btn-primary"
            style={{ fontSize: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            <RefreshCw size={12} />
            Sync All
          </button>
        </div>
      )}

      {isLoading ? (
        <div style={{ textAlign: 'center', padding: '40px', color: '#3a3a44', fontSize: '12px' }}>loading…</div>
      ) : (
        <div className="card overflow-hidden">
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #1f1f1f' }}>
                {['Source', 'Last Success', 'Added', 'Updated', 'Failed', 'Status', ...(isAdmin ? ['Action'] : [])].map((h) => (
                  <th key={h} style={{
                    textAlign: 'left', fontSize: '10px', fontWeight: 600, letterSpacing: '1.2px',
                    color: '#3a3a44', padding: '10px 14px', whiteSpace: 'nowrap',
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {statuses.map((s: SyncStatusOut) => (
                <SyncRow key={s.source_name} status={s} isAdmin={isAdmin}
                  onSync={() => syncMutation.mutate(s.source_name.toLowerCase())}
                  syncing={syncMutation.isPending} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function SyncRow({
  status,
  isAdmin,
  onSync,
  syncing,
}: {
  status: SyncStatusOut
  isAdmin: boolean
  onSync: () => void
  syncing: boolean
}) {
  return (
    <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
      <td style={{ padding: '10px 14px', fontSize: '12px', fontWeight: 500, color: '#c8ccd4' }}>
        {status.source_name}
      </td>
      <td style={{ padding: '10px 14px', fontSize: '11px', color: '#71717A' }}>
        {formatDate(status.last_success_at)}
      </td>
      <td style={{ padding: '10px 14px', fontSize: '12px', color: '#36B37E', textAlign: 'center' }}>
        {status.records_added}
      </td>
      <td style={{ padding: '10px 14px', fontSize: '12px', color: '#60A5FA', textAlign: 'center' }}>
        {status.records_updated}
      </td>
      <td style={{ padding: '10px 14px', fontSize: '12px', color: status.records_failed > 0 ? '#EF4444' : '#3a3a44', textAlign: 'center' }}>
        {status.records_failed}
      </td>
      <td style={{ padding: '10px 14px' }}>
        {status.is_running ? (
          <span style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '11px', color: '#E5A93D' }}>
            <RefreshCw size={10} style={{ animation: 'spin 1s linear infinite' }} />
            Running
          </span>
        ) : status.error_msg ? (
          <span title={status.error_msg} style={{ fontSize: '11px', color: '#EF4444' }}>Error</span>
        ) : status.last_success_at ? (
          <span style={{ fontSize: '11px', color: '#36B37E' }}>OK</span>
        ) : (
          <span style={{ fontSize: '11px', color: '#3a3a44' }}>Never</span>
        )}
      </td>
      {isAdmin && (
        <td style={{ padding: '10px 14px' }}>
          <button
            onClick={onSync}
            disabled={syncing || status.is_running}
            style={{
              fontSize: '11px', padding: '3px 10px', borderRadius: '5px',
              background: 'rgba(255,255,255,0.04)', border: '1px solid #2a2a2a',
              color: '#71717A', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '4px',
            }}
          >
            <RefreshCw size={10} />
            Sync
          </button>
        </td>
      )}
    </tr>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

type TabId = 'vulnerabilities' | 'products' | 'sync'

const TABS: Array<{ id: TabId; label: string; icon: typeof Shield }> = [
  { id: 'vulnerabilities', label: 'Vulnerabilities', icon: Shield },
  { id: 'products', label: 'Products', icon: Database },
  { id: 'sync', label: 'Sync Status', icon: RefreshCw },
]

export default function IntelDashboard() {
  const [activeTab, setActiveTab] = useState<TabId>('vulnerabilities')
  const [productFilter, setProductFilter] = useState('')

  function handleProductClick(name: string) {
    setProductFilter(name)
    setActiveTab('vulnerabilities')
  }

  return (
    <div>
      <PageHeader
        title="CVE Intelligence"
        subtitle="Vulnerability database — NVD · CISA KEV · OSV"
      />

      {/* Tab bar */}
      <div style={{ display: 'flex', gap: '2px', marginBottom: '20px', borderBottom: '1px solid #1f1f1f', paddingBottom: '0' }}>
        {TABS.map(({ id, label, icon: Icon }) => {
          const active = activeTab === id
          return (
            <button
              key={id}
              onClick={() => setActiveTab(id)}
              style={{
                display: 'flex', alignItems: 'center', gap: '6px',
                fontSize: '12px', fontWeight: active ? 600 : 400,
                padding: '8px 14px', background: 'transparent', border: 'none',
                cursor: 'pointer', borderBottom: active ? '2px solid var(--color-accent)' : '2px solid transparent',
                color: active ? '#c8ccd4' : '#3a3a44',
                marginBottom: '-1px', transition: 'color 150ms',
              }}
            >
              <Icon size={12} />
              {label}
            </button>
          )
        })}
      </div>

      {/* Tab content */}
      {activeTab === 'vulnerabilities' && (
        <VulnerabilitiesTab initialProduct={productFilter} />
      )}
      {activeTab === 'products' && (
        <ProductsTab onProductClick={handleProductClick} />
      )}
      {activeTab === 'sync' && (
        <SyncTab />
      )}

      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
      `}</style>
    </div>
  )
}
