import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { BookOpen, AlertTriangle, Layers, Download, FileText } from 'lucide-react'
import { PageHeader } from '../components/Layout'
import { RiskScore } from '../components/RiskScore'
import { ScanStatusBadge } from '../components/StatusBadge'
import { useAuth } from '../lib/auth'
import { reports as reportsApi, scans as scansApi } from '../lib/api'
import type { Scan } from '../types'

type ReportType = 'executive' | 'technical' | 'full'
type ReportFormat = 'json' | 'html' | 'pdf' | 'csv'

const REPORT_TYPES: {
  id: ReportType
  label: string
  description: string
  detail: string
  icon: typeof FileText
}[] = [
  {
    id: 'executive',
    label: 'Executive',
    description: 'For stakeholders & management',
    detail: 'CRITICAL & HIGH findings only. Top 20 issues. No technical evidence.',
    icon: BookOpen,
  },
  {
    id: 'technical',
    label: 'Technical',
    description: 'For security engineers',
    detail: 'All findings with evidence, reproduction steps and remediation guidance.',
    icon: AlertTriangle,
  },
  {
    id: 'full',
    label: 'Full',
    description: 'Complete audit document',
    detail: 'All findings, evidence, methodology, CVE references and risk scoring.',
    icon: Layers,
  },
]

const FORMAT_META: Record<ReportFormat, { label: string; hint: string }> = {
  pdf:  { label: 'PDF',  hint: 'Opens in a new tab — use "Save as PDF" from the print dialog.' },
  html: { label: 'HTML', hint: 'Styled document. Open in browser or attach to email.' },
  json: { label: 'JSON', hint: 'Machine-readable. Full data, nested structure.' },
  csv:  { label: 'CSV',  hint: 'Flat table. Import into spreadsheets or SIEM.' },
}

export default function Reports() {
  const { currentOrg } = useAuth()
  const orgId = currentOrg?.id ?? ''
  const [searchParams] = useSearchParams()

  const [selectedScan, setSelectedScan] = useState(searchParams.get('scan_id') ?? '')
  const [reportType, setReportType] = useState<ReportType>('full')
  const [format, setFormat] = useState<ReportFormat>('json')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const { data: scanList = [] } = useQuery({
    queryKey: ['scans', orgId],
    queryFn: () => scansApi.list(orgId, 50, 0),
    enabled: !!orgId,
  })

  const eligibleScans = scanList.filter((s) => s.status === 'completed' || s.status === 'partial')
  const activeScan = eligibleScans.find((s) => s.id === selectedScan) ?? null

  async function handleDownload() {
    if (!selectedScan) return
    setError(null)
    setLoading(true)
    try {
      const slug = `mailox-${reportType}-${selectedScan.slice(0, 8)}`
      if (format === 'pdf') {
        // PDF = HTML opened in new tab + auto-print (browser "Save as PDF")
        const html = await reportsApi.download(orgId, selectedScan, reportType, 'html')
        const blob = new Blob([html as string], { type: 'text/html' })
        const url = URL.createObjectURL(blob)
        const win = window.open(url + '#print', '_blank')
        if (win) win.addEventListener('unload', () => URL.revokeObjectURL(url))
      } else {
        const data = await reportsApi.download(orgId, selectedScan, reportType, format)
        if (format === 'json') {
          downloadBlob(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }), `${slug}.json`)
        } else if (format === 'html') {
          downloadBlob(new Blob([data as string], { type: 'text/html' }), `${slug}.html`)
        } else {
          downloadBlob(data as Blob, `${slug}.csv`)
        }
      }
    } catch (err: unknown) {
      setError(
        (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
          'Report generation failed'
      )
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <PageHeader title="Reports" subtitle="Generate and export assessment reports" />

      <div className="reports-grid">
        {/* ── Left: config ── */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>

          {/* Selected scan preview */}
          <section>
            <div style={{ fontSize: '11px', letterSpacing: '0.12em', textTransform: 'uppercase', color: '#3a3a44', fontWeight: 600, marginBottom: '12px' }}>
              Selected assessment
            </div>
            {activeScan ? (
              <div style={{
                borderRadius: '10px',
                border: '1px solid rgba(229,57,53,0.25)',
                background: 'linear-gradient(135deg, rgba(229,57,53,0.05) 0%, rgba(229,57,53,0.02) 100%)',
                padding: '18px 20px',
              }}>
                <div style={{ fontSize: '14px', fontWeight: 600, color: '#e8ecf2', marginBottom: '10px', fontFamily: '"JetBrains Mono", monospace' }}>
                  {activeScan.target_domain}
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                  <MetaItem label="Status" value={<ScanStatusBadge status={activeScan.status} />} />
                  <MetaItem label="Risk score" value={<RiskScore score={activeScan.risk_score} size="sm" showLabel />} />
                  <MetaItem label="Findings" value={<span style={{ fontSize: '13px', color: '#c8ccd4', fontFamily: '"JetBrains Mono", monospace' }}>{activeScan.finding_count}</span>} />
                  <MetaItem label="Date" value={<span style={{ fontSize: '12px', color: '#71717a' }}>{new Date(activeScan.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}</span>} />
                </div>
              </div>
            ) : (
              <div style={{
                borderRadius: '10px',
                border: '1px dashed #1f1f26',
                padding: '24px 20px',
                textAlign: 'center',
                color: '#3a3a44',
                fontSize: '12px',
                letterSpacing: '0.3px',
              }}>
                Select an assessment →
              </div>
            )}
          </section>

          {/* Report type */}
          <section>
            <div style={{ fontSize: '11px', letterSpacing: '0.12em', textTransform: 'uppercase', color: '#3a3a44', fontWeight: 600, marginBottom: '12px' }}>
              Report type
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {REPORT_TYPES.map(({ id, label, description, detail, icon: Icon }) => {
                const active = reportType === id
                return (
                  <button
                    key={id}
                    onClick={() => setReportType(id)}
                    style={{
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: '14px',
                      padding: '16px 18px',
                      borderRadius: '9px',
                      border: active ? '1px solid rgba(229,57,53,0.4)' : '1px solid #1a1a1f',
                      background: active
                        ? 'linear-gradient(135deg, rgba(229,57,53,0.07) 0%, rgba(229,57,53,0.03) 100%)'
                        : 'rgba(255,255,255,0.02)',
                      cursor: 'pointer',
                      textAlign: 'left',
                      transition: 'border-color 150ms, background 150ms',
                      width: '100%',
                    }}
                    onMouseEnter={(e) => { if (!active) (e.currentTarget as HTMLElement).style.borderColor = '#2a2a30' }}
                    onMouseLeave={(e) => { if (!active) (e.currentTarget as HTMLElement).style.borderColor = '#1a1a1f' }}
                  >
                    <div style={{
                      width: '32px', height: '32px', borderRadius: '8px', flexShrink: 0,
                      background: active ? 'rgba(229,57,53,0.12)' : 'rgba(255,255,255,0.04)',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      transition: 'background 150ms',
                    }}>
                      <Icon size={14} style={{ color: active ? 'var(--color-accent)' : '#52525b', transition: 'color 150ms' }} />
                    </div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', marginBottom: '3px' }}>
                        <span style={{ fontSize: '13px', fontWeight: 600, color: active ? '#e8ecf2' : '#a1a1aa', transition: 'color 150ms' }}>
                          {label}
                        </span>
                        <span style={{ fontSize: '11px', color: '#3a3a44' }}>{description}</span>
                      </div>
                      <div style={{ fontSize: '11px', color: '#52525b', lineHeight: 1.5 }}>{detail}</div>
                    </div>
                    {active && (
                      <div style={{
                        width: '6px', height: '6px', borderRadius: '50%',
                        background: 'var(--color-accent)', flexShrink: 0, marginTop: '5px',
                      }} />
                    )}
                  </button>
                )
              })}
            </div>
          </section>

          {/* Format */}
          <section>
            <div style={{ fontSize: '11px', letterSpacing: '0.12em', textTransform: 'uppercase', color: '#3a3a44', fontWeight: 600, marginBottom: '12px' }}>
              Export format
            </div>
            <div style={{ display: 'flex', gap: '6px', marginBottom: '10px' }}>
              {(['pdf', 'html', 'json', 'csv'] as const).map((f) => {
                const active = format === f
                return (
                  <button
                    key={f}
                    onClick={() => setFormat(f)}
                    style={{
                      flex: 1,
                      padding: '10px 8px',
                      fontSize: '11px',
                      fontWeight: 600,
                      letterSpacing: '0.1em',
                      textTransform: 'uppercase',
                      fontFamily: '"JetBrains Mono", monospace',
                      borderRadius: '7px',
                      border: active ? '1px solid rgba(229,57,53,0.4)' : '1px solid #1a1a1f',
                      background: active ? 'rgba(229,57,53,0.08)' : 'rgba(255,255,255,0.02)',
                      color: active ? '#e8ecf2' : '#52525b',
                      cursor: 'pointer',
                      transition: 'all 150ms',
                    }}
                  >
                    {FORMAT_META[f].label}
                  </button>
                )
              })}
            </div>
            <div style={{ fontSize: '11px', color: '#52525b', lineHeight: 1.5 }}>
              {FORMAT_META[format].hint}
            </div>
          </section>

          {/* Error */}
          {error && (
            <div style={{
              fontSize: '12px', padding: '12px 14px', borderRadius: '8px',
              color: '#f87171',
              background: 'rgba(239,68,68,0.06)',
              border: '1px solid rgba(239,68,68,0.2)',
            }}>
              {error}
            </div>
          )}

          {/* Download */}
          <button
            onClick={handleDownload}
            disabled={!selectedScan || loading}
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '8px',
              padding: '14px 20px',
              borderRadius: '9px',
              fontSize: '13px',
              fontWeight: 600,
              letterSpacing: '0.02em',
              border: 'none',
              cursor: !selectedScan || loading ? 'not-allowed' : 'pointer',
              opacity: !selectedScan || loading ? 0.4 : 1,
              background: 'var(--color-accent)',
              color: '#fff',
              transition: 'opacity 150ms, transform 100ms',
              width: '100%',
            }}
            onMouseEnter={(e) => { if (selectedScan && !loading) (e.currentTarget as HTMLElement).style.transform = 'translateY(-1px)' }}
            onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.transform = '' }}
          >
            <Download size={14} />
            {loading ? 'Generating…' : format === 'pdf' ? 'Open PDF preview' : 'Download report'}
          </button>
        </div>

        {/* ── Right: scan list ── */}
        <div>
          <div style={{ fontSize: '11px', letterSpacing: '0.12em', textTransform: 'uppercase', color: '#3a3a44', fontWeight: 600, marginBottom: '12px' }}>
            Completed assessments
            {eligibleScans.length > 0 && (
              <span style={{ marginLeft: '8px', color: '#2a2a34', fontWeight: 400 }}>
                {eligibleScans.length}
              </span>
            )}
          </div>

          {eligibleScans.length === 0 ? (
            <div style={{
              borderRadius: '10px',
              border: '1px dashed #1f1f26',
              padding: '48px 24px',
              textAlign: 'center',
            }}>
              <div style={{ fontSize: '12px', color: '#3a3a44', marginBottom: '6px' }}>No completed assessments</div>
              <div style={{ fontSize: '11px', color: '#2a2a34' }}>Run a scan first to generate reports</div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {eligibleScans.map((s) => (
                <ScanCard
                  key={s.id}
                  scan={s}
                  selected={s.id === selectedScan}
                  onSelect={() => setSelectedScan(s.id === selectedScan ? '' : s.id)}
                />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function ScanCard({ scan, selected, onSelect }: { scan: Scan; selected: boolean; onSelect: () => void }) {
  const date = new Date(scan.created_at)
  return (
    <button
      onClick={onSelect}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '14px',
        padding: '14px 16px',
        borderRadius: '9px',
        border: selected ? '1px solid rgba(229,57,53,0.35)' : '1px solid #1a1a1f',
        background: selected
          ? 'linear-gradient(135deg, rgba(229,57,53,0.07) 0%, rgba(229,57,53,0.02) 100%)'
          : 'rgba(255,255,255,0.015)',
        cursor: 'pointer',
        textAlign: 'left',
        width: '100%',
        transition: 'border-color 150ms, background 150ms',
      }}
      onMouseEnter={(e) => { if (!selected) (e.currentTarget as HTMLElement).style.borderColor = '#2a2a30' }}
      onMouseLeave={(e) => { if (!selected) (e.currentTarget as HTMLElement).style.borderColor = '#1a1a1f' }}
    >
      {/* Selection indicator */}
      <div style={{
        width: '8px', height: '8px', borderRadius: '50%', flexShrink: 0,
        border: selected ? 'none' : '1px solid #2a2a34',
        background: selected ? 'var(--color-accent)' : 'transparent',
        boxShadow: selected ? '0 0 6px rgba(229,57,53,0.5)' : 'none',
        transition: 'all 150ms',
      }} />

      {/* Domain + date */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{
          fontSize: '13px', fontWeight: 500,
          color: selected ? '#e8ecf2' : '#a1a1aa',
          fontFamily: '"JetBrains Mono", monospace',
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
          marginBottom: '3px',
          transition: 'color 150ms',
        }}>
          {scan.target_domain}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontSize: '11px', color: '#3a3a44' }}>
            {date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}
          </span>
          <ScanStatusBadge status={scan.status} />
        </div>
      </div>

      {/* Stats */}
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '4px', flexShrink: 0 }}>
        <RiskScore score={scan.risk_score} size="sm" showLabel />
        <span style={{ fontSize: '11px', color: '#3a3a44', fontFamily: '"JetBrains Mono", monospace' }}>
          {scan.finding_count} findings
        </span>
      </div>
    </button>
  )
}

function MetaItem({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <div style={{ fontSize: '10px', letterSpacing: '0.1em', textTransform: 'uppercase', color: '#3a3a44', marginBottom: '4px' }}>
        {label}
      </div>
      {value}
    </div>
  )
}

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}
