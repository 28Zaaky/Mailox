import React, { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import {
  AlertTriangle,
  ArrowLeft,
  Calendar,
  ChevronDown,
  Clock,
  ExternalLink,
  Server,
  Shield,
  Zap,
} from 'lucide-react'
import { SeverityBadge } from '../components/SeverityBadge'
import { useAuth } from '../lib/auth'
import { findings as findingsApi } from '../lib/api'
import type { FindingStatus } from '../types'

const STATUS_OPTIONS: { value: FindingStatus; label: string; color: string }[] = [
  { value: 'open', label: 'Open', color: '#666672' },
  { value: 'confirmed', label: 'Confirmed', color: '#E8173A' },
  { value: 'in_remediation', label: 'In Remediation', color: '#CA8A04' },
  { value: 'accepted_risk', label: 'Accepted Risk', color: '#7C3AED' },
  { value: 'resolved', label: 'Resolved', color: '#3fb950' },
  { value: 'false_positive', label: 'False Positive', color: '#3a3a44' },
]

function formatDate(iso: string | null): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

export default function FindingDetail() {
  const { findingId } = useParams<{ findingId: string }>()
  const qc = useQueryClient()
  const { currentOrg } = useAuth()
  const orgId = currentOrg?.id ?? ''

  const [statusMenuOpen, setStatusMenuOpen] = useState(false)

  const { data: finding, isLoading, error } = useQuery({
    queryKey: ['finding', orgId, findingId],
    queryFn: () => findingsApi.get(orgId, findingId!),
    enabled: !!orgId && !!findingId,
  })

  const mutation = useMutation({
    mutationFn: (status: FindingStatus) => findingsApi.updateStatus(orgId, findingId!, status),
    onSuccess: (updated) => {
      qc.setQueryData(['finding', orgId, findingId], updated)
      qc.invalidateQueries({ queryKey: ['findings', orgId] })
      qc.invalidateQueries({ queryKey: ['findings-summary', orgId] })
      qc.invalidateQueries({ queryKey: ['org-stats', orgId] })
      toast.success(`Status updated to ${updated.status.replace('_', ' ')}`)
      setStatusMenuOpen(false)
    },
    onError: () => toast.error('Failed to update status'),
  })

  if (isLoading) {
    return (
      <div>
        <div className="h-4 w-48 bg-bg-elevated animate-pulse mb-8" />
        <div className="card p-6 space-y-4">
          {[1,2,3,4].map(i => <div key={i} className="h-4 bg-bg-elevated animate-pulse" />)}
        </div>
      </div>
    )
  }

  if (error || !finding) {
    return (
      <div>
        <div className="card p-8 text-center">
          <AlertTriangle size={24} style={{ color: '#E8173A', margin: '0 auto 12px' }} />
          <div className="text-sm text-text-muted">Finding not found or access denied.</div>
          <Link to="/findings" className="btn-secondary mt-4" style={{ display: 'inline-flex' }}>
            Back to Findings
          </Link>
        </div>
      </div>
    )
  }

  const currentStatus = STATUS_OPTIONS.find(s => s.value === finding.status)

  return (
    <div style={{ width: '100%' }}>
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 mb-5 text-xs text-text-muted" style={{ letterSpacing: '0.5px' }}>
        <Link
          to="/findings"
          className="flex items-center gap-1.5"
          style={{ transition: 'color 150ms var(--ease-out)' }}
          onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.color = '#c8ccd4' }}
          onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.color = '' }}
        >
          <ArrowLeft size={12} />
          Findings
        </Link>
        <span style={{ color: '#1f1f1f' }}>/</span>
        <span className="text-text-primary truncate max-w-xs">{finding.title}</span>
      </div>

      {/* Header */}
      <div className="card glow-card mb-5" style={{ padding: '20px 24px' }}>
        <div className="flex items-start justify-between gap-4 mb-3">
          <h1 style={{ fontSize: '16px', fontWeight: 600, color: '#F5F5F5', lineHeight: 1.4, fontFamily: "'Space Grotesk', sans-serif", flex: 1 }}>
            {finding.title}
          </h1>
          <SeverityBadge level={finding.risk_level} size="md" />
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          {/* Status dropdown */}
          <div className="relative">
            <button
              onClick={() => setStatusMenuOpen(o => !o)}
              className="flex items-center gap-2 text-xs"
              style={{
                color: currentStatus?.color ?? '#666672',
                border: `1px solid ${currentStatus?.color ?? '#3a3a44'}40`,
                background: `${currentStatus?.color ?? '#666672'}0A`,
                cursor: 'pointer',
                padding: '4px 12px',
                borderRadius: '20px',
                letterSpacing: '0.3px',
                transition: 'opacity 150ms var(--ease-out)',
              }}
            >
              {currentStatus?.label ?? finding.status.replace(/_/g, ' ')}
              <ChevronDown size={10} style={{ transform: statusMenuOpen ? 'rotate(180deg)' : 'none', transition: 'transform 200ms var(--ease-out)' }} />
            </button>
            {statusMenuOpen && (
              <div
                className="absolute left-0 mt-1 border border-border z-50 overflow-hidden"
                style={{ background: '#121212', minWidth: '180px', borderRadius: '8px', animation: 'cardEnter 150ms var(--ease-out) both' }}
              >
                {STATUS_OPTIONS.map(opt => (
                  <button
                    key={opt.value}
                    onClick={() => mutation.mutate(opt.value)}
                    disabled={mutation.isPending}
                    className="w-full text-left px-3 py-2 text-xs"
                    style={{
                      color: opt.value === finding.status ? opt.color : '#666672',
                      background: opt.value === finding.status ? 'rgba(26,26,26,0.5)' : 'transparent',
                      border: 'none', cursor: 'pointer', letterSpacing: '0.5px',
                      transition: 'background-color 150ms var(--ease-out), color 150ms var(--ease-out)',
                    }}
                    onMouseEnter={(e) => { const el = e.currentTarget as HTMLElement; el.style.backgroundColor = 'rgba(26,26,26,0.8)'; el.style.color = opt.color }}
                    onMouseLeave={(e) => { const el = e.currentTarget as HTMLElement; el.style.backgroundColor = opt.value === finding.status ? 'rgba(26,26,26,0.5)' : 'transparent'; el.style.color = opt.value === finding.status ? opt.color : '#666672' }}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            )}
          </div>

          <span style={{ color: '#3a3a44', fontSize: '11px' }}>·</span>
          <span className="text-xs text-text-muted">{finding.engine}</span>
          <span style={{ color: '#3a3a44', fontSize: '11px' }}>·</span>
          <span className="text-xs text-text-muted">{Math.round(finding.confidence * 100)}% confidence</span>

          {finding.cvss_score !== null && (
            <>
              <span style={{ color: '#3a3a44', fontSize: '11px' }}>·</span>
              <span className="text-xs tabular-nums" style={{ color: '#E8173A', border: '1px solid rgba(232,23,58,0.3)', padding: '2px 8px', borderRadius: '4px' }}>
                CVSS {finding.cvss_score.toFixed(1)}
              </span>
            </>
          )}
        </div>
      </div>

      {/* 2-column layout */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 320px', gap: '16px', alignItems: 'start' }}>

        {/* LEFT — description + evidence + references */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>

          {/* Description */}
          <div className="card glow-card p-6 card-enter" style={{ '--stagger-delay': '0ms' } as React.CSSProperties}>
            <div className="label mb-3">Description</div>
            <p className="text-sm text-text-secondary" style={{ lineHeight: 1.8 }}>
              {finding.description}
            </p>
          </div>

          {/* Evidence */}
          {finding.evidence.length > 0 && (
            <div className="card glow-card p-6 card-enter" style={{ '--stagger-delay': '50ms' } as React.CSSProperties}>
              <div className="label mb-4">Technical Evidence</div>
              <div className="space-y-3">
                {finding.evidence.map((ev, i) => (
                  <div key={i} className="border border-border p-4" style={{ background: 'rgba(26,26,26,0.3)', borderRadius: '6px' }}>
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-xs" style={{ color: '#3a3a44', border: '1px solid #1f1f1f', padding: '1px 6px', borderRadius: '4px' }}>
                        {ev.type}
                      </span>
                      <span className="text-xs text-text-muted">{ev.source}</span>
                    </div>
                    <div className="text-xs text-text-secondary" style={{ wordBreak: 'break-all' }}>
                      {ev.observed_value}
                    </div>
                    {ev.technical_details && Object.keys(ev.technical_details).length > 0 && (
                      <details className="mt-2">
                        <summary className="text-xs text-text-muted cursor-pointer">Technical details</summary>
                        <pre className="text-xs text-text-muted mt-2 overflow-auto" style={{ maxHeight: '200px' }}>
                          {JSON.stringify(ev.technical_details, null, 2)}
                        </pre>
                      </details>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* References */}
          {finding.references.length > 0 && (
            <div className="card glow-card p-6 card-enter" style={{ '--stagger-delay': '80ms' } as React.CSSProperties}>
              <div className="label mb-4">References</div>
              <div className="space-y-2">
                {finding.references.map((ref, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <ExternalLink size={12} style={{ color: '#3a3a44', flexShrink: 0 }} />
                    <a
                      href={ref}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-sm text-text-muted break-all"
                      style={{ transition: 'color 150ms var(--ease-out)' }}
                      onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.color = '#E8173A' }}
                      onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.color = '' }}
                    >
                      {ref}
                    </a>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* RIGHT — meta sidebar */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>

          {/* Discovery Details */}
          <div className="card glow-card p-5 card-enter" style={{ '--stagger-delay': '30ms' } as React.CSSProperties}>
            <div className="label mb-4">Discovery Details</div>
            <div className="space-y-3">
              <MetaRow icon={Server} label="Affected Asset" value={finding.affected_asset ?? 'Unknown'} empty={!finding.affected_asset} />
              <MetaRow icon={Calendar} label="Discovered" value={formatDate(finding.created_at)} />
              <MetaRow icon={Clock} label="Last Seen" value={formatDate(finding.last_seen_at)} />
              <MetaRow icon={Zap} label="Engine" value={finding.engine} />
              <MetaRow icon={Shield} label="Check ID" value={finding.check_id} mono />
            </div>
          </div>

          {/* Remediation */}
          <div className="card glow-card p-5 card-enter" style={{ '--stagger-delay': '60ms' } as React.CSSProperties}>
            <div className="label mb-3">Remediation</div>
            <p className="text-sm text-text-secondary" style={{ lineHeight: 1.8 }}>
              {finding.remediation || 'No remediation guidance available.'}
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

function MetaRow({
  icon: Icon,
  label,
  value,
  empty = false,
  mono = false,
}: {
  icon: React.ComponentType<{ size?: number; style?: React.CSSProperties }>
  label: string
  value: string
  empty?: boolean
  mono?: boolean
}) {
  return (
    <div className="flex items-start gap-3">
      <Icon size={13} style={{ color: '#3a3a44', flexShrink: 0, marginTop: '2px' }} />
      <div className="flex-1 min-w-0">
        <div className="text-xs text-text-muted mb-0.5" style={{ letterSpacing: '1.5px' }}>
          {label.toUpperCase()}
        </div>
        <div
          className="text-sm"
          style={{
            color: empty ? '#3a3a44' : '#c8ccd4',
            letterSpacing: mono ? '0.5px' : '0.3px',
            fontStyle: empty ? 'italic' : 'normal',
            wordBreak: 'break-all',
          }}
        >
          {value}
        </div>
      </div>
    </div>
  )
}
