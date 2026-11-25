import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { scans as scansApi } from '../lib/api'
import { ScanStatusBadge } from './StatusBadge'
import { RiskScore } from './RiskScore'
import type { Scan } from '../types'

interface ScanHistoryTimelineProps {
  domain: string
  orgId: string
  currentScanId: string
}

export function ScanHistoryTimeline({ domain, orgId, currentScanId }: ScanHistoryTimelineProps) {
  const { data: allScans, isLoading } = useQuery<Scan[]>({
    queryKey: ['scans', orgId],
    queryFn: () => scansApi.list(orgId, 50, 0),
    enabled: !!orgId,
    staleTime: 30_000,
  })

  if (isLoading) return null

  const domainScans = (allScans ?? [])
    .filter(s => s.target_domain === domain)
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
    .slice(0, 10)

  if (domainScans.length <= 1) {
    return (
      <div className="card p-4 mb-4">
        <div className="label mb-2">Scan History</div>
        <div className="text-sm text-text-muted italic">No previous scans for {domain}</div>
      </div>
    )
  }

  return (
    <div className="card overflow-hidden mb-4">
      <div className="px-4 py-2.5 border-b border-border flex items-center justify-between">
        <span className="label">Scan History</span>
        <span className="text-xs text-text-muted font-mono">{domain}</span>
      </div>
      <div className="divide-y divide-border/50">
        {domainScans.map(s => {
          const isCurrent = s.id === currentScanId
          return (
            <Link
              key={s.id}
              to={`/assessments/${s.id}`}
              style={{ textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '10px' }}
              className={`px-4 py-2.5 hover:bg-bg-elevated/50 transition-colors ${isCurrent ? 'bg-bg-elevated/40' : ''}`}
            >
              {/* current indicator dot */}
              <span
                style={{
                  width: '5px',
                  height: '5px',
                  borderRadius: '50%',
                  flexShrink: 0,
                  background: isCurrent ? 'var(--color-accent)' : 'transparent',
                  border: isCurrent ? 'none' : '1px solid transparent',
                }}
              />
              <span
                className="text-xs font-mono text-text-muted"
                style={{ minWidth: '130px', flexShrink: 0 }}
              >
                {new Date(s.created_at).toLocaleString('en-GB', {
                  day: '2-digit',
                  month: 'short',
                  year: 'numeric',
                  hour: '2-digit',
                  minute: '2-digit',
                  hour12: false,
                })}
              </span>
              <ScanStatusBadge status={s.status} />
              {s.risk_score !== null && (
                <RiskScore score={s.risk_score} size="sm" showLabel />
              )}
              <span className="text-xs text-text-muted" style={{ marginLeft: 'auto', flexShrink: 0 }}>
                {s.finding_count} finding{s.finding_count !== 1 ? 's' : ''}
              </span>
            </Link>
          )
        })}
      </div>
    </div>
  )
}
