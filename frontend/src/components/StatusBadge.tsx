import type { FindingStatus, ScanStatus } from '../types'

const SCAN: Record<ScanStatus, { color: string; bg: string; border: string }> = {
  pending:   { color: '#71717A', bg: 'rgba(113,113,122,0.06)', border: 'rgba(113,113,122,0.2)' },
  queued:    { color: '#71717A', bg: 'rgba(113,113,122,0.06)', border: 'rgba(113,113,122,0.2)' },
  running:   { color: '#60A5FA', bg: 'rgba(96,165,250,0.08)',  border: 'rgba(96,165,250,0.25)' },
  completed: { color: '#36B37E', bg: 'rgba(54,179,126,0.08)', border: 'rgba(54,179,126,0.25)' },
  partial:   { color: '#E5A93D', bg: 'rgba(229,169,61,0.08)', border: 'rgba(229,169,61,0.25)' },
  failed:    { color: '#EF4444', bg: 'rgba(239,68,68,0.08)',  border: 'rgba(239,68,68,0.25)'  },
  cancelled: { color: '#71717A', bg: 'rgba(113,113,122,0.06)', border: 'rgba(113,113,122,0.2)' },
}

const FINDING: Record<FindingStatus, { color: string; bg: string; border: string }> = {
  open:            { color: '#71717A', bg: 'rgba(113,113,122,0.06)', border: 'rgba(113,113,122,0.2)'  },
  confirmed:       { color: '#EF4444', bg: 'rgba(239,68,68,0.08)',   border: 'rgba(239,68,68,0.25)'   },
  in_remediation:  { color: '#E5A93D', bg: 'rgba(229,169,61,0.08)',  border: 'rgba(229,169,61,0.25)'  },
  accepted_risk:   { color: '#8B5CF6', bg: 'rgba(139,92,246,0.08)',  border: 'rgba(139,92,246,0.25)'  },
  resolved:        { color: '#36B37E', bg: 'rgba(54,179,126,0.08)',  border: 'rgba(54,179,126,0.25)'  },
  false_positive:  { color: '#52525B', bg: 'rgba(82,82,91,0.06)',    border: 'rgba(82,82,91,0.2)'     },
}

const FALLBACK = { color: '#71717A', bg: 'rgba(113,113,122,0.06)', border: 'rgba(113,113,122,0.2)' }

function Pill({ color, bg, border, label, pulse }: { color: string; bg: string; border: string; label: string; pulse?: boolean; pulseSlow?: boolean }) {
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '5px',
      fontSize: '11px', fontWeight: 500,
      padding: '3px 10px', borderRadius: '20px',
      color, background: bg, border: `1px solid ${border}`,
      whiteSpace: 'nowrap',
    }}>
      <span
        className={pulse ? 'dot-pulse' : ''}
        style={{ width: '5px', height: '5px', borderRadius: '50%', background: color, flexShrink: 0, color }}
      />
      {label}
    </span>
  )
}

export function ScanStatusBadge({ status }: { status: ScanStatus }) {
  const s = SCAN[status] ?? FALLBACK
  return <Pill {...s} label={status} pulse={status === 'running' || status === 'queued'} />
}

export function FindingStatusBadge({ status }: { status: FindingStatus | string }) {
  const s = FINDING[status as FindingStatus] ?? FALLBACK
  return <Pill {...s} label={status.replace(/_/g, ' ')} />
}
