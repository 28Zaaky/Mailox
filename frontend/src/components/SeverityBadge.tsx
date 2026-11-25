import type { RiskLevel } from '../types'

const SEV: Record<RiskLevel, { color: string; bg: string; border: string }> = {
  critical: { color: '#EF4444', bg: 'rgba(239,68,68,0.09)',   border: 'rgba(239,68,68,0.28)'   },
  high:     { color: '#EA580C', bg: 'rgba(234,88,12,0.09)',   border: 'rgba(234,88,12,0.28)'   },
  medium:   { color: '#E5A93D', bg: 'rgba(229,169,61,0.09)',  border: 'rgba(229,169,61,0.28)'  },
  low:      { color: '#36B37E', bg: 'rgba(54,179,126,0.09)',  border: 'rgba(54,179,126,0.28)'  },
  info:     { color: '#60A5FA', bg: 'rgba(96,165,250,0.09)',  border: 'rgba(96,165,250,0.28)'  },
}

const FALLBACK = { color: '#71717A', bg: 'rgba(113,113,122,0.09)', border: 'rgba(113,113,122,0.28)' }

interface Props {
  level: RiskLevel | string
  size?: 'sm' | 'md'
}

export function SeverityBadge({ level, size = 'sm' }: Props) {
  const s = SEV[level as RiskLevel] ?? FALLBACK
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '5px',
      fontSize: size === 'sm' ? '11px' : '12px',
      fontWeight: 500,
      padding: size === 'sm' ? '3px 9px' : '4px 11px',
      borderRadius: '20px',
      color: s.color,
      background: s.bg,
      border: `1px solid ${s.border}`,
      whiteSpace: 'nowrap',
    }}>
      <span style={{ width: '5px', height: '5px', borderRadius: '50%', background: s.color, flexShrink: 0 }} />
      {level}
    </span>
  )
}
