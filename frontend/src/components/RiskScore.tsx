import clsx from 'clsx'

function posture(score: number | null | undefined): { label: string; color: string } {
  if (score == null) return { label: 'Unknown', color: 'text-text-muted' }
  if (score >= 75) return { label: 'Critical', color: 'text-severity-critical' }
  if (score >= 50) return { label: 'High', color: 'text-severity-high' }
  if (score >= 25) return { label: 'Medium', color: 'text-severity-medium' }
  if (score > 0) return { label: 'Low', color: 'text-severity-low' }
  return { label: 'Clean', color: 'text-severity-low' }
}

interface Props {
  score: number | null | undefined
  showLabel?: boolean
  size?: 'sm' | 'md' | 'lg'
}

export function RiskScore({ score, showLabel = false, size = 'md' }: Props) {
  const { label, color } = posture(score)
  const display = score != null ? score.toFixed(0) : '—'

  return (
    <span className="inline-flex items-center gap-1.5">
      <span
        className={clsx(
          'font-mono font-bold tabular-nums',
          color,
          size === 'sm' && 'text-sm',
          size === 'md' && 'text-xl',
          size === 'lg' && 'text-3xl'
        )}
      >
        {display}
      </span>
      {size !== 'sm' && (
        <span className="text-text-muted text-xs">/100</span>
      )}
      {showLabel && (
        <span className={clsx('text-xs font-medium', color)}>{label}</span>
      )}
    </span>
  )
}
