import { Mail, Server } from 'lucide-react'
import type { ScanFinding } from '../types'

interface ProviderPanelProps {
  findings: ScanFinding[]
}

export function ProviderPanel({ findings }: ProviderPanelProps) {
  const emailFinding = findings.find(f => f.check_id === 'DNS-PROVIDER-01')
  const hostingFinding = findings.find(f => f.check_id === 'DNS-HOSTING-01')

  if (!emailFinding && !hostingFinding) return null

  const emailProvider = emailFinding?.evidence?.[0]?.observed_value ?? null
  const emailConfidence = emailFinding?.confidence ?? 0
  const hostingProvider = hostingFinding?.evidence?.[0]?.observed_value ?? null
  const hostingConfidence = hostingFinding?.confidence ?? 0

  return (
    <div className="card p-4 mb-4">
      <div className="label mb-3">Infrastructure</div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px' }}>
        <ProviderRow
          icon={<Mail size={13} />}
          label="Email Provider"
          name={emailProvider}
          confidence={emailConfidence}
        />
        <ProviderRow
          icon={<Server size={13} />}
          label="Hosting / ASN"
          name={hostingProvider}
          confidence={hostingConfidence}
        />
      </div>
    </div>
  )
}

function ProviderRow({
  icon,
  label,
  name,
  confidence,
}: {
  icon: React.ReactNode
  label: string
  name: string | null
  confidence: number
}) {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '10px',
        padding: '8px 12px',
        background: 'var(--color-bg-elevated)',
        border: '1px solid var(--color-border)',
        borderRadius: '6px',
        flex: '1',
        minWidth: '200px',
      }}
    >
      <span style={{ color: 'var(--color-text-muted)', flexShrink: 0 }}>{icon}</span>
      <div style={{ flex: 1 }}>
        <div className="label" style={{ marginBottom: '2px' }}>
          {label}
        </div>
        <span
          style={{
            fontSize: '13px',
            fontWeight: 500,
            color: name ? 'var(--color-text-primary)' : 'var(--color-text-muted)',
            fontStyle: name ? 'normal' : 'italic',
          }}
        >
          {name ?? 'Unknown'}
        </span>
      </div>
      {name && confidence > 0.7 && (
        <span
          style={{
            fontSize: '10px',
            fontWeight: 500,
            padding: '2px 7px',
            borderRadius: '20px',
            color: '#36B37E',
            background: 'rgba(54,179,126,0.08)',
            border: '1px solid rgba(54,179,126,0.25)',
            whiteSpace: 'nowrap',
            flexShrink: 0,
          }}
        >
          {Math.round(confidence * 100)}% conf
        </span>
      )}
    </div>
  )
}
