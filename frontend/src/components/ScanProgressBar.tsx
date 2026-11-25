import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { X } from 'lucide-react'
import { useScanMonitor, engineLabel } from '../lib/scan-monitor'
import { useAuth } from '../lib/auth'

export function ScanProgressBar() {
  const { activeScans } = useScanMonitor()
  const { currentOrg } = useAuth()
  const navigate = useNavigate()
  const [dismissed, setDismissed] = useState<Set<string>>(new Set())

  const visible = activeScans.filter((s) => !dismissed.has(s.id))
  if (visible.length === 0) return null

  return (
    <div style={{
      position: 'fixed', bottom: '20px', right: '20px',
      zIndex: 100, display: 'flex', flexDirection: 'column', gap: '6px',
      fontFamily: '"JetBrains Mono", monospace',
    }}>
      {visible.map((scan) => {
        const pct = scan.status === 'queued' ? 0 : Math.max(2, scan.progress_pct ?? 0)
        const engine = scan.status === 'queued' ? 'queued…' : engineLabel(scan.current_engine)
        const isQueued = scan.status === 'queued'

        return (
          <div
            key={scan.id}
            onClick={() => { if (currentOrg) navigate(`/assessments/${scan.id}`) }}
            style={{
              width: '220px', borderRadius: '8px',
              background: '#0d0d0f',
              border: '1px solid rgba(229,57,53,0.22)',
              boxShadow: '0 0 12px rgba(229,57,53,0.07), 0 4px 16px rgba(0,0,0,0.5)',
              padding: '10px 12px',
              cursor: 'pointer',
            }}
          >
            {/* Domain + dismiss */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
              <span style={{
                fontSize: '11px', color: '#d4d4d8', fontWeight: 600,
                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                maxWidth: '170px',
              }}>
                {scan.target_domain}
              </span>
              <button
                onClick={(e) => { e.stopPropagation(); setDismissed((p) => new Set([...p, scan.id])) }}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#3a3a44', padding: '0 0 0 6px', flexShrink: 0 }}
                onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.color = '#71717a' }}
                onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.color = '#3a3a44' }}
              >
                <X size={10} />
              </button>
            </div>

            {/* Progress bar */}
            <div style={{ height: '2px', background: '#1a1a1f', borderRadius: '1px', overflow: 'hidden', position: 'relative', marginBottom: '7px' }}>
              {!isQueued && (
                <div style={{
                  height: '100%', width: `${pct}%`,
                  background: 'linear-gradient(90deg, rgba(229,57,53,0.6), #E53935)',
                  borderRadius: '1px',
                  boxShadow: '0 0 6px rgba(229,57,53,0.8)',
                  transition: 'width 600ms cubic-bezier(0.23,1,0.32,1)',
                }} />
              )}
              {isQueued && (
                <div style={{
                  position: 'absolute', inset: 0,
                  background: 'linear-gradient(90deg, transparent 0%, rgba(229,57,53,0.3) 50%, transparent 100%)',
                  animation: 'spbShimmer 2s ease-in-out infinite',
                }} />
              )}
            </div>

            {/* Engine + % */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '10px', color: '#52525b' }}>{engine}</span>
              {!isQueued && (
                <span style={{ fontSize: '10px', color: '#E53935', textShadow: '0 0 6px rgba(229,57,53,0.5)' }}>
                  {pct}%
                </span>
              )}
            </div>
          </div>
        )
      })}

      <style>{`
        @keyframes spbShimmer {
          0%   { background-position: 200% 0; }
          100% { background-position: -200% 0; }
        }
      `}</style>
    </div>
  )
}
