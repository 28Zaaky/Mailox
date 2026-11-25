import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { PageHeader } from '../../components/Layout'
import { useAuth } from '../../lib/auth'
import { scans as scansApi } from '../../lib/api'

export default function Assets() {
  const { currentOrg } = useAuth()
  const orgId = currentOrg?.id ?? ''

  const { data: scanList = [], isLoading: scansLoading } = useQuery({
    queryKey: ['scans', orgId],
    queryFn: () => scansApi.list(orgId, 50, 0),
    enabled: !!orgId,
  })

  const completedScans = scanList.filter(
    (s) => s.status === 'completed' || s.status === 'partial'
  )

  const [selectedId, setSelectedId] = useState<string>('')
  const activeScanId = selectedId || completedScans[0]?.id

  const { data: assets, isLoading: assetsLoading } = useQuery({
    queryKey: ['scan-assets', orgId, activeScanId],
    queryFn: () => scansApi.assets(orgId, activeScanId!),
    enabled: !!orgId && !!activeScanId,
  })

  const isLoading = scansLoading || assetsLoading

  const activeScan = completedScans.find((s) => s.id === activeScanId)

  return (
    <div>
      <PageHeader
        title="Discovered Assets"
        subtitle={activeScan ? activeScan.target_domain : 'No completed scan'}
      />

      {/* Scan selector */}
      {completedScans.length > 1 && (
        <div className="mb-6">
          <label className="label block mb-1.5">Assessment</label>
          <select
            value={activeScanId ?? ''}
            onChange={(e) => setSelectedId(e.target.value)}
            className="input w-auto max-w-xs"
          >
            {completedScans.map((s) => (
              <option key={s.id} value={s.id}>
                {s.target_domain} — {new Date(s.created_at).toLocaleDateString()}
              </option>
            ))}
          </select>
        </div>
      )}

      {!activeScanId && !scansLoading && (
        <div style={{ textAlign: 'center', padding: '72px 24px' }}>
          <svg width="52" height="52" viewBox="0 0 52 52" fill="none" style={{ margin: '0 auto 18px', display: 'block' }}>
            <rect x="6" y="10" width="40" height="10" rx="3" stroke="#27272a" strokeWidth="1.5" />
            <rect x="6" y="24" width="40" height="10" rx="3" stroke="#27272a" strokeWidth="1.5" />
            <rect x="6" y="38" width="40" height="8" rx="3" stroke="#27272a" strokeWidth="1.5" />
            <circle cx="11" cy="15" r="2" fill="#3a3a44" />
            <circle cx="11" cy="29" r="2" fill="#3a3a44" />
            <circle cx="11" cy="42" r="2" fill="#3a3a44" />
          </svg>
          <div style={{ fontSize: '15px', fontWeight: 600, color: '#71717a', marginBottom: '6px' }}>
            No assets discovered
          </div>
          <div style={{ fontSize: '13px', color: '#52525b', maxWidth: '260px', margin: '0 auto 24px', lineHeight: 1.6 }}>
            Run an assessment to map MX records, SMTP hosts and webmail interfaces.
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
      )}

      {isLoading && (
        <div className="text-xs py-8 text-center" style={{ color: '#3a3a44', letterSpacing: '1px' }}>
          loading…
        </div>
      )}

      {assets && (
        <div className="space-y-6">
          <AssetSection title="MX Records" count={assets.mx_records.length}>
            {assets.mx_records.length === 0 ? (
              <EmptyRow />
            ) : (
              <table className="w-full text-sm">
                <thead className="border-b border-border">
                  <tr>
                    <th className="px-4 py-2.5 text-left label">Priority</th>
                    <th className="px-4 py-2.5 text-left label">Hostname</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {assets.mx_records.map((mx, i) => (
                    <tr key={i} className="hover:bg-bg-elevated transition-colors">
                      <td className="px-4 py-2 text-xs text-text-muted tabular-nums">{mx.priority}</td>
                      <td className="px-4 py-2 text-xs font-mono text-text-secondary">{mx.hostname}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </AssetSection>

          <AssetSection title="SMTP Hosts" count={assets.smtp_hosts.length}>
            {assets.smtp_hosts.length === 0 ? (
              <EmptyRow />
            ) : (
              <table className="w-full text-sm">
                <thead className="border-b border-border">
                  <tr>
                    <th className="px-4 py-2.5 text-left label">Host</th>
                    <th className="px-4 py-2.5 text-left label">Port</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {assets.smtp_hosts.map((s, i) => (
                    <tr key={i} className="hover:bg-bg-elevated transition-colors">
                      <td className="px-4 py-2 text-xs font-mono text-text-secondary">{s.host}</td>
                      <td className="px-4 py-2 text-xs text-text-muted tabular-nums">{s.port}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </AssetSection>

          <AssetSection title="Webmail Interfaces" count={assets.webmail_hosts.length}>
            {assets.webmail_hosts.length === 0 ? (
              <EmptyRow />
            ) : (
              <table className="w-full text-sm">
                <thead className="border-b border-border">
                  <tr>
                    <th className="px-4 py-2.5 text-left label">Host</th>
                    <th className="px-4 py-2.5 text-left label">Product</th>
                    <th className="px-4 py-2.5 text-left label">Version</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {assets.webmail_hosts.map((w, i) => (
                    <tr key={i} className="hover:bg-bg-elevated transition-colors">
                      <td className="px-4 py-2 text-xs font-mono text-text-secondary">{w.host}</td>
                      <td className="px-4 py-2 text-xs text-text-muted">{w.product}</td>
                      <td className="px-4 py-2 text-xs text-text-muted">{w.version ?? '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </AssetSection>
        </div>
      )}
    </div>
  )
}

function AssetSection({
  title,
  count,
  children,
}: {
  title: string
  count: number
  children: React.ReactNode
}) {
  return (
    <section>
      <h2 className="text-xs mb-2 flex items-center gap-2" style={{ color: '#E8173A', letterSpacing: '2px' }}>
        {title.toUpperCase()}
        <span className="text-text-muted" style={{ color: '#3a3a44' }}>({count})</span>
      </h2>
      <div className="card">{children}</div>
    </section>
  )
}

function EmptyRow() {
  return (
    <div className="px-4 py-4 text-xs text-center" style={{ color: '#3a3a44', letterSpacing: '1px' }}>
      none discovered
    </div>
  )
}
