import { useRef, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { PageHeader } from '../../components/Layout'
import { SeverityBadge } from '../../components/SeverityBadge'
import { useAuth } from '../../lib/auth'
import { findings as findingsApi, secrets as secretsApi } from '../../lib/api'
import type { ExposedSecret, FindingStatus, ScanFinding } from '../../types'
import clsx from 'clsx'

const CONFIDENCE_LABEL = (n: number) =>
  n >= 0.9 ? 'High' : n >= 0.6 ? 'Medium' : 'Low'

const CONFIDENCE_COLOR = (n: number) =>
  n >= 0.9
    ? 'text-red-400 bg-red-900/20'
    : n >= 0.6
    ? 'text-yellow-400 bg-yellow-900/20'
    : 'text-blue-400 bg-blue-900/20'

export default function CredentialExposure() {
  const { currentOrg } = useAuth()
  const orgId = currentOrg?.id ?? ''
  const qc = useQueryClient()
  const fileRef = useRef<HTMLInputElement>(null)
  const [uploadPage, setUploadPage] = useState(1)
  const pageSize = 25

  // Auto-findings from HIBP domain scan (engine="secrets")
  const { data: findingsData, isLoading: findingsLoading } = useQuery({
    queryKey: ['findings', orgId, 'secrets'],
    queryFn: () => findingsApi.list(orgId, { engine: 'secrets', page_size: 100 }),
    enabled: !!orgId,
  })

  // Manually uploaded file secrets
  const { data: uploadedData, isLoading: uploadLoading } = useQuery({
    queryKey: ['secrets', orgId, uploadPage],
    queryFn: () => secretsApi.list(orgId, { page: uploadPage, page_size: pageSize }),
    enabled: !!orgId,
  })

  const uploadMutation = useMutation({
    mutationFn: (file: File) => secretsApi.upload(orgId, file),
    onSuccess: (res: { found?: number }) => {
      toast.success(`Scan complete — ${res.found ?? 0} secret(s) found`)
      qc.invalidateQueries({ queryKey: ['secrets', orgId] })
    },
    onError: () => toast.error('Upload failed'),
  })

  const statusMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: FindingStatus }) =>
      findingsApi.updateStatus(orgId, id, status),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['findings', orgId, 'secrets'] }),
    onError: () => toast.error('Update failed'),
  })

  const secretStatusMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      secretsApi.updateStatus(orgId, id, status),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['secrets', orgId] }),
    onError: () => toast.error('Update failed'),
  })

  const autoFindings: ScanFinding[] = findingsData?.items ?? []
  const uploadedSecrets: ExposedSecret[] = uploadedData?.items ?? []
  const uploadedTotal = uploadedData?.total ?? 0
  const uploadedPages = Math.ceil(uploadedTotal / pageSize)

  return (
    <div className="p-6 space-y-8 max-w-5xl mx-auto">
      <PageHeader
        title="Credential Exposure"
        subtitle={`${autoFindings.length} breach finding${autoFindings.length !== 1 ? 's' : ''} · ${uploadedTotal} file secret${uploadedTotal !== 1 ? 's' : ''}`}
        description="Domain breach intelligence (auto) and file-based secret scanning (upload)."
      />

      {/* ── Auto findings from HIBP ─────────────────────────────────── */}
      <section>
        <h2 className="text-xs font-semibold uppercase tracking-widest text-text-muted mb-3">
          Domain breach intel
        </h2>

        {findingsLoading ? (
          <p className="text-text-muted text-sm font-mono">Loading…</p>
        ) : autoFindings.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '56px 24px' }}>
            <svg width="48" height="48" viewBox="0 0 48 48" fill="none" style={{ margin: '0 auto 16px', display: 'block' }}>
              <circle cx="24" cy="24" r="23" stroke="#1a3a2a" strokeWidth="1.5" />
              <path d="M15 22l6 7L33 16" stroke="#36B37E" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            <div style={{ fontSize: '15px', fontWeight: 600, color: '#52525b', marginBottom: '6px' }}>
              No breach records found
            </div>
            <div style={{ fontSize: '13px', color: '#3a3a44', maxWidth: '260px', margin: '0 auto 20px', lineHeight: 1.6 }}>
              No HIBP matches for this domain. Run a new assessment to re-check.
            </div>
            <a
              href="/assessments/new"
              style={{
                display: 'inline-flex', alignItems: 'center', gap: '6px',
                padding: '7px 18px', borderRadius: '6px',
                border: '1px solid #27272a',
                color: '#71717a', fontSize: '12px', fontWeight: 600,
                textDecoration: 'none', letterSpacing: '0.03em',
              }}
            >
              → Run assessment
            </a>
          </div>
        ) : (
          <div className="space-y-2">
            {autoFindings.map((f) => (
              <div
                key={f.id}
                className="bg-bg-surface border border-border-subtle rounded-lg p-4 flex items-start justify-between gap-4"
              >
                <div className="min-w-0 space-y-1">
                  <p className="text-text-primary text-sm font-medium">{f.title}</p>
                  <p className="text-text-muted text-xs line-clamp-2">{f.description}</p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <SeverityBadge level={f.risk_level} />
                  <select
                    className="text-xs rounded px-2 py-0.5 border border-border-subtle bg-bg-base cursor-pointer text-text-primary"
                    defaultValue={f.status}
                    onChange={(e) => statusMutation.mutate({ id: f.id, status: e.target.value as FindingStatus })}
                  >
                    <option value="open">Open</option>
                    <option value="acknowledged">Acknowledged</option>
                    <option value="false_positive">False positive</option>
                    <option value="resolved">Resolved</option>
                  </select>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* ── Manual file upload ──────────────────────────────────────── */}
      <section>
        <h2 className="text-xs font-semibold uppercase tracking-widest text-text-muted mb-3">
          File scan (manual upload)
        </h2>

        <div
          onClick={() => fileRef.current?.click()}
          onDragOver={(e) => e.preventDefault()}
          onDrop={(e) => {
            e.preventDefault()
            const file = e.dataTransfer.files[0]
            if (file) uploadMutation.mutate(file)
          }}
          className={clsx(
            'border-2 border-dashed rounded-lg p-6 text-center cursor-pointer transition-colors mb-4',
            uploadMutation.isPending
              ? 'border-accent/60 bg-accent-muted'
              : 'border-border-subtle hover:border-accent/40 hover:bg-bg-surface',
          )}
        >
          <input
            ref={fileRef}
            type="file"
            accept=".zip,.env,.conf,.cfg,.json,.yaml,.yml,.txt,.py,.js,.ts,.rb,.php"
            className="hidden"
            onChange={(e) => {
              const file = e.target.files?.[0]
              if (file) uploadMutation.mutate(file)
              e.target.value = ''
            }}
          />
          {uploadMutation.isPending ? (
            <p className="text-accent text-sm font-mono animate-pulse">Scanning…</p>
          ) : (
            <>
              <p className="text-text-muted text-sm">
                Drop a file or <span className="text-accent">click to upload</span>
              </p>
              <p className="text-text-subtle text-xs mt-1">
                .zip, .env, config files, source code — max 50 MB
              </p>
            </>
          )}
        </div>

        {uploadLoading ? (
          <p className="text-text-muted text-sm font-mono">Loading…</p>
        ) : uploadedSecrets.length === 0 ? (
          <p className="text-text-subtle text-xs text-center py-4">
            No file secrets found yet.
          </p>
        ) : (
          <div className="space-y-2">
            {uploadedSecrets.map((s) => (
              <div
                key={s.id}
                className="bg-bg-surface border border-border-subtle rounded-lg p-4 flex items-start justify-between gap-4"
              >
                <div className="min-w-0">
                  <p className="text-text-primary text-sm font-mono truncate">{s.masked_value}</p>
                  <p className="text-text-muted text-xs mt-0.5">
                    <span className="text-text-subtle">{s.secret_type}</span>
                    {s.affected_asset && <> · {s.affected_asset}</>}
                    {' · '}{s.source}
                  </p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className={clsx('text-xs font-mono px-2 py-0.5 rounded', CONFIDENCE_COLOR(s.confidence))}>
                    {CONFIDENCE_LABEL(s.confidence)}
                  </span>
                  <select
                    className="text-xs rounded px-2 py-0.5 border border-border-subtle bg-bg-base cursor-pointer text-text-primary"
                    defaultValue={s.status ?? 'new'}
                    onChange={(e) => secretStatusMutation.mutate({ id: s.id, status: e.target.value })}
                  >
                    <option value="new">New</option>
                    <option value="confirmed">Confirmed</option>
                    <option value="false_positive">False positive</option>
                    <option value="resolved">Resolved</option>
                  </select>
                </div>
              </div>
            ))}

            {uploadedPages > 1 && (
              <div className="flex items-center justify-between pt-2">
                <span className="text-text-muted text-xs">{uploadedTotal} total · page {uploadPage}/{uploadedPages}</span>
                <div className="flex gap-2">
                  <button disabled={uploadPage <= 1} onClick={() => setUploadPage((p) => p - 1)}
                    className="text-xs px-3 py-1 rounded border border-border-subtle disabled:opacity-40 hover:border-accent/40">
                    Prev
                  </button>
                  <button disabled={uploadPage >= uploadedPages} onClick={() => setUploadPage((p) => p + 1)}
                    className="text-xs px-3 py-1 rounded border border-border-subtle disabled:opacity-40 hover:border-accent/40">
                    Next
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </section>
    </div>
  )
}
