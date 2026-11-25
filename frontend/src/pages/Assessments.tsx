import React, { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate } from 'react-router-dom'
import { Ban, Plus, RefreshCw, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { PageHeader } from '../components/Layout'
import { RiskScore } from '../components/RiskScore'
import { ScanStatusBadge } from '../components/StatusBadge'
import { BatchScanForm } from '../components/BatchScanForm'
import { useAuth } from '../lib/auth'
import { scans as scansApi, profiles as profilesApi } from '../lib/api'

export default function Assessments() {
  const { currentOrg } = useAuth()
  const orgId = currentOrg?.id ?? ''
  const qc = useQueryClient()
  const navigate = useNavigate()

  const [domain, setDomain] = useState('')
  const [showNew, setShowNew] = useState(false)
  const [scanMode, setScanMode] = useState<'single' | 'batch'>('single')
  const [selectedProfileId, setSelectedProfileId] = useState<string>('')

  const { data: profileList = [] } = useQuery({
    queryKey: ['profiles', orgId],
    queryFn: () => profilesApi.list(orgId),
    enabled: !!orgId && showNew,
  })

  const { data: scanList = [], isLoading, refetch } = useQuery({
    queryKey: ['scans', orgId],
    queryFn: () => scansApi.list(orgId, 50, 0),
    enabled: !!orgId,
    refetchInterval: (query) => {
      const data = query.state.data ?? []
      const hasActive = data.some(
        (s) => s.status === 'running' || s.status === 'queued'
      )
      return hasActive ? 4000 : false
    },
  })

  const createMutation = useMutation({
    mutationFn: (d: string) =>
      scansApi.create(orgId, d, undefined, selectedProfileId || undefined),
    onSuccess: (scan) => {
      qc.invalidateQueries({ queryKey: ['scans', orgId] })
      qc.invalidateQueries({ queryKey: ['org-stats', orgId] })
      navigate(`/assessments/${scan.id}`)
    },
    onError: (e: { response?: { data?: { detail?: string } } }) =>
      toast.error(e?.response?.data?.detail ?? 'Failed to create scan'),
  })

  const deleteMutation = useMutation({
    mutationFn: (scanId: string) => scansApi.delete(orgId, scanId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scans', orgId] })
      qc.invalidateQueries({ queryKey: ['org-stats', orgId] })
      toast.success('Scan deleted')
    },
    onError: (e: { response?: { status?: number; data?: { detail?: string } } }) =>
      toast.error(`Failed to delete scan: ${e?.response?.data?.detail ?? e?.response?.status ?? 'unknown error'}`),
  })

  const cancelMutation = useMutation({
    mutationFn: (scanId: string) => scansApi.cancel(orgId, scanId),
    onMutate: (scanId: string) => {
      // Optimistic: show cancelled immediately — backend confirms async
      qc.setQueryData(['scans', orgId], (old: import('../types').Scan[] | undefined) =>
        old?.map((s) => s.id === scanId ? { ...s, status: 'cancelled' as const } : s) ?? []
      )
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scans', orgId] })
      qc.invalidateQueries({ queryKey: ['org-stats', orgId] })
      toast.success('Scan cancelled')
    },
    onError: () => {
      // Rollback optimistic update
      qc.invalidateQueries({ queryKey: ['scans', orgId] })
      toast.error('Failed to cancel scan')
    },
  })

  function handleCreate(e: React.FormEvent) {
    e.preventDefault()
    if (domain.trim()) createMutation.mutate(domain.trim())
  }

  return (
    <div>
      <PageHeader
        title="Assessments"
        subtitle="Email infrastructure security scans"
        action={
          <div className="flex items-center gap-2">
            <button
              onClick={() => refetch()}
              className="btn-ghost p-2"
              title="Refresh"
            >
              <RefreshCw size={14} />
            </button>
            <button
              onClick={() => setShowNew(true)}
              className="btn-primary flex items-center gap-1.5 text-sm"
            >
              <Plus size={14} />
              New scan
            </button>
          </div>
        }
      />

      {/* New scan form */}
      {showNew && (
        <div className="card p-4 mb-6">
          {/* Single / Batch tab toggle */}
          <div className="flex gap-1 mb-4 border-b border-border pb-3">
            <button
              type="button"
              onClick={() => setScanMode('single')}
              className={`text-sm px-3 py-1 rounded transition-colors ${
                scanMode === 'single'
                  ? 'bg-accent text-white'
                  : 'text-text-muted hover:text-text-primary'
              }`}
            >
              Single
            </button>
            <button
              type="button"
              onClick={() => setScanMode('batch')}
              className={`text-sm px-3 py-1 rounded transition-colors ${
                scanMode === 'batch'
                  ? 'bg-accent text-white'
                  : 'text-text-muted hover:text-text-primary'
              }`}
            >
              Batch
            </button>
          </div>

          {scanMode === 'single' ? (
            <>
              <form onSubmit={handleCreate} className="flex items-end gap-3 flex-wrap">
                <div className="flex-1" style={{ minWidth: '200px' }}>
                  <label className="label block mb-1.5">Target domain</label>
                  <input
                    type="text"
                    className="input"
                    value={domain}
                    onChange={(e) => setDomain(e.target.value)}
                    placeholder="mail.example.com"
                    pattern="^[a-zA-Z0-9][a-zA-Z0-9\-\.]*\.[a-zA-Z]{2,}$"
                    required
                    autoFocus
                  />
                </div>
                <div style={{ minWidth: '160px' }}>
                  <label className="label block mb-1.5">Profile</label>
                  <select
                    className="input"
                    value={selectedProfileId}
                    onChange={(e) => setSelectedProfileId(e.target.value)}
                  >
                    <option value="">Default (Full)</option>
                    {profileList.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.name}{p.is_builtin ? '' : ' (custom)'}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => setShowNew(false)}
                    className="btn-secondary"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={createMutation.isPending}
                    className="btn-primary disabled:opacity-50"
                  >
                    {createMutation.isPending ? 'Launching…' : 'Launch scan'}
                  </button>
                </div>
              </form>
              {createMutation.isError && (
                <div className="mt-2 text-xs text-severity-critical">
                  {String(
                    (createMutation.error as { response?: { data?: { detail?: string } } })?.response
                      ?.data?.detail ?? 'Failed to create scan'
                  )}
                </div>
              )}
            </>
          ) : (
            <BatchScanForm
              orgId={orgId}
              profileList={profileList}
              onCancel={() => setShowNew(false)}
            />
          )}
        </div>
      )}

      {/* Table */}
      <div className="card">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border">
              <th className="text-left label px-5 py-3.5">Domain</th>
              <th className="text-left label px-5 py-3.5">Status</th>
              <th className="text-left label px-5 py-3.5">Risk</th>
              <th className="text-left label px-5 py-3.5">Findings</th>
              <th className="text-left label px-5 py-3.5">Started</th>
              <th className="px-5 py-3.5" />
            </tr>
          </thead>
          <tbody>
            {isLoading && (
              <tr>
                <td colSpan={6} className="px-4 py-6 text-center text-text-muted text-sm">
                  Loading…
                </td>
              </tr>
            )}
            {!isLoading && scanList.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-10 text-center">
                  <div className="text-text-muted text-sm mb-2">No assessments</div>
                  <button
                    onClick={() => setShowNew(true)}
                    className="text-xs text-accent hover:text-accent-hover"
                  >
                    Launch your first scan →
                  </button>
                </td>
              </tr>
            )}
            {scanList.map((scan) => (
              <tr
                key={scan.id}
                className="border-b border-border/50 hover:bg-bg-elevated/50 transition-colors"
              >
                <td className="px-5 py-4">
                  <Link
                    to={`/assessments/${scan.id}`}
                    className="text-sm text-text-primary hover:text-accent transition-colors"
                  >
                    {scan.target_domain}
                  </Link>
                </td>
                <td className="px-5 py-4">
                  <div className="flex items-center gap-3">
                    <ScanStatusBadge status={scan.status} />
                    {(scan.status === 'running' || scan.status === 'queued') && (
                      <span className="text-xs text-text-muted">
                        {scan.progress_pct}%
                      </span>
                    )}
                  </div>
                </td>
                <td className="px-5 py-4">
                  <RiskScore score={scan.risk_score} size="sm" />
                </td>
                <td className="px-5 py-4 text-sm text-text-secondary">
                  {scan.finding_count}
                </td>
                <td className="px-5 py-4 text-sm text-text-muted">
                  {scan.started_at
                    ? new Date(scan.started_at).toLocaleString()
                    : new Date(scan.created_at).toLocaleString()}
                </td>
                <td className="px-5 py-4 text-right">
                  <div className="flex items-center justify-end gap-1">
                    {(scan.status === 'running' || scan.status === 'queued') && (
                      <button
                        onClick={() => cancelMutation.mutate(scan.id)}
                        disabled={cancelMutation.isPending}
                        className="p-1.5 hover:bg-bg-elevated text-text-muted hover:text-severity-high transition-colors disabled:opacity-30"
                        title="Cancel scan"
                      >
                        <Ban size={13} />
                      </button>
                    )}
                    {scan.status !== 'running' && scan.status !== 'queued' && (
                      <button
                        onClick={() => deleteMutation.mutate(scan.id)}
                        disabled={deleteMutation.isPending}
                        className="p-1.5 hover:bg-bg-elevated text-text-muted hover:text-severity-critical transition-colors disabled:opacity-30"
                        title="Delete scan"
                      >
                        <Trash2 size={13} />
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
