import React, { useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, Users, Archive, Check, X, Target, Plus, Trash2, FileText, Activity, ToggleLeft, ToggleRight } from 'lucide-react'
import { useAuth } from '../lib/auth'
import { projects as projectsApi, orgs as orgsApi, assets as assetsApi, monitoring as monitoringApi, profiles as profilesApi, reportsV2 } from '../lib/api'
import type { ProjectMember } from '../types'

function RoleBadge({ role }: { role: ProjectMember['role'] }) {
  const labels: Record<ProjectMember['role'], string> = {
    project_manager: 'Manager',
    analyst: 'Analyst',
    auditor: 'Auditor',
    viewer: 'Viewer',
  }
  return (
    <span style={{
      fontSize: '11px', padding: '2px 8px', borderRadius: '12px',
      background: '#27272a', color: '#a1a1aa',
    }}>
      {labels[role]}
    </span>
  )
}

function InlineEdit({
  value,
  onSave,
  multiline,
  placeholder,
}: {
  value: string
  onSave: (v: string) => Promise<unknown>
  multiline?: boolean
  placeholder?: string
}) {
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState(value)
  const [saving, setSaving] = useState(false)

  const handleSave = async () => {
    if (draft.trim() === value) { setEditing(false); return }
    setSaving(true)
    try {
      await onSave(draft.trim())
      setEditing(false)
    } finally {
      setSaving(false)
    }
  }

  if (!editing) {
    return (
      <span
        onClick={() => { setDraft(value); setEditing(true) }}
        style={{ cursor: 'pointer', borderBottom: '1px dashed #3f3f46' }}
        title="Click to edit"
      >
        {value || <span style={{ color: '#52525b' }}>{placeholder ?? 'Click to add'}</span>}
      </span>
    )
  }

  const sharedStyle: React.CSSProperties = {
    background: '#111113', border: '1px solid rgba(var(--color-accent-rgb), 0.4)',
    borderRadius: '6px', color: '#f4f4f5', fontSize: 'inherit',
    padding: '4px 8px', outline: 'none',
  }

  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
      {multiline ? (
        <textarea
          autoFocus
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          rows={3}
          style={{ ...sharedStyle, width: 'min(400px, 70vw)', resize: 'vertical' }}
        />
      ) : (
        <input
          autoFocus
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') handleSave(); if (e.key === 'Escape') setEditing(false) }}
          style={{ ...sharedStyle, minWidth: '200px' }}
        />
      )}
      <button
        onClick={handleSave}
        disabled={saving}
        style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#4ade80', padding: '2px' }}
      >
        <Check size={14} />
      </button>
      <button
        onClick={() => setEditing(false)}
        style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#71717a', padding: '2px' }}
      >
        <X size={14} />
      </button>
    </span>
  )
}

export default function ProjectDetail() {
  const { projectId } = useParams<{ projectId: string }>()
  const { currentOrg, user } = useAuth()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [archiveConfirm, setArchiveConfirm] = useState(false)

  const { data: project, isLoading } = useQuery({
    queryKey: ['project', currentOrg?.id, projectId],
    queryFn: () => projectsApi.get(currentOrg!.id, projectId!),
    enabled: !!currentOrg && !!projectId,
  })

  const { data: members } = useQuery({
    queryKey: ['project-members', currentOrg?.id, projectId],
    queryFn: () => projectsApi.members(currentOrg!.id, projectId!),
    enabled: !!currentOrg && !!projectId,
  })

  const { data: orgMembers } = useQuery({
    queryKey: ['org-members', currentOrg?.id],
    queryFn: () => orgsApi.members(currentOrg!.id),
    enabled: !!currentOrg,
  })

  const updateMutation = useMutation({
    mutationFn: (data: { name?: string; description?: string }) =>
      projectsApi.update(currentOrg!.id, projectId!, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['project', currentOrg?.id, projectId] })
      qc.invalidateQueries({ queryKey: ['projects', currentOrg?.id] })
    },
  })

  const archiveMutation = useMutation({
    mutationFn: () => projectsApi.archive(currentOrg!.id, projectId!),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['projects', currentOrg?.id] })
      navigate('/projects')
    },
  })

  const removeMemberMutation = useMutation({
    mutationFn: (userId: string) => projectsApi.removeMember(currentOrg!.id, projectId!, userId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['project-members', currentOrg?.id, projectId] }),
  })

  if (!currentOrg) return null

  if (isLoading) {
    return <div className="card" style={{ height: '200px', opacity: 0.4 }} />
  }

  if (!project) {
    return (
      <div>
        <p style={{ color: '#71717a' }}>Project not found.</p>
        <Link to="/projects" style={{ color: 'rgba(var(--color-accent-rgb), 0.9)', fontSize: '13px' }}>
          ← Back to projects
        </Link>
      </div>
    )
  }

  const memberUserIds = new Set((members ?? []).map((m) => m.user_id))
  const addableMembers = (orgMembers ?? []).filter((m) => !memberUserIds.has(m.user_id))

  return (
    <div style={{ maxWidth: '960px' }}>
      {/* Header */}
      <div style={{ marginBottom: '28px' }}>
        <Link
          to="/projects"
          style={{
            display: 'inline-flex', alignItems: 'center', gap: '6px',
            color: '#71717a', fontSize: '12px', textDecoration: 'none', marginBottom: '16px',
          }}
        >
          <ArrowLeft size={12} /> Projects
        </Link>

        <div className="card" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '16px' }}>
            <div style={{ flex: 1 }}>
              <h1 style={{ fontSize: '20px', fontWeight: 700, color: '#f4f4f5', margin: '0 0 8px' }}>
                <InlineEdit
                  value={project.name}
                  onSave={(name) => updateMutation.mutateAsync({ name })}
                />
              </h1>
              <p style={{ fontSize: '13px', color: '#71717a', margin: 0 }}>
                <InlineEdit
                  value={project.description ?? ''}
                  onSave={(description) => updateMutation.mutateAsync({ description })}
                  multiline
                  placeholder="Add a description…"
                />
              </p>
            </div>

            <div style={{ display: 'flex', gap: '8px', flexShrink: 0 }}>
              {project.status === 'active' && (
                <button
                  onClick={() => setArchiveConfirm(true)}
                  style={{
                    display: 'inline-flex', alignItems: 'center', gap: '6px',
                    padding: '7px 12px', borderRadius: '6px',
                    border: '1px solid #27272a', background: 'transparent',
                    color: '#71717a', fontSize: '12px', cursor: 'pointer',
                  }}
                >
                  <Archive size={12} /> Archive
                </button>
              )}
            </div>
          </div>

          <div style={{ display: 'flex', gap: '24px', marginTop: '20px', paddingTop: '20px', borderTop: '1px solid #27272a' }}>
            <Stat label="Status" value={project.status} />
            <Stat label="Members" value={String(members?.length ?? '…')} />
            <Stat label="Created" value={new Date(project.created_at).toLocaleDateString()} />
            <Stat label="Updated" value={new Date(project.updated_at).toLocaleDateString()} />
          </div>
        </div>
      </div>

      {/* Members */}
      <div className="card" style={{ padding: '20px 24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
          <h2 style={{ fontSize: '14px', fontWeight: 600, color: '#f4f4f5', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Users size={14} /> Members
          </h2>
          {addableMembers.length > 0 && (
            <AddMemberDropdown
              orgId={currentOrg.id}
              projectId={projectId!}
              addableMembers={addableMembers}
              onAdded={() => qc.invalidateQueries({ queryKey: ['project-members', currentOrg.id, projectId] })}
            />
          )}
        </div>

        {members && members.length > 0 ? (
          <div style={{ display: 'grid', gap: '8px' }}>
            {members.map((m) => {
              const orgMember = orgMembers?.find((om) => om.user_id === m.user_id)
              const isMe = m.user_id === user?.id
              return (
                <div
                  key={m.user_id}
                  style={{
                    display: 'flex', alignItems: 'center', gap: '12px',
                    padding: '10px 14px', borderRadius: '8px', background: '#111113',
                  }}
                >
                  <div
                    style={{
                      width: 30, height: 30, borderRadius: '50%',
                      background: 'rgba(var(--color-accent-rgb), 0.15)',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      fontSize: '11px', fontWeight: 700,
                      color: 'rgba(var(--color-accent-rgb), 0.9)',
                      flexShrink: 0,
                    }}
                  >
                    {(orgMember?.full_name ?? orgMember?.email ?? 'U').charAt(0).toUpperCase()}
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <span style={{ fontSize: '13px', color: '#f4f4f5' }}>
                      {orgMember?.full_name ?? orgMember?.email ?? m.user_id}
                    </span>
                    {isMe && (
                      <span style={{ marginLeft: '6px', fontSize: '10px', color: '#52525b' }}>(you)</span>
                    )}
                  </div>
                  <RoleBadge role={m.role} />
                  {!isMe && project.status === 'active' && (
                    <button
                      onClick={() => removeMemberMutation.mutate(m.user_id)}
                      title="Remove member"
                      style={{
                        background: 'none', border: 'none', cursor: 'pointer',
                        color: '#52525b', padding: '4px', borderRadius: '4px',
                      }}
                    >
                      <X size={12} />
                    </button>
                  )}
                </div>
              )
            })}
          </div>
        ) : (
          <p style={{ color: '#52525b', fontSize: '13px', margin: 0 }}>No members yet.</p>
        )}
      </div>

      {/* Scope */}
      <div className="card" style={{ padding: '20px 24px', marginTop: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
          <h2 style={{ fontSize: '14px', fontWeight: 600, color: '#f4f4f5', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Target size={14} /> Scope
          </h2>
          {project.status === 'active' && (
            <AddScopeForm orgId={currentOrg.id} projectId={projectId!}
              onAdded={() => qc.invalidateQueries({ queryKey: ['project-scope', currentOrg.id, projectId] })} />
          )}
        </div>
        <ScopeList orgId={currentOrg.id} projectId={projectId!} projectActive={project.status === 'active'} />
      </div>

      {/* Reports */}
      <div className="card" style={{ padding: '20px 24px', marginTop: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
          <h2 style={{ fontSize: '14px', fontWeight: 600, color: '#f4f4f5', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
            <FileText size={14} /> Reports
          </h2>
        </div>
        <ProjectReportsList orgId={currentOrg.id} projectId={projectId!} />
      </div>

      {/* Monitoring */}
      <div className="card" style={{ padding: '20px 24px', marginTop: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
          <h2 style={{ fontSize: '14px', fontWeight: 600, color: '#f4f4f5', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Activity size={14} /> Monitoring
          </h2>
        </div>
        <MonitoringSection orgId={currentOrg.id} projectId={projectId!} projectActive={project.status === 'active'} />
      </div>

      {/* Archive confirm */}
      {archiveConfirm && (
        <div
          style={{
            position: 'fixed', inset: 0, zIndex: 50,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            background: 'rgba(0,0,0,0.6)',
          }}
          onClick={() => setArchiveConfirm(false)}
        >
          <div
            className="card"
            style={{ width: 360, padding: '24px' }}
            onClick={(e) => e.stopPropagation()}
          >
            <h2 style={{ fontSize: '15px', fontWeight: 600, color: '#f4f4f5', marginBottom: '10px' }}>
              Archive project?
            </h2>
            <p style={{ fontSize: '13px', color: '#71717a', marginBottom: '20px' }}>
              The project will be archived and hidden from active listings. This can be undone later.
            </p>
            <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
              <button
                onClick={() => setArchiveConfirm(false)}
                style={{
                  padding: '7px 16px', borderRadius: '6px', border: '1px solid #27272a',
                  background: 'transparent', color: '#a1a1aa', fontSize: '13px', cursor: 'pointer',
                }}
              >
                Cancel
              </button>
              <button
                onClick={() => archiveMutation.mutate()}
                disabled={archiveMutation.isPending}
                style={{
                  padding: '7px 16px', borderRadius: '6px', border: 'none',
                  background: '#7f1d1d', color: '#fca5a5', fontSize: '13px', cursor: 'pointer',
                }}
              >
                {archiveMutation.isPending ? 'Archiving…' : 'Archive'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p style={{ fontSize: '10px', color: '#52525b', margin: '0 0 2px', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
        {label}
      </p>
      <p style={{ fontSize: '13px', color: '#d4d4d8', margin: 0, fontWeight: 500 }}>{value}</p>
    </div>
  )
}

function AddMemberDropdown({
  orgId,
  projectId,
  addableMembers,
  onAdded,
}: {
  orgId: string
  projectId: string
  addableMembers: { user_id: string; email: string; full_name: string | null }[]
  onAdded: () => void
}) {
  const [open, setOpen] = useState(false)
  const [adding, setAdding] = useState<string | null>(null)

  const handleAdd = async (userId: string) => {
    setAdding(userId)
    try {
      await projectsApi.addMember(orgId, projectId, userId)
      onAdded()
    } finally {
      setAdding(null)
      setOpen(false)
    }
  }

  return (
    <div style={{ position: 'relative' }}>
      <button
        onClick={() => setOpen((v) => !v)}
        style={{
          display: 'inline-flex', alignItems: 'center', gap: '6px',
          padding: '5px 12px', borderRadius: '6px',
          border: '1px solid #27272a', background: 'transparent',
          color: '#a1a1aa', fontSize: '12px', cursor: 'pointer',
        }}
      >
        + Add member
      </button>
      {open && (
        <div
          style={{
            position: 'absolute', top: '100%', right: 0, zIndex: 10,
            marginTop: '6px', background: '#18181b', border: '1px solid #27272a',
            borderRadius: '8px', minWidth: '220px', overflow: 'hidden',
            boxShadow: '0 8px 24px rgba(0,0,0,0.4)',
          }}
        >
          {addableMembers.map((m) => (
            <button
              key={m.user_id}
              onClick={() => handleAdd(m.user_id)}
              disabled={adding === m.user_id}
              style={{
                width: '100%', textAlign: 'left', padding: '10px 14px',
                background: 'none', border: 'none', cursor: 'pointer',
                color: '#d4d4d8', fontSize: '13px',
                borderBottom: '1px solid #27272a',
              }}
            >
              {m.full_name ? `${m.full_name} (${m.email})` : m.email}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Scope components ──────────────────────────────────────────────────────────

const ASSET_TYPE_LABELS: Record<string, string> = {
  domain: 'Domain',
  mx_record: 'MX Record',
  smtp_endpoint: 'SMTP Endpoint',
  webmail: 'Webmail',
  ip: 'IP',
}

function ScopeList({
  orgId,
  projectId,
  projectActive,
}: {
  orgId: string
  projectId: string
  projectActive: boolean
}) {
  const qc = useQueryClient()
  const { data: scope, isLoading } = useQuery({
    queryKey: ['project-scope', orgId, projectId],
    queryFn: () => assetsApi.listScope(orgId, projectId),
    enabled: !!orgId && !!projectId,
  })

  const removeMutation = useMutation({
    mutationFn: (assetId: string) => assetsApi.removeScope(orgId, projectId, assetId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['project-scope', orgId, projectId] }),
  })

  if (isLoading) return <p style={{ color: '#52525b', fontSize: '13px', margin: 0 }}>Loading…</p>
  if (!scope || scope.length === 0) {
    return <p style={{ color: '#52525b', fontSize: '13px', margin: 0 }}>No scope targets defined. Add a domain or asset to authorize scanning.</p>
  }

  return (
    <div style={{ display: 'grid', gap: '6px' }}>
      {scope.map((item: { asset_id: string; asset: { asset_type: string; value: string; last_seen_at: string }; authorized: boolean }) => (
        <div
          key={item.asset_id}
          style={{
            display: 'flex', alignItems: 'center', gap: '12px',
            padding: '9px 14px', borderRadius: '8px', background: '#111113',
          }}
        >
          <span style={{
            fontSize: '10px', padding: '2px 7px', borderRadius: '10px',
            background: '#1e1e22', color: '#71717a', flexShrink: 0,
          }}>
            {ASSET_TYPE_LABELS[item.asset.asset_type] ?? item.asset.asset_type}
          </span>
          <span style={{ flex: 1, fontSize: '13px', color: '#d4d4d8', fontFamily: 'monospace', minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {item.asset.value}
          </span>
          <span style={{
            fontSize: '10px', color: item.authorized ? '#36b37e' : '#ef4444', flexShrink: 0,
          }}>
            {item.authorized ? 'authorized' : 'unauthorized'}
          </span>
          <span style={{ fontSize: '11px', color: '#52525b', flexShrink: 0 }}>
            {new Date(item.asset.last_seen_at).toLocaleDateString()}
          </span>
          {projectActive && (
            <button
              onClick={() => removeMutation.mutate(item.asset_id)}
              disabled={removeMutation.isPending}
              title="Remove from scope"
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#52525b', padding: '4px', borderRadius: '4px' }}
            >
              <Trash2 size={12} />
            </button>
          )}
        </div>
      ))}
    </div>
  )
}

// ── Project reports ───────────────────────────────────────────────────────────

function ProjectReportsList({ orgId, projectId }: { orgId: string; projectId: string }) {
  const { data: reportList, isLoading } = useQuery({
    queryKey: ['project-reports', orgId, projectId],
    queryFn: () => reportsV2.listProjectReports(orgId, projectId, { limit: 20 }),
    enabled: !!orgId && !!projectId,
  })

  if (isLoading) return <p style={{ color: '#52525b', fontSize: '13px', margin: 0 }}>Loading…</p>
  if (!reportList || reportList.length === 0) {
    return (
      <p style={{ color: '#52525b', fontSize: '13px', margin: 0 }}>
        No reports generated yet. Generate a report from an assessment to see it here.
      </p>
    )
  }

  return (
    <div style={{ display: 'grid', gap: '6px' }}>
      {reportList.map((r) => (
        <div
          key={r.id}
          style={{
            display: 'flex', alignItems: 'center', gap: '12px',
            padding: '9px 14px', borderRadius: '8px', background: '#111113',
          }}
        >
          <FileText size={13} style={{ color: '#52525b', flexShrink: 0 }} />
          <span style={{ flex: 1, fontSize: '13px', color: '#d4d4d8', minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {r.title ?? `${r.report_type} report`}
          </span>
          <span style={{ fontSize: '10px', padding: '2px 7px', borderRadius: '10px', background: '#1e1e22', color: '#71717a', flexShrink: 0 }}>
            {r.format.toUpperCase()}
          </span>
          <span style={{ fontSize: '11px', color: '#52525b', flexShrink: 0 }}>
            {new Date(r.generated_at).toLocaleDateString()}
          </span>
          {r.size_bytes != null && (
            <span style={{ fontSize: '11px', color: '#3f3f46', flexShrink: 0 }}>
              {r.size_bytes < 1024 ? `${r.size_bytes}B` : `${(r.size_bytes / 1024).toFixed(1)}KB`}
            </span>
          )}
        </div>
      ))}
    </div>
  )
}

function AddScopeForm({
  orgId,
  projectId,
  onAdded,
}: {
  orgId: string
  projectId: string
  onAdded: () => void
}) {
  const [open, setOpen] = useState(false)
  const [assetType, setAssetType] = useState('domain')
  const [value, setValue] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!value.trim()) return
    setSaving(true)
    setError('')
    try {
      await assetsApi.addScope(orgId, projectId, { asset_type: assetType, value: value.trim() })
      setValue('')
      setOpen(false)
      onAdded()
    } catch {
      setError('Failed to add target.')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div style={{ position: 'relative' }}>
      <button
        onClick={() => setOpen((v) => !v)}
        style={{
          display: 'inline-flex', alignItems: 'center', gap: '6px',
          padding: '5px 12px', borderRadius: '6px',
          border: '1px solid #27272a', background: 'transparent',
          color: '#a1a1aa', fontSize: '12px', cursor: 'pointer',
        }}
      >
        <Plus size={12} /> Add target
      </button>
      {open && (
        <div
          style={{
            position: 'absolute', top: '100%', right: 0, zIndex: 10,
            marginTop: '6px', background: '#18181b', border: '1px solid #27272a',
            borderRadius: '8px', padding: '14px', minWidth: '280px',
            boxShadow: '0 8px 24px rgba(0,0,0,0.4)',
          }}
          onClick={(e) => e.stopPropagation()}
        >
          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <select
              value={assetType}
              onChange={(e) => setAssetType(e.target.value)}
              style={{
                padding: '6px 10px', borderRadius: '5px', border: '1px solid #27272a',
                background: '#111113', color: '#d4d4d8', fontSize: '12px',
              }}
            >
              {Object.entries(ASSET_TYPE_LABELS).map(([k, v]) => (
                <option key={k} value={k}>{v}</option>
              ))}
            </select>
            <input
              type="text"
              placeholder="e.g. example.com"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              style={{
                padding: '6px 10px', borderRadius: '5px', border: '1px solid #27272a',
                background: '#111113', color: '#d4d4d8', fontSize: '12px',
              }}
            />
            {error && <p style={{ color: '#ef4444', fontSize: '11px', margin: 0 }}>{error}</p>}
            <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
              <button
                type="button"
                onClick={() => setOpen(false)}
                style={{
                  padding: '5px 12px', borderRadius: '5px', border: '1px solid #27272a',
                  background: 'transparent', color: '#a1a1aa', fontSize: '12px', cursor: 'pointer',
                }}
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={saving || !value.trim()}
                style={{
                  padding: '5px 12px', borderRadius: '5px', border: 'none',
                  background: 'rgba(var(--color-accent-rgb), 0.9)', color: '#fff',
                  fontSize: '12px', cursor: 'pointer',
                }}
              >
                {saving ? 'Adding…' : 'Add'}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  )
}

// ── MonitoringSection ─────────────────────────────────────────────────────────

interface MonitoringSchedule {
  id: string
  project_id: string
  profile_id: string
  cron_expression: string
  enabled: boolean
  next_run_at: string | null
  last_run_at: string | null
  last_scan_id: string | null
  created_at: string
}

function MonitoringSection({
  orgId,
  projectId,
  projectActive,
}: {
  orgId: string
  projectId: string
  projectActive: boolean
}) {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [cronExpr, setCronExpr] = useState('0 2 * * *')
  const [profileId, setProfileId] = useState('')

  const { data: schedules, isLoading } = useQuery<MonitoringSchedule[]>({
    queryKey: ['monitoring', orgId, projectId],
    queryFn: () => monitoringApi.list(orgId, projectId),
  })

  const { data: profileList = [] } = useQuery({
    queryKey: ['profiles', orgId],
    queryFn: () => profilesApi.list(orgId),
    enabled: showCreate,
  })

  const createMutation = useMutation({
    mutationFn: (body: { cron_expression: string; profile_id: string }) =>
      monitoringApi.create(orgId, projectId, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['monitoring', orgId, projectId] })
      setShowCreate(false)
      setCronExpr('0 2 * * *')
      setProfileId('')
    },
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      monitoringApi.update(orgId, projectId, id, { enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['monitoring', orgId, projectId] }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => monitoringApi.delete(orgId, projectId, id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['monitoring', orgId, projectId] }),
  })

  if (isLoading) {
    return <p style={{ color: '#52525b', fontSize: '13px', margin: 0 }}>Loading…</p>
  }

  return (
    <div>
      {schedules && schedules.length > 0 ? (
        <div style={{ display: 'grid', gap: '8px', marginBottom: showCreate ? '16px' : 0 }}>
          {schedules.map((s) => (
            <div
              key={s.id}
              style={{
                display: 'flex', alignItems: 'center', gap: '12px',
                padding: '10px 14px', borderRadius: '8px', background: '#111113',
              }}
            >
              <div style={{ flex: 1, minWidth: 0 }}>
                <code style={{ fontSize: '12px', color: '#d4d4d8', fontFamily: 'monospace' }}>
                  {s.cron_expression}
                </code>
                <div style={{ fontSize: '11px', color: '#52525b', marginTop: '2px' }}>
                  {s.next_run_at
                    ? `Next: ${new Date(s.next_run_at).toLocaleString()}`
                    : s.enabled ? 'Computing next run…' : 'Paused'}
                  {s.last_run_at && ` · Last: ${new Date(s.last_run_at).toLocaleString()}`}
                </div>
              </div>

              <span style={{
                fontSize: '10px', padding: '2px 7px', borderRadius: '10px',
                background: s.enabled ? 'rgba(74,222,128,0.1)' : 'rgba(113,113,122,0.15)',
                color: s.enabled ? '#4ade80' : '#71717a',
              }}>
                {s.enabled ? 'active' : 'paused'}
              </span>

              {projectActive && (
                <>
                  <button
                    onClick={() => toggleMutation.mutate({ id: s.id, enabled: !s.enabled })}
                    title={s.enabled ? 'Pause' : 'Resume'}
                    style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#52525b', padding: '4px' }}
                  >
                    {s.enabled ? <ToggleRight size={14} style={{ color: '#4ade80' }} /> : <ToggleLeft size={14} />}
                  </button>
                  <button
                    onClick={() => deleteMutation.mutate(s.id)}
                    title="Delete schedule"
                    style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#52525b', padding: '4px' }}
                  >
                    <Trash2 size={12} />
                  </button>
                </>
              )}
            </div>
          ))}
        </div>
      ) : (
        !showCreate && (
          <p style={{ color: '#52525b', fontSize: '13px', margin: '0 0 12px' }}>
            No monitoring schedules. Add one to run recurring assessments automatically.
          </p>
        )
      )}

      {projectActive && !showCreate && (
        <button
          onClick={() => setShowCreate(true)}
          style={{
            display: 'inline-flex', alignItems: 'center', gap: '6px',
            padding: '6px 12px', borderRadius: '6px',
            border: '1px solid #27272a', background: 'transparent',
            color: '#71717a', fontSize: '12px', cursor: 'pointer', marginTop: '4px',
          }}
        >
          <Plus size={12} /> Add schedule
        </button>
      )}

      {showCreate && (
        <div style={{ marginTop: '12px', padding: '16px', borderRadius: '8px', background: '#111113' }}>
          <p style={{ fontSize: '12px', color: '#a1a1aa', marginBottom: '10px' }}>
            Cron expression (UTC) — e.g. <code style={{ color: '#d4d4d8' }}>0 2 * * *</code> = daily at 02:00
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <select
              value={profileId}
              onChange={(e) => setProfileId(e.target.value)}
              style={{
                background: '#0a0a0a', border: '1px solid #27272a', borderRadius: '6px',
                color: profileId ? '#f4f4f5' : '#71717a', fontSize: '13px', padding: '7px 10px', outline: 'none',
              }}
            >
              <option value="">Default profile (Full scan)</option>
              {profileList.map((p) => (
                <option key={p.id} value={p.id}>{p.name}{p.is_builtin ? '' : ' (custom)'}</option>
              ))}
            </select>
            <input
              value={cronExpr}
              onChange={(e) => setCronExpr(e.target.value)}
              placeholder="0 2 * * *"
              style={{
                background: '#0a0a0a', border: '1px solid #27272a', borderRadius: '6px',
                color: '#f4f4f5', fontSize: '13px', padding: '7px 10px', fontFamily: 'monospace', outline: 'none',
              }}
            />
          </div>
          <div style={{ display: 'flex', gap: '8px', marginTop: '8px' }}>
            <button
              onClick={() => createMutation.mutate({ cron_expression: cronExpr, profile_id: profileId || '' })}
              disabled={createMutation.isPending || !cronExpr.trim()}
              style={{
                padding: '7px 14px', borderRadius: '6px', border: 'none',
                background: 'rgba(var(--color-accent-rgb), 0.9)', color: '#fff',
                fontSize: '12px', cursor: 'pointer',
              }}
            >
              {createMutation.isPending ? 'Saving…' : 'Save'}
            </button>
            <button
              onClick={() => setShowCreate(false)}
              style={{
                padding: '7px 10px', borderRadius: '6px',
                border: '1px solid #27272a', background: 'transparent',
                color: '#71717a', fontSize: '12px', cursor: 'pointer',
              }}
            >
              Cancel
            </button>
          </div>
          {createMutation.isError && (
            <p style={{ color: '#f87171', fontSize: '11px', marginTop: '8px' }}>
              Error — check cron expression format (5 fields required)
            </p>
          )}
        </div>
      )}
    </div>
  )
}
