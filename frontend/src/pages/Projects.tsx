import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Plus, FolderOpen, Archive, ChevronRight } from 'lucide-react'
import { useAuth } from '../lib/auth'
import { projects as projectsApi } from '../lib/api'
import { PageHeader } from '../components/Layout'
import type { Project } from '../types'

function StatusBadge({ status }: { status: Project['status'] }) {
  const map: Record<Project['status'], { bg: string; color: string }> = {
    active:   { bg: '#16a34a18', color: '#4ade80' },
    archived: { bg: '#71717a18', color: '#a1a1aa' },
    closed:   { bg: '#dc262618', color: '#f87171' },
  }
  const c = map[status]
  return (
    <span style={{
      display: 'inline-block', padding: '2px 8px', borderRadius: '12px',
      fontSize: '11px', fontWeight: 500, background: c.bg, color: c.color,
      flexShrink: 0,
    }}>
      {status}
    </span>
  )
}

function CreateModal({ orgId, onClose }: { orgId: string; onClose: () => void }) {
  const qc = useQueryClient()
  const [name, setName] = useState('')
  const [desc, setDesc] = useState('')
  const [err, setErr] = useState('')

  const { mutate, isPending } = useMutation({
    mutationFn: () => projectsApi.create(orgId, name.trim(), desc.trim() || undefined),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['projects', orgId] }); onClose() },
    onError: (e: unknown) => {
      setErr((e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? 'Creation failed')
    },
  })

  return (
    <div
      style={{
        position: 'fixed', inset: 0, zIndex: 50,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: 'rgba(0,0,0,0.6)', padding: '16px',
      }}
      onClick={onClose}
    >
      <div
        className="card"
        style={{ width: '100%', maxWidth: '420px', padding: '24px' }}
        onClick={(e) => e.stopPropagation()}
      >
        <h2 style={{ fontSize: '15px', fontWeight: 600, marginBottom: '20px', color: '#f4f4f5' }}>
          New project
        </h2>

        <label style={{ display: 'block', marginBottom: '14px' }}>
          <span className="label" style={{ display: 'block', marginBottom: '6px' }}>Name *</span>
          <input
            autoFocus className="input w-full"
            value={name} onChange={(e) => setName(e.target.value)}
            placeholder="e.g. ACME Corp audit"
          />
        </label>

        <label style={{ display: 'block', marginBottom: '20px' }}>
          <span className="label" style={{ display: 'block', marginBottom: '6px' }}>Description</span>
          <textarea
            className="input w-full" rows={3}
            value={desc} onChange={(e) => setDesc(e.target.value)}
            placeholder="Optional"
            style={{ resize: 'vertical' }}
          />
        </label>

        {err && <p style={{ color: '#f87171', fontSize: '12px', marginBottom: '12px' }}>{err}</p>}

        <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
          <button className="btn" onClick={onClose}>Cancel</button>
          <button
            className="btn-primary"
            onClick={() => { if (name.trim().length >= 2) mutate() }}
            disabled={isPending || name.trim().length < 2}
          >
            {isPending ? 'Creating…' : 'Create'}
          </button>
        </div>
      </div>
    </div>
  )
}

export default function Projects() {
  const { currentOrg } = useAuth()
  const [showCreate, setShowCreate] = useState(false)

  const { data, isLoading } = useQuery({
    queryKey: ['projects', currentOrg?.id],
    queryFn: () => projectsApi.list(currentOrg!.id),
    enabled: !!currentOrg,
  })

  if (!currentOrg) return null

  const active   = data?.filter((p) => p.status === 'active') ?? []
  const archived = data?.filter((p) => p.status !== 'active') ?? []

  return (
    <div style={{ maxWidth: '900px' }}>
      {showCreate && (
        <CreateModal orgId={currentOrg.id} onClose={() => setShowCreate(false)} />
      )}

      <PageHeader
        title="Projects"
        subtitle={data ? `${data.length} project${data.length !== 1 ? 's' : ''}` : undefined}
        action={
          <button className="btn-primary" style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
            onClick={() => setShowCreate(true)}>
            <Plus size={14} /> New project
          </button>
        }
      />

      {isLoading && (
        <div style={{ display: 'grid', gap: '10px' }}>
          {[1, 2, 3].map((i) => (
            <div key={i} className="card" style={{ height: '72px', opacity: 0.4 }} />
          ))}
        </div>
      )}

      {!isLoading && active.length === 0 && archived.length === 0 && (
        <div className="card" style={{
          padding: '64px 24px', textAlign: 'center',
          display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '12px',
        }}>
          <FolderOpen size={36} style={{ color: '#3f3f46' }} />
          <p style={{ color: '#71717a', fontSize: '14px', margin: 0 }}>No projects yet</p>
          <button className="btn-primary" style={{ marginTop: '4px' }} onClick={() => setShowCreate(true)}>
            Create first project
          </button>
        </div>
      )}

      {active.length > 0 && <ProjectList title="Active" projects={active} />}

      {archived.length > 0 && (
        <div style={{ marginTop: '28px' }}>
          <ProjectList title="Archived" projects={archived} />
        </div>
      )}
    </div>
  )
}

function ProjectList({ title, projects }: { title: string; projects: Project[] }) {
  return (
    <div>
      <p style={{
        fontSize: '11px', fontWeight: 600, color: '#52525b',
        textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '8px',
      }}>
        {title}
      </p>
      <div style={{ display: 'grid', gap: '8px' }}>
        {projects.map((p) => <ProjectRow key={p.id} project={p} />)}
      </div>
    </div>
  )
}

function ProjectRow({ project }: { project: Project }) {
  const relTime = formatRelativeTime(new Date(project.updated_at))

  return (
    <Link to={`/projects/${project.id}`} style={{ textDecoration: 'none' }}>
      <div className="card" style={{
        padding: '14px 18px',
        display: 'flex', alignItems: 'center', gap: '14px',
        cursor: 'pointer', transition: 'background-color 150ms',
      }}>
        <div style={{
          width: 36, height: 36, borderRadius: '8px', flexShrink: 0,
          background: 'rgba(var(--color-accent-rgb), 0.1)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          {project.status === 'archived'
            ? <Archive size={16} style={{ color: 'rgba(229,57,53,0.7)' }} />
            : <FolderOpen size={16} style={{ color: 'rgba(229,57,53,0.7)' }} />}
        </div>

        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
            <span style={{
              fontSize: '14px', fontWeight: 600, color: '#f4f4f5',
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
            }}>
              {project.name}
            </span>
            <StatusBadge status={project.status} />
          </div>
          {project.description && (
            <p style={{
              fontSize: '12px', color: '#71717a', margin: '2px 0 0',
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
            }}>
              {project.description}
            </p>
          )}
        </div>

        <span style={{ fontSize: '11px', color: '#52525b', flexShrink: 0, whiteSpace: 'nowrap' }}>
          {relTime}
        </span>

        <ChevronRight size={14} style={{ color: '#52525b', flexShrink: 0 }} />
      </div>
    </Link>
  )
}

function formatRelativeTime(date: Date): string {
  const diff = Date.now() - date.getTime()
  const m = Math.floor(diff / 60000)
  if (m < 1)  return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  const d = Math.floor(h / 24)
  if (d < 30) return `${d}d ago`
  return date.toLocaleDateString()
}
