import React, { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { PageHeader } from '../components/Layout'
import { useAuth } from '../lib/auth'
import { auth as authApi, orgs as orgsApi } from '../lib/api'
import { prefs } from '../lib/preferences'
import { toast } from 'sonner'
import { Eye, EyeOff, Monitor, ShieldCheck, ShieldOff, Smartphone, Trash2 } from 'lucide-react'

const ACCENT_COLORS = [
  { label: 'Crimson', value: '#E8173A' },
  { label: 'Amber', value: '#CA8A04' },
  { label: 'Emerald', value: '#3fb950' },
  { label: 'Blue', value: '#2563EB' },
  { label: 'Violet', value: '#7c3aed' },
]

/**
 * UI-only gate for org admin cards/actions. The backend enforces permissions;
 * this only hides controls a member can't use. When the API doesn't expose the
 * caller's role (undefined), everything stays visible and the backend decides.
 */
function useCanAdminOrg(): boolean {
  const { user, currentOrg } = useAuth()
  if (user?.is_platform_admin) return true
  const role = currentOrg?.current_user_role
  if (role == null) return true
  return role === 'org_admin'
}

export default function Settings() {
  const { localMode } = useAuth()
  const canAdmin = useCanAdminOrg()

  // Local mode: simplified settings (no accounts, no orgs, just tool config)
  if (localMode) {
    return (
      <div>
        <PageHeader title="Settings" />
        <div className="settings-grid">
          <div className="flex flex-col gap-5">
            <AppearanceCard />
            <PentestConfigCard />
          </div>
          <div className="flex flex-col gap-5">
            <IntegrationsCard />
          </div>
        </div>
      </div>
    )
  }

  return (
    <div>
      <PageHeader title="Settings" />

      {/* Two-column layout — balanced distribution */}
      <div className="settings-grid">
        {/* Left column — Account & Org */}
        <div className="flex flex-col gap-5">
          <ProfileCard />
          <MFACard />
          <SessionsCard />
          <AppearanceCard />
        </div>

        {/* Right column — Org & Integrations */}
        <div className="flex flex-col gap-5">
          <OrgInfoCard />
          <CreateOrgCard />
          {canAdmin && <PentestConfigCard />}
          {canAdmin && <IntegrationsCard />}
        </div>
      </div>
    </div>
  )
}

// ── Profile / Avatar ─────────────────────────────────────────────────────────

function ProfileCard() {
  const { user } = useAuth()
  const avatarKey = user?.id ? `mailox_avatar_${user.id}` : null
  const [avatarUrl, setAvatarUrl] = useState<string | null>(null)

  // Sync avatar when user changes (login/logout/switch)
  React.useEffect(() => {
    if (!avatarKey) {
      setAvatarUrl(null)
      return
    }
    try {
      setAvatarUrl(localStorage.getItem(avatarKey))
    } catch {
      setAvatarUrl(null)
    }
  }, [avatarKey])

  const initials = (() => {
    const name = user?.full_name ?? user?.email ?? ''
    const parts = name.trim().split(/\s+/)
    if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase()
    return name.slice(0, 2).toUpperCase()
  })()

  function handleUpload() {
    const input = document.createElement('input')
    input.type = 'file'
    input.accept = 'image/*'
    input.onchange = () => {
      const file = input.files?.[0]
      if (!file) return
      const reader = new FileReader()
      reader.onload = (e) => {
        const result = e.target?.result as string
        try { if (avatarKey) localStorage.setItem(avatarKey, result) } catch { /* quota */ }
        window.dispatchEvent(new StorageEvent('storage', { key: avatarKey ?? '', newValue: result }))
        setAvatarUrl(result)
        toast.success('Photo de profil mise à jour')
      }
      reader.readAsDataURL(file)
    }
    input.click()
  }

  function handleRemove() {
    try { if (avatarKey) localStorage.removeItem(avatarKey) } catch { /* noop */ }
    window.dispatchEvent(new StorageEvent('storage', { key: avatarKey ?? '', newValue: null }))
    setAvatarUrl(null)
    toast.success('Photo supprimée')
  }

  return (
    <Section title="Profile">
      <div className="flex items-center gap-5">
        <button
          onClick={handleUpload}
          title="Changer la photo"
          style={{
            width: '72px', height: '72px', borderRadius: '12px', border: 'none',
            cursor: 'pointer', overflow: 'hidden', flexShrink: 0, position: 'relative',
            background: avatarUrl ? 'transparent' : 'rgba(232,23,58,0.12)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}
          onMouseEnter={(e) => { const o = (e.currentTarget as HTMLElement).querySelector('.av-overlay') as HTMLElement | null; if (o) o.style.opacity = '1' }}
          onMouseLeave={(e) => { const o = (e.currentTarget as HTMLElement).querySelector('.av-overlay') as HTMLElement | null; if (o) o.style.opacity = '0' }}
        >
          {avatarUrl
            ? <img src={avatarUrl} alt="" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
            : <span style={{ fontSize: '22px', color: '#E8173A', fontWeight: 600 }}>{initials}</span>}
          <div className="av-overlay" style={{
            position: 'absolute', inset: 0, background: 'rgba(0,0,0,0.55)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            opacity: 0, transition: 'opacity 150ms',
          }}>
            <span style={{ fontSize: '10px', color: '#fff', letterSpacing: '0.05em' }}>EDIT</span>
          </div>
        </button>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: '14px', color: '#c8ccd4', fontWeight: 500, marginBottom: '4px' }}>
            {user?.full_name ?? user?.email?.split('@')[0] ?? '—'}
          </div>
          <div style={{ fontSize: '12px', color: '#52525B', marginBottom: '12px' }}>{user?.email}</div>
          <div className="flex gap-2">
            <button className="btn-secondary" style={{ fontSize: '12px', padding: '5px 12px' }} onClick={handleUpload}>
              {avatarUrl ? 'Changer' : 'Uploader'} photo
            </button>
            {avatarUrl && (
              <button className="btn-ghost" style={{ fontSize: '12px', padding: '5px 12px', color: '#EF4444' }} onClick={handleRemove}>
                Supprimer
              </button>
            )}
          </div>
        </div>
      </div>
    </Section>
  )
}

// ── Organization info ─────────────────────────────────────────────────────────

function OrgInfoCard() {
  const { currentOrg, refreshOrgs, setCurrentOrg, orgs } = useAuth()
  const [editing, setEditing] = useState(false)
  const [nameInput, setNameInput] = useState('')
  const [confirmDelete, setConfirmDelete] = useState(false)
  const navigate = useNavigate()
  const canAdmin = useCanAdminOrg()

  const updateMutation = useMutation({
    mutationFn: (name: string) => orgsApi.update(currentOrg!.id, name),
    onSuccess: (updated) => {
      setEditing(false)
      refreshOrgs()
      setCurrentOrg({ ...currentOrg!, name: updated.name })
      toast.success('Organization name updated')
    },
    onError: () => toast.error('Failed to update name'),
  })

  const deleteMutation = useMutation({
    mutationFn: () => orgsApi.delete(currentOrg!.id),
    onSuccess: async () => {
      toast.success('Organization deleted')
      await refreshOrgs()
      const remaining = orgs.filter((o) => o.id !== currentOrg!.id)
      if (remaining.length > 0) setCurrentOrg(remaining[0])
      else navigate('/')
    },
    onError: () => toast.error('Failed to delete organization'),
  })

  if (!currentOrg) return null

  return (
    <Section title="Organization">
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-5">
        <div>
          <div className="text-xs mb-1" style={{ color: '#52525B', letterSpacing: '1px' }}>NAME</div>
          {editing ? (
            <div className="flex items-center gap-2">
              <input
                type="text"
                className="input flex-1"
                style={{ padding: '5px 10px', fontSize: '13px' }}
                value={nameInput}
                onChange={(e) => setNameInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && nameInput.trim()) updateMutation.mutate(nameInput.trim())
                  if (e.key === 'Escape') setEditing(false)
                }}
                autoFocus
              />
              <button
                className="btn-primary"
                style={{ padding: '5px 12px', fontSize: '12px', whiteSpace: 'nowrap' }}
                disabled={updateMutation.isPending || !nameInput.trim()}
                onClick={() => updateMutation.mutate(nameInput.trim())}
              >
                Save
              </button>
              <button
                className="btn-ghost"
                style={{ padding: '5px 10px', fontSize: '12px' }}
                onClick={() => setEditing(false)}
              >
                Cancel
              </button>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <span style={{ fontSize: '13px', color: '#c8ccd4' }}>{currentOrg.name}</span>
              {canAdmin && <button
                style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: '#3a3a44', padding: '2px' }}
                onClick={() => { setNameInput(currentOrg.name); setEditing(true) }}
                title="Edit name"
                onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.color = '#c8ccd4' }}
                onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.color = '#3a3a44' }}
              >
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
              </button>}
            </div>
          )}
        </div>
        <Field label="Slug" value={currentOrg.slug} mono />
        <Field
          label="Created"
          value={new Date(currentOrg.created_at).toLocaleDateString('en-US', {
            year: 'numeric', month: 'short', day: 'numeric',
          })}
        />
        <Field label="ID" value={currentOrg.id} mono truncate />
      </div>

      {canAdmin && <div className="pt-4 border-t border-border">
        {confirmDelete ? (
          <div>
            <p className="text-sm mb-3" style={{ color: '#EF4444', lineHeight: 1.5 }}>
              Delete <strong>{currentOrg.name}</strong>? This is irreversible.
            </p>
            <div className="flex gap-2">
              <button
                className="btn-primary"
                style={{ padding: '7px 16px', fontSize: '12px', background: '#EF4444', borderColor: '#EF4444' }}
                onClick={() => deleteMutation.mutate()}
                disabled={deleteMutation.isPending}
              >
                {deleteMutation.isPending ? 'Deleting…' : 'Confirm delete'}
              </button>
              <button className="btn-ghost" style={{ padding: '7px 12px', fontSize: '12px' }} onClick={() => setConfirmDelete(false)}>
                Cancel
              </button>
            </div>
          </div>
        ) : (
          <button
            className="btn-ghost"
            style={{ padding: '6px 12px', fontSize: '12px', color: '#EF4444', display: 'flex', alignItems: 'center', gap: '6px' }}
            onClick={() => setConfirmDelete(true)}
          >
            <Trash2 size={13} />
            Delete organization
          </button>
        )}
      </div>}
    </Section>
  )
}

// ── Create org ────────────────────────────────────────────────────────────────

function CreateOrgCard() {
  const { refreshOrgs } = useAuth()
  const qc = useQueryClient()
  const [orgName, setOrgName] = useState('')

  const createMutation = useMutation({
    mutationFn: (name: string) => orgsApi.create(name),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['orgs'] })
      refreshOrgs()
      setOrgName('')
      toast.success('Organization created')
    },
    onError: (err: { response?: { data?: { detail?: string } } }) => {
      toast.error(err?.response?.data?.detail ?? 'Failed to create organization')
    },
  })

  return (
    <Section title="New Organization">
      <form
        onSubmit={(e) => {
          e.preventDefault()
          if (orgName.trim()) createMutation.mutate(orgName.trim())
        }}
        className="flex gap-3"
      >
        <input
          type="text"
          className="input flex-1"
          value={orgName}
          onChange={(e) => setOrgName(e.target.value)}
          placeholder="Organization name"
          required
        />
        <button
          type="submit"
          disabled={createMutation.isPending}
          className="btn-primary"
          style={{ whiteSpace: 'nowrap' }}
        >
          {createMutation.isPending ? 'Creating…' : 'Create'}
        </button>
      </form>
    </Section>
  )
}

// ── Appearance ────────────────────────────────────────────────────────────────

function AppearanceCard() {
  const [density, setDensity] = useState<'compact' | 'comfortable' | 'spacious'>(
    () => prefs.getDensity()
  )
  const [accent, setAccent] = useState(() => prefs.getAccentColor())
  const [reducedMotion, setReducedMotion] = useState(() => prefs.getReducedMotion())

  function applyToDOM(d: typeof density, a: string, rm: boolean) {
    const root = document.documentElement
    root.dataset.density = d
    root.style.setProperty('--color-accent', a)
    const h = a.replace('#', ''); root.style.setProperty('--color-accent-rgb', `${parseInt(h.slice(0,2),16)}, ${parseInt(h.slice(2,4),16)}, ${parseInt(h.slice(4,6),16)}`)
    if (rm) root.dataset.reducedMotion = 'true'
    else delete root.dataset.reducedMotion
  }

  function save() {
    prefs.setDensity(density)
    prefs.setAccentColor(accent)
    prefs.setReducedMotion(reducedMotion)
    applyToDOM(density, accent, reducedMotion)
    toast.success('Preferences saved')
  }

  function reset() {
    const d = 'comfortable' as const, a = '#E8173A', rm = false
    setDensity(d); setAccent(a); setReducedMotion(rm)
    prefs.setDensity(d); prefs.setAccentColor(a); prefs.setReducedMotion(rm)
    applyToDOM(d, a, rm)
    toast.success('Reset to defaults')
  }

  return (
    <Section title="Appearance">
      {/* Density */}
      <div className="mb-6">
        <div className="text-sm text-text-primary mb-1">Interface density</div>
        <div className="text-xs text-text-muted mb-3">Controls padding in tables and content areas</div>
        <div className="flex gap-2 flex-wrap">
          {(['compact', 'comfortable', 'spacious'] as const).map((d) => (
            <button
              key={d}
              onClick={() => setDensity(d)}
              className={density === d ? 'btn-primary' : 'btn-secondary'}
              style={{ padding: '6px 16px', fontSize: '13px' }}
            >
              {d.charAt(0).toUpperCase() + d.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Accent */}
      <div className="mb-6">
        <div className="text-sm text-text-primary mb-1">Accent color</div>
        <div className="text-xs text-text-muted mb-3">Applied to buttons, focus rings, and active states</div>
        <div className="flex gap-3 flex-wrap">
          {ACCENT_COLORS.map((c) => (
            <button
              key={c.value}
              onClick={() => setAccent(c.value)}
              title={c.label}
              style={{
                width: '28px',
                height: '28px',
                background: c.value,
                border: accent === c.value ? '2px solid #e8ecf2' : '2px solid transparent',
                outline: accent === c.value ? `2px solid ${c.value}` : 'none',
                outlineOffset: '2px',
                cursor: 'pointer',
                borderRadius: '6px',
                transition: 'outline 150ms var(--ease-out)',
              }}
            />
          ))}
        </div>
        <div className="text-xs text-text-muted mt-2">
          {ACCENT_COLORS.find((c) => c.value === accent)?.label ?? accent}
        </div>
      </div>

      {/* Reduced motion */}
      <div className="mb-6 flex items-center justify-between gap-4">
        <div>
          <div className="text-sm text-text-primary">Reduced motion</div>
          <div className="text-xs text-text-muted">Disables entrance animations. Keeps opacity fades.</div>
        </div>
        <button
          onClick={() => setReducedMotion((r) => !r)}
          style={{
            width: '44px',
            height: '24px',
            background: reducedMotion ? 'var(--color-accent)' : '#1f1f1f',
            border: '1px solid',
            borderColor: reducedMotion ? 'var(--color-accent)' : '#3a3a44',
            borderRadius: '12px',
            position: 'relative',
            cursor: 'pointer',
            flexShrink: 0,
            transition: 'background-color 200ms var(--ease-out), border-color 200ms var(--ease-out)',
          }}
        >
          <span style={{
            position: 'absolute',
            top: '3px',
            left: reducedMotion ? '22px' : '3px',
            width: '16px',
            height: '16px',
            background: '#e8ecf2',
            borderRadius: '50%',
            transition: 'left 200ms var(--ease-out)',
          }} />
        </button>
      </div>

      {/* System info */}
      <div className="border-t border-border pt-4 mb-6 space-y-2">
        <InfoRow label="Timezone" value={Intl.DateTimeFormat().resolvedOptions().timeZone} />
        <InfoRow label="Language" value="English" />
      </div>

      <div className="flex gap-3">
        <button onClick={save} className="btn-primary">Save preferences</button>
        <button onClick={reset} className="btn-secondary">Reset</button>
      </div>
    </Section>
  )
}

// ── MFA ───────────────────────────────────────────────────────────────────────

function MFACard() {
  const qc = useQueryClient()
  const [step, setStep] = useState<'idle' | 'pending' | 'done'>('idle')
  const [setupData, setSetupData] = useState<{ secret: string; backup_codes: string[] } | null>(null)
  const [code, setCode] = useState('')
  const [err, setErr] = useState<string | null>(null)

  const { data: me } = useQuery({ queryKey: ['me'], queryFn: () => authApi.me() })

  const setupMut = useMutation({
    mutationFn: () => authApi.mfaSetup(),
    onSuccess: (d) => { setSetupData(d); setStep('pending'); setErr(null) },
    onError: (e: { response?: { data?: { detail?: string } } }) =>
      setErr(e?.response?.data?.detail ?? 'Setup failed'),
  })

  const verifyMut = useMutation({
    mutationFn: (c: string) => authApi.mfaVerify(c),
    onSuccess: () => {
      setStep('done'); setSetupData(null); setCode('')
      qc.invalidateQueries({ queryKey: ['me'] })
      toast.success('MFA enabled')
    },
    onError: (e: { response?: { data?: { detail?: string } } }) =>
      setErr(e?.response?.data?.detail ?? 'Invalid code'),
  })

  const isMfaOn = me?.mfa_enabled && step !== 'pending'

  return (
    <Section
      title="Two-Factor Authentication"
      badge={
        <span style={{
          fontSize: '11px',
          color: isMfaOn ? '#3fb950' : '#666672',
          border: `1px solid ${isMfaOn ? 'rgba(63,185,80,0.3)' : '#1f1f1f'}`,
          padding: '2px 10px',
          borderRadius: '4px',
        }}>
          {isMfaOn ? 'Enabled' : 'Disabled'}
        </span>
      }
    >
      {isMfaOn || step === 'done' ? (
        <div className="flex items-center gap-2 text-sm" style={{ color: '#3fb950' }}>
          <ShieldCheck size={14} />
          MFA active — TOTP authenticator
        </div>
      ) : step === 'idle' ? (
        <div>
          <p className="text-sm text-text-muted mb-4" style={{ lineHeight: 1.6 }}>
            Protect your account with a TOTP authenticator app (Google Authenticator, Authy, 1Password).
          </p>
          <button className="btn-primary" disabled={setupMut.isPending} onClick={() => setupMut.mutate()}>
            <ShieldOff size={14} />
            {setupMut.isPending ? 'Generating…' : 'Enable MFA'}
          </button>
          {err && <p className="mt-2 text-xs" style={{ color: '#E8173A' }}>{err}</p>}
        </div>
      ) : setupData ? (
        <div className="space-y-5">
          <div>
            <div className="label mb-2">Secret key</div>
            <code className="block text-xs text-text-primary bg-bg-elevated border border-border px-3 py-2 select-all break-all mono" style={{ borderRadius: '5px' }}>
              {setupData.secret}
            </code>
          </div>
          {setupData.backup_codes.length > 0 && (
            <div>
              <div className="label mb-2">Backup codes — save now, shown once</div>
              <div className="bg-bg-elevated border border-border p-3 grid grid-cols-2 gap-1" style={{ borderRadius: '5px' }}>
                {setupData.backup_codes.map((c) => (
                  <code key={c} className="text-xs text-text-primary mono">{c}</code>
                ))}
              </div>
            </div>
          )}
          <div>
            <div className="label mb-2">Verification code</div>
            <div className="flex items-center gap-3 flex-wrap">
              <input
                type="text"
                inputMode="numeric"
                maxLength={6}
                className="input w-28 text-center mono"
                style={{ letterSpacing: '0.3em' }}
                placeholder="000000"
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
              />
              <button className="btn-primary" disabled={code.length !== 6 || verifyMut.isPending} onClick={() => verifyMut.mutate(code)}>
                {verifyMut.isPending ? 'Verifying…' : 'Confirm'}
              </button>
              <button className="btn-ghost" onClick={() => { setStep('idle'); setSetupData(null); setCode('') }}>
                Cancel
              </button>
            </div>
            {err && <p className="mt-1 text-xs" style={{ color: '#E8173A' }}>{err}</p>}
          </div>
        </div>
      ) : null}
    </Section>
  )
}

// ── Sessions ──────────────────────────────────────────────────────────────────

function SessionsCard() {
  const { logout } = useAuth()
  const qc = useQueryClient()
  const [confirmRevokeAll, setConfirmRevokeAll] = useState(false)

  const { data: sessions = [], isLoading } = useQuery({
    queryKey: ['sessions'],
    queryFn: () => authApi.listSessions(),
    refetchInterval: 30_000,
  })

  const revokeOneMutation = useMutation({
    mutationFn: (id: string) => authApi.revokeSession(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['sessions'] })
      toast.success('Session revoked')
    },
    onError: () => toast.error('Failed to revoke session'),
  })

  const revokeAllMutation = useMutation({
    // Context logout: revokes every session server-side, then always clears local
    // state + query cache; ProtectedRoute redirects to /login.
    mutationFn: () => logout(true),
    onError: () => toast.error('Could not revoke other sessions — signed out on this device only'),
  })

  return (
    <Section title="Active Sessions">
      {/* Session list */}
      <div className="space-y-2 mb-5">
        {isLoading ? (
          <div className="text-sm text-text-muted">Loading…</div>
        ) : sessions.length === 0 ? (
          <div className="text-sm text-text-muted">No active sessions found.</div>
        ) : (
          sessions.map((s) => <SessionRow key={s.id} session={s} onRevoke={() => revokeOneMutation.mutate(s.id)} revoking={revokeOneMutation.isPending} />)
        )}
      </div>

      {/* Revoke all */}
      <div className="border-t border-border pt-4">
        {!confirmRevokeAll ? (
          <button className="btn-secondary text-xs" style={{ padding: '6px 14px' }} onClick={() => setConfirmRevokeAll(true)}>
            Sign out all devices
          </button>
        ) : (
          <div className="flex items-center gap-3">
            <button className="btn-primary text-xs" style={{ padding: '6px 14px' }} disabled={revokeAllMutation.isPending} onClick={() => revokeAllMutation.mutate()}>
              {revokeAllMutation.isPending ? 'Signing out…' : 'Confirm'}
            </button>
            <button className="btn-ghost text-xs" onClick={() => setConfirmRevokeAll(false)}>Cancel</button>
          </div>
        )}
      </div>
    </Section>
  )
}

function SessionRow({ session, onRevoke, revoking }: {
  session: { id: string; ip_address: string | null; user_agent: string | null; created_at: string; expires_at: string }
  onRevoke: () => void
  revoking: boolean
}) {
  const ua = session.user_agent ?? ''
  const isMobile = /mobile|android|iphone|ipad/i.test(ua)
  const browser = ua.match(/(Chrome|Firefox|Safari|Edge|Opera)\/[\d.]+/)?.[0] ?? 'Unknown browser'
  const os = ua.match(/\(([^)]+)\)/)?.[1]?.split(';')[0] ?? ''

  const created = new Date(session.created_at)
  const expires = new Date(session.expires_at)
  const now = new Date()
  const daysLeft = Math.ceil((expires.getTime() - now.getTime()) / 86_400_000)

  return (
    <div
      className="flex items-start justify-between gap-3 p-3"
      style={{ background: '#111', borderRadius: '6px', border: '1px solid #1f1f1f' }}
    >
      <div className="flex items-start gap-3">
        <div style={{ color: '#3a3a44', marginTop: '2px', flexShrink: 0 }}>
          {isMobile ? <Smartphone size={14} /> : <Monitor size={14} />}
        </div>
        <div>
          <div className="text-sm text-text-primary" style={{ fontWeight: 500 }}>{browser}</div>
          {os && <div className="text-xs text-text-muted">{os}</div>}
          <div className="text-xs text-text-muted mt-1">
            {session.ip_address ?? 'Unknown IP'} · {created.toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
            {daysLeft > 0 && <span style={{ color: '#3a3a44' }}> · expires in {daysLeft}d</span>}
          </div>
        </div>
      </div>
      <button
        onClick={onRevoke}
        disabled={revoking}
        title="Revoke this session"
        style={{
          background: 'transparent',
          border: 'none',
          cursor: revoking ? 'default' : 'pointer',
          color: '#3a3a44',
          padding: '4px',
          borderRadius: '4px',
          flexShrink: 0,
          transition: 'color 150ms var(--ease-out)',
          opacity: revoking ? 0.4 : 1,
        }}
        onMouseEnter={(e) => { if (!revoking) (e.currentTarget as HTMLElement).style.color = '#E8173A' }}
        onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.color = '#3a3a44' }}
      >
        <Trash2 size={13} />
      </button>
    </div>
  )
}

// ── Shared components ─────────────────────────────────────────────────────────

// ── Pentest Config ────────────────────────────────────────────────────────────

function ToggleRow({
  label,
  description,
  checked,
  onChange,
  disabled,
}: {
  label: string
  description: string
  checked: boolean
  onChange: (v: boolean) => void
  disabled?: boolean
}) {
  return (
    <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '16px' }}>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: '13px', color: '#c8ccd4', fontWeight: 500 }}>{label}</div>
        <div style={{ fontSize: '11px', color: '#52525B', marginTop: '2px', lineHeight: 1.5 }}>{description}</div>
      </div>
      <button
        type="button"
        disabled={disabled}
        onClick={() => onChange(!checked)}
        style={{
          flexShrink: 0,
          width: '36px', height: '20px',
          borderRadius: '10px',
          border: 'none',
          background: checked ? 'var(--color-accent)' : '#2a2a2a',
          cursor: disabled ? 'not-allowed' : 'pointer',
          position: 'relative',
          transition: 'background 200ms',
          opacity: disabled ? 0.5 : 1,
        }}
        aria-pressed={checked}
      >
        <span style={{
          position: 'absolute',
          top: '2px',
          left: checked ? '18px' : '2px',
          width: '16px', height: '16px',
          borderRadius: '50%',
          background: '#fff',
          transition: 'left 200ms',
          boxShadow: '0 1px 3px rgba(0,0,0,0.3)',
        }} />
      </button>
    </div>
  )
}

function PentestConfigCard() {
  const { currentOrg } = useAuth()
  const orgId = currentOrg?.id ?? ''
  const qc = useQueryClient()

  const { data, isLoading } = useQuery({
    queryKey: ['pentest-config', orgId],
    queryFn: () => orgsApi.getPentestConfig(orgId),
    enabled: !!orgId,
  })

  const mutation = useMutation({
    mutationFn: (cfg: Parameters<typeof orgsApi.updatePentestConfig>[1]) =>
      orgsApi.updatePentestConfig(orgId, cfg),
    onSuccess: (updated) => {
      qc.setQueryData(['pentest-config', orgId], updated)
      toast.success('Pentest config saved')
    },
    onError: () => toast.error('Failed to save config'),
  })

  const testMutation = useMutation({
    mutationFn: () => orgsApi.testCanary(orgId),
    onSuccess: (res) => {
      if (res.sent) {
        toast.success('Test email sent — check your canary inbox')
      } else {
        toast.warning('No SMTP configured — email logged to server console instead')
      }
    },
    onError: () => toast.error('Failed to send test email'),
  })

  const [canaryEmail, setCanaryEmail] = useState('')
  const [editingEmail, setEditingEmail] = useState(false)

  if (isLoading || !data) return null

  const cfg = data

  function toggle(key: 'cred_probe_enabled' | 'web_active_probe_enabled') {
    mutation.mutate({ [key]: !cfg[key] })
  }

  function saveEmail() {
    mutation.mutate({ canary_email: canaryEmail || null })
    setEditingEmail(false)
  }

  return (
    <Section title="Pentest Modules">
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>

        <ToggleRow
          label="Active Web Probes"
          description="Enable SQLi, XSS, SSTI, LFI, SSRF injection probes on web pentest scans. Sends payloads to the target."
          checked={cfg.web_active_probe_enabled}
          onChange={() => toggle('web_active_probe_enabled')}
          disabled={mutation.isPending}
        />

        <div style={{ height: '1px', background: 'rgba(255,255,255,0.05)' }} />

        <ToggleRow
          label="Credential Testing"
          description="Test SMTP, IMAP and webmail login endpoints with factory-default credentials. Rate-limited, stops on first success."
          checked={cfg.cred_probe_enabled}
          onChange={() => toggle('cred_probe_enabled')}
          disabled={mutation.isPending}
        />

        <div style={{ height: '1px', background: 'rgba(255,255,255,0.05)' }} />

        {/* Canary email */}
        <div>
          <div style={{ fontSize: '13px', color: '#c8ccd4', fontWeight: 500, marginBottom: '4px' }}>Canary Email</div>
          <div style={{ fontSize: '11px', color: '#52525B', marginBottom: '10px', lineHeight: 1.5 }}>
            Receives test emails from Canary Probes (open relay, SPF spoofing, DMARC bypass confirmations).
          </div>
          {editingEmail ? (
            <div style={{ display: 'flex', gap: '6px' }}>
              <input
                className="input"
                style={{ flex: 1, fontSize: '12px' }}
                type="email"
                value={canaryEmail}
                onChange={(e) => setCanaryEmail(e.target.value)}
                placeholder="analyst@example.com"
                autoFocus
                onKeyDown={(e) => { if (e.key === 'Enter') saveEmail(); if (e.key === 'Escape') setEditingEmail(false) }}
              />
              <button onClick={saveEmail} className="btn-primary" style={{ fontSize: '11px', padding: '6px 12px' }}>Save</button>
              <button onClick={() => setEditingEmail(false)} className="btn-secondary" style={{ fontSize: '11px', padding: '6px 10px' }}>✕</button>
            </div>
          ) : (
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span style={{
                fontSize: '12px',
                fontFamily: '"JetBrains Mono", monospace',
                color: cfg.canary_email ? '#c8ccd4' : '#3a3a44',
                padding: '4px 10px',
                background: 'rgba(255,255,255,0.03)',
                border: '1px solid rgba(255,255,255,0.06)',
                borderRadius: '6px',
                flex: 1,
              }}>
                {cfg.canary_email ?? 'not configured'}
              </span>
              <button
                onClick={() => { setCanaryEmail(cfg.canary_email ?? ''); setEditingEmail(true) }}
                className="btn-secondary"
                style={{ fontSize: '11px', padding: '5px 12px', flexShrink: 0 }}
              >
                {cfg.canary_email ? 'Edit' : 'Set'}
              </button>
              {cfg.canary_email && (
                <>
                  <button
                    onClick={() => testMutation.mutate()}
                    disabled={testMutation.isPending}
                    className="btn-secondary"
                    style={{ fontSize: '11px', padding: '5px 12px', flexShrink: 0, opacity: testMutation.isPending ? 0.5 : 1 }}
                  >
                    {testMutation.isPending ? 'Sending…' : 'Test'}
                  </button>
                  <button
                    onClick={() => mutation.mutate({ canary_email: null })}
                    className="btn-secondary"
                    style={{ fontSize: '11px', padding: '5px 10px', flexShrink: 0, color: '#EF4444' }}
                  >
                    ✕
                  </button>
                </>
              )}
            </div>
          )}
        </div>

      </div>
    </Section>
  )
}

// ── Integrations / Scan Settings ──────────────────────────────────────────────

function SecretInput({
  value,
  onChange,
  placeholder,
  isSet,
}: {
  value: string
  onChange: (v: string) => void
  placeholder?: string
  isSet: boolean
}) {
  const [show, setShow] = useState(false)
  return (
    <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
      <input
        type={show ? 'text' : 'password'}
        className="input"
        style={{ flex: 1, fontSize: '12px', fontFamily: '"JetBrains Mono", monospace', paddingRight: '36px' }}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={isSet && !value ? '••••••••• (configured)' : (placeholder ?? '')}
        autoComplete="off"
      />
      <button
        type="button"
        onClick={() => setShow((s) => !s)}
        style={{
          position: 'absolute', right: '8px', background: 'transparent',
          border: 'none', cursor: 'pointer', color: '#52525B', padding: '2px',
        }}
        tabIndex={-1}
      >
        {show ? <EyeOff size={13} /> : <Eye size={13} />}
      </button>
    </div>
  )
}

function IntegrationsCard() {
  const { currentOrg } = useAuth()
  const orgId = currentOrg?.id ?? ''
  const qc = useQueryClient()

  const { data, isLoading } = useQuery({
    queryKey: ['org-settings', orgId],
    queryFn: () => orgsApi.getSettings(orgId),
    enabled: !!orgId,
  })

  const mutation = useMutation({
    mutationFn: (body: Parameters<typeof orgsApi.updateSettings>[1]) =>
      orgsApi.updateSettings(orgId, body),
    onSuccess: (updated) => {
      qc.setQueryData(['org-settings', orgId], updated)
      toast.success('Integration settings saved')
    },
    onError: () => toast.error('Failed to save integration settings'),
  })

  const [ghToken, setGhToken] = useState('')
  const [intelxKey, setIntelxKey] = useState('')
  const [nvdKey, setNvdKey] = useState('')
  const [canaryEmail, setCanaryEmail] = useState('')
  const [credProbe, setCredProbe] = useState<boolean | null>(null)
  const [scanTimeout, setScanTimeout] = useState('')

  // Sync state from server on first load
  React.useEffect(() => {
    if (data) {
      setCanaryEmail(data.canary_email ?? '')
      setCredProbe(data.cred_probe_enabled ?? null)
      setScanTimeout(data.scan_timeout_seconds != null ? String(data.scan_timeout_seconds) : '')
    }
  }, [data])

  if (isLoading || !data) return null

  function handleSave(e: React.FormEvent) {
    e.preventDefault()
    const body: Parameters<typeof orgsApi.updateSettings>[1] = {}
    if (ghToken) body.github_token = ghToken
    if (intelxKey) body.intelx_api_key = intelxKey
    if (nvdKey) body.nvd_api_key = nvdKey
    if (canaryEmail !== (data?.canary_email ?? '')) body.canary_email = canaryEmail
    if (credProbe !== null && credProbe !== data?.cred_probe_enabled) body.cred_probe_enabled = credProbe
    const timeoutNum = parseInt(scanTimeout, 10)
    if (!isNaN(timeoutNum) && timeoutNum !== data?.scan_timeout_seconds) body.scan_timeout_seconds = timeoutNum
    mutation.mutate(body)
  }

  const labelStyle = { fontSize: '11px', color: '#52525B', letterSpacing: '1px', marginBottom: '6px' }
  const descStyle = { fontSize: '11px', color: '#3a3a44', marginBottom: '8px', lineHeight: 1.5 }

  return (
    <Section title="Integrations">
      <form onSubmit={handleSave} style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>

        {/* GitHub Token */}
        <div>
          <div style={labelStyle}>GITHUB TOKEN</div>
          <div style={descStyle}>Used for GitHub code search to detect exposed credentials in public repos.</div>
          <SecretInput
            value={ghToken}
            onChange={setGhToken}
            placeholder="ghp_..."
            isSet={data.github_token_set}
          />
          {data.github_token_set && !ghToken && (
            <div style={{ fontSize: '11px', color: '#3fb950', marginTop: '4px' }}>Configured — enter new value to replace</div>
          )}
        </div>

        <div style={{ height: '1px', background: 'rgba(255,255,255,0.05)' }} />

        {/* IntelX API Key */}
        <div>
          <div style={labelStyle}>INTELLIGENCEX API KEY</div>
          <div style={descStyle}>Searches leaked databases, pastes, and dark web content via IntelX.</div>
          <SecretInput
            value={intelxKey}
            onChange={setIntelxKey}
            placeholder="ix_..."
            isSet={data.intelx_api_key_set}
          />
          {data.intelx_api_key_set && !intelxKey && (
            <div style={{ fontSize: '11px', color: '#3fb950', marginTop: '4px' }}>Configured — enter new value to replace</div>
          )}
        </div>

        <div style={{ height: '1px', background: 'rgba(255,255,255,0.05)' }} />

        {/* NVD API Key */}
        <div>
          <div style={labelStyle}>NVD API KEY</div>
          <div style={descStyle}>Higher rate limits for NVD CVE lookups during vulnerability intelligence scans.</div>
          <SecretInput
            value={nvdKey}
            onChange={setNvdKey}
            placeholder="nvd-api-key-..."
            isSet={data.nvd_api_key_set}
          />
          {data.nvd_api_key_set && !nvdKey && (
            <div style={{ fontSize: '11px', color: '#3fb950', marginTop: '4px' }}>Configured — enter new value to replace</div>
          )}
        </div>

        <div style={{ height: '1px', background: 'rgba(255,255,255,0.05)' }} />

        {/* Canary Email */}
        <div>
          <div style={labelStyle}>CANARY EMAIL</div>
          <div style={descStyle}>Receives test emails from canary probes (open relay, SPF spoofing). Overrides global setting.</div>
          <input
            type="email"
            className="input"
            style={{ width: '100%', fontSize: '12px' }}
            value={canaryEmail}
            onChange={(e) => setCanaryEmail(e.target.value)}
            placeholder="analyst@example.com"
          />
        </div>

        <div style={{ height: '1px', background: 'rgba(255,255,255,0.05)' }} />

        {/* Credential Probing */}
        <ToggleRow
          label="Credential Probing"
          description="Enable SMTP/IMAP/webmail credential probes for this org. Overrides global default."
          checked={credProbe ?? false}
          onChange={(v) => setCredProbe(v)}
          disabled={mutation.isPending}
        />

        <div style={{ height: '1px', background: 'rgba(255,255,255,0.05)' }} />

        {/* Scan Timeout */}
        <div>
          <div style={labelStyle}>SCAN TIMEOUT (seconds)</div>
          <div style={descStyle}>Max duration per scan. 30–600 seconds. Leave blank to use global default ({data.scan_timeout_seconds == null ? 'inherited' : `${data.scan_timeout_seconds}s`}).</div>
          <input
            type="number"
            className="input"
            style={{ width: '120px', fontSize: '12px' }}
            value={scanTimeout}
            onChange={(e) => setScanTimeout(e.target.value)}
            placeholder="120"
            min={30}
            max={600}
          />
        </div>

        <div className="pt-2">
          <button
            type="submit"
            className="btn-primary"
            disabled={mutation.isPending}
            style={{ padding: '7px 20px', fontSize: '12px' }}
          >
            {mutation.isPending ? 'Saving…' : 'Save integration settings'}
          </button>
        </div>
      </form>
    </Section>
  )
}

function Section({
  title,
  badge,
  children,
}: {
  title: string
  badge?: React.ReactNode
  children: React.ReactNode
}) {
  return (
    <div className="card p-6">
      <div className="flex items-center justify-between gap-3 mb-5">
        <h2 className="text-sm font-medium text-text-primary" style={{ letterSpacing: 0 }}>{title}</h2>
        {badge}
      </div>
      {children}
    </div>
  )
}

function Field({ label, value, mono = false, truncate = false }: {
  label: string; value: string; mono?: boolean; truncate?: boolean
}) {
  return (
    <div>
      <div className="label mb-1">{label}</div>
      <div
        className={`text-sm ${mono ? 'mono' : ''} ${truncate ? 'truncate' : ''}`}
        style={{ color: '#c8ccd4' }}
        title={truncate ? value : undefined}
      >
        {value}
      </div>
    </div>
  )
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-4">
      <span className="text-sm text-text-secondary">{label}</span>
      <span className="text-sm text-text-muted">{value}</span>
    </div>
  )
}
