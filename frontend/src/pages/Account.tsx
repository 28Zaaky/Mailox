import React, { useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { Camera, Check, Mail, Pencil, Shield, ShieldCheck, X } from 'lucide-react'
import { PageHeader } from '../components/Layout'
import { useAuth } from '../lib/auth'
import { auth as authApi } from '../lib/api'
import { toast } from 'sonner'
import type { User } from '../types'

function readStorage(key: string): string | null {
  try { return localStorage.getItem(key) } catch { return null }
}
function writeStorage(key: string, val: string) {
  try { localStorage.setItem(key, val) } catch { /* quota */ }
}

export default function Account() {
  const { user } = useAuth()
  if (!user) return null
  return <AccountInner user={user} />
}

function AccountInner({ user }: { user: User }) {
  const { currentOrg, refreshUser } = useAuth()
  const fileRef = useRef<HTMLInputElement>(null)

  const avatarKey = `mailox_avatar_${user.id}`
  const [avatarUrl, setAvatarUrl] = useState<string | null>(() => readStorage(avatarKey))
  // Server value is the source of truth (refreshed via refreshUser after updateMe)
  const displayName = user.full_name ?? ''
  const [editingName, setEditingName] = useState(false)
  const [nameInput, setNameInput] = useState(displayName)

  const initials = (() => {
    const name = displayName || user.email
    const parts = name.trim().split(/\s+/)
    if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase()
    return name.slice(0, 2).toUpperCase()
  })()

  function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    if (file.size > 2 * 1024 * 1024) { toast.error('Image must be under 2 MB'); return }
    const reader = new FileReader()
    reader.onload = (ev) => {
      const result = ev.target?.result as string
      setAvatarUrl(result)
      writeStorage(avatarKey, result)
      window.dispatchEvent(new StorageEvent('storage', { key: avatarKey, newValue: result }))
      toast.success('Profile photo updated')
    }
    reader.readAsDataURL(file)
    e.target.value = ''
  }

  async function saveName() {
    const trimmed = nameInput.trim()
    setEditingName(false)
    try {
      await authApi.updateMe(trimmed || null)
      await refreshUser()
      toast.success('Display name saved')
    } catch {
      toast.error('Failed to save display name')
      setEditingName(true)
    }
  }

  function removePhoto() {
    setAvatarUrl(null)
    try { localStorage.removeItem(avatarKey) } catch { /* noop */ }
    window.dispatchEvent(new StorageEvent('storage', { key: avatarKey, newValue: null }))
    toast.success('Profile photo removed')
  }

  return (
    <div>
      <PageHeader title="My Account" />

      <div className="settings-grid">
        {/* ── Left: identity ── */}
        <div className="flex flex-col gap-5">
          {/* Avatar + name */}
          <div className="card p-6">
            <div className="label mb-5">Profile</div>

            <div className="flex items-start gap-5 mb-6">
              {/* Avatar */}
              <div style={{ position: 'relative', flexShrink: 0 }}>
                <div
                  style={{
                    width: '80px',
                    height: '80px',
                    borderRadius: '14px',
                    overflow: 'hidden',
                    border: '2px solid #2a2a2a',
                    background: avatarUrl ? 'transparent' : 'rgba(232,23,58,0.1)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    position: 'relative',
                  }}
                >
                  {avatarUrl ? (
                    <img src={avatarUrl} alt="Profile" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
                  ) : (
                    <span style={{ fontSize: '22px', color: '#E8173A', fontWeight: 600 }}>{initials}</span>
                  )}
                  {/* Camera overlay */}
                  <button
                    onClick={() => fileRef.current?.click()}
                    className="avatar-cam-overlay"
                    style={{
                      position: 'absolute',
                      inset: 0,
                      background: 'rgba(0,0,0,0.6)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      border: 'none',
                      cursor: 'pointer',
                      opacity: 0,
                      transition: 'opacity 150ms var(--ease-out)',
                    }}
                  >
                    <Camera size={18} style={{ color: '#fff' }} />
                  </button>
                </div>

                <input ref={fileRef} type="file" accept="image/*" onChange={handleFileChange} style={{ display: 'none' }} />
              </div>

              <div style={{ flex: 1, minWidth: 0 }}>
                {/* Display name */}
                {editingName ? (
                  <div className="flex items-center gap-2 mb-2">
                    <input
                      type="text"
                      className="input"
                      style={{ padding: '6px 10px', fontSize: '14px' }}
                      value={nameInput}
                      onChange={(e) => setNameInput(e.target.value)}
                      onKeyDown={(e) => { if (e.key === 'Enter') saveName(); if (e.key === 'Escape') setEditingName(false) }}
                      autoFocus
                    />
                    <button onClick={saveName} className="btn-ghost" style={{ padding: '6px 8px' }}>
                      <Check size={14} style={{ color: '#3fb950' }} />
                    </button>
                    <button onClick={() => setEditingName(false)} className="btn-ghost" style={{ padding: '6px 8px' }}>
                      <X size={13} />
                    </button>
                  </div>
                ) : (
                  <div className="flex items-center gap-2 mb-1">
                    <span style={{ fontSize: '15px', fontWeight: 600, color: '#e8ecf2' }}>
                      {displayName || <span style={{ color: '#3a3a44', fontStyle: 'italic', fontWeight: 400 }}>No display name</span>}
                    </span>
                    <button
                      onClick={() => { setNameInput(displayName); setEditingName(true) }}
                      style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: '#3a3a44', padding: '2px' }}
                      onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.color = '#c8ccd4' }}
                      onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.color = '#3a3a44' }}
                    >
                      <Pencil size={12} />
                    </button>
                  </div>
                )}
                <div className="flex items-center gap-2 text-sm text-text-muted mb-3">
                  <Mail size={12} style={{ flexShrink: 0 }} />
                  {user.email}
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span style={{
                    fontSize: '11px',
                    color: user.is_active ? '#3fb950' : '#E8173A',
                    border: `1px solid ${user.is_active ? 'rgba(63,185,80,0.3)' : 'rgba(232,23,58,0.3)'}`,
                    padding: '2px 10px',
                    borderRadius: '4px',
                  }}>
                    {user.is_active ? 'Active' : 'Inactive'}
                  </span>
                  {currentOrg && (
                    <span style={{ fontSize: '11px', color: '#3a3a44', border: '1px solid #1f1f1f', padding: '2px 10px', borderRadius: '4px' }}>
                      {currentOrg.name}
                    </span>
                  )}
                  {user.is_platform_admin && (
                    <span style={{ fontSize: '11px', color: '#CA8A04', border: '1px solid rgba(202,138,4,0.3)', padding: '2px 10px', borderRadius: '4px' }}>
                      Admin
                    </span>
                  )}
                </div>
              </div>
            </div>

            {/* Photo actions */}
            <div className="flex items-center gap-2 pt-4 border-t border-border">
              <button
                className="btn-secondary"
                style={{ padding: '7px 16px', fontSize: '13px' }}
                onClick={() => fileRef.current?.click()}
              >
                <Camera size={13} />
                {avatarUrl ? 'Change photo' : 'Upload photo'}
              </button>
              {avatarUrl && (
                <button
                  className="btn-ghost"
                  style={{ padding: '7px 12px', fontSize: '13px' }}
                  onClick={removePhoto}
                >
                  Remove
                </button>
              )}
            </div>
            <p className="text-xs text-text-muted mt-2">JPG, PNG or GIF · max 2 MB · stored locally in your browser</p>
          </div>

          {/* Account details */}
          <div className="card p-6">
            <div className="label mb-4">Account info</div>
            <div className="space-y-3">
              <InfoRow label="Email" value={user.email} mono />
              <InfoRow label="User ID" value={user.id} mono truncate />
              <InfoRow label="Role" value={user.is_platform_admin ? 'Platform admin' : 'Member'} />
            </div>
            <p className="text-xs text-text-muted mt-4 pt-4 border-t border-border" style={{ lineHeight: 1.6 }}>
              Email and password changes are managed by your platform administrator.
            </p>
          </div>
        </div>

        {/* ── Right: security ── */}
        <div className="flex flex-col gap-5">
          {/* MFA */}
          <div className="card p-6">
            <div className="flex items-center justify-between gap-3 mb-5">
              <div className="label">Two-Factor Authentication</div>
              <span style={{
                fontSize: '11px',
                color: user.mfa_enabled ? '#3fb950' : '#666672',
                border: `1px solid ${user.mfa_enabled ? 'rgba(63,185,80,0.3)' : '#1f1f1f'}`,
                padding: '2px 10px',
                borderRadius: '4px',
              }}>
                {user.mfa_enabled ? 'Enabled' : 'Disabled'}
              </span>
            </div>

            {user.mfa_enabled ? (
              <div className="flex items-center gap-2 text-sm mb-4" style={{ color: '#3fb950' }}>
                <ShieldCheck size={14} />
                MFA active — TOTP authenticator
              </div>
            ) : (
              <div className="flex items-center gap-2 text-sm mb-4 text-text-muted">
                <Shield size={14} style={{ color: '#3a3a44' }} />
                Not configured — your account is less secure
              </div>
            )}

            <Link
              to="/settings"
              className="btn-secondary"
              style={{ display: 'inline-flex', padding: '8px 16px', fontSize: '13px' }}
            >
              {user.mfa_enabled ? 'Manage in Settings' : 'Enable MFA in Settings'}
            </Link>
          </div>

          {/* Sessions */}
          <div className="card p-6">
            <div className="label mb-4">Sessions</div>
            <p className="text-sm text-text-muted mb-4" style={{ lineHeight: 1.6 }}>
              Manage active sessions and sign out from other devices.
            </p>
            <Link
              to="/settings"
              className="btn-secondary"
              style={{ display: 'inline-flex', padding: '8px 16px', fontSize: '13px' }}
            >
              View active sessions
            </Link>
          </div>

          {/* Password */}
          <div className="card p-6">
            <div className="label mb-4">Password</div>
            <p className="text-sm text-text-muted mb-4" style={{ lineHeight: 1.6 }}>
              Password changes are managed by your platform administrator.
            </p>
            <div
              className="text-xs px-3 py-2.5"
              style={{
                color: '#3a3a44',
                background: '#111',
                border: '1px solid #1f1f1f',
                borderRadius: '5px',
              }}
            >
              Self-service password reset coming in a future release.
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function InfoRow({ label, value, mono = false, truncate = false }: {
  label: string; value: string; mono?: boolean; truncate?: boolean
}) {
  return (
    <div className="flex items-center justify-between gap-4 py-2 border-b border-border last:border-0">
      <span className="text-sm text-text-secondary shrink-0">{label}</span>
      <span
        className={`text-sm text-right ${mono ? 'mono' : ''} ${truncate ? 'truncate' : ''}`}
        style={{ color: '#c8ccd4', maxWidth: '60%' }}
        title={truncate ? value : undefined}
      >
        {value}
      </span>
    </div>
  )
}
