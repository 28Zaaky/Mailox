import React from 'react'
import {
  Activity,
  AlertTriangle,
  BarChart2,
  Camera,
  ChevronLeft,
  Database,
  FileText,

  Globe,
  Key,

  Mail,
  Search,
  Server,
  Settings,
  Shield,
  Swords,
  Target,
  Users,
  X,
  Zap,
} from 'lucide-react'
import { NavLink } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { edition as editionApi } from '../lib/api'
import clsx from 'clsx'
import { useAuth } from '../lib/auth'

const NAV_SECTIONS_TOP = [
  {
    label: 'Main',
    items: [
      { label: 'Overview', to: '/', icon: BarChart2 },
      { label: 'Assessments', to: '/assessments', icon: Activity },
      { label: 'Findings', to: '/findings', icon: AlertTriangle },
      { label: 'Assets', to: '/assets', icon: Server },
      { label: 'Reports', to: '/reports', icon: FileText },
    ],
  },
  {
    label: 'Security Ops',
    items: [
      { label: 'SMTP Discovery', to: '/smtp-discovery', icon: Search },
      { label: 'SMTP Security', to: '/smtp-security', icon: Shield },
      { label: 'DNS & Auth', to: '/dns-auth', icon: Globe },
      { label: 'Webmail & TLS', to: '/webmail', icon: Mail },
      { label: 'Vuln Intel', to: '/vuln-intel', icon: Zap },
      { label: 'CVE Intel', to: '/intel', icon: Database },
      { label: 'Credentials', to: '/secrets', icon: Key },
    ],
  },
  {
    label: 'Pentest',
    items: [
      { label: 'Web Pentest', to: '/web-pentest', icon: Target },
      { label: 'Pentest Probes', to: '/pentest', icon: Swords },
    ],
  },
]

const NAV_WORKSPACE = {
  label: 'Workspace',
  items: [
    { label: 'Team', to: '/team', icon: Users },
    { label: 'Settings', to: '/settings', icon: Settings },
  ],
}

// SaaS only: domain ownership proof, and access requests / invitations
const NAV_DOMAINS_ITEM = { label: 'Domains', to: '/domains', icon: Globe }

const NAV_ADMIN_ITEM = { label: 'Access', to: '/admin/access', icon: Key }

// Non-uniform stagger: diminishing gaps, reads as a wave not a metronome
const STAGGER_DELAYS = [0, 25, 45, 62, 76, 88, 98, 107, 115, 122, 128, 134, 139, 143, 147, 151]

interface SidebarProps {
  collapsed: boolean
  onToggle: () => void
  mobileOpen?: boolean
  onMobileClose?: () => void
}

export function Sidebar({ collapsed, onToggle, mobileOpen, onMobileClose }: SidebarProps) {
  const { user, localMode } = useAuth()
  const { data: info } = useQuery({ queryKey: ['edition'], queryFn: editionApi.info, staleTime: Infinity })
  const isSaas = info?.edition === 'saas'
  // Platform admin sees admin panel in SaaS mode
  const showAccess = !!user?.is_platform_admin && isSaas
  const workspaceSection = {
    ...NAV_WORKSPACE,
    items: [
      // Local tool mode: no team to manage
      ...(localMode ? [] : NAV_WORKSPACE.items.slice(0, 1)),  // Team
      ...(isSaas ? [NAV_DOMAINS_ITEM] : []),
      ...NAV_WORKSPACE.items.slice(1),  // Settings
      ...(showAccess ? [NAV_ADMIN_ITEM] : []),
    ],
  }
  const [orgMenuOpen, setOrgMenuOpen] = React.useState(false)
  const orgMenuRef = React.useRef<HTMLDivElement>(null)

  React.useEffect(() => {
    if (!orgMenuOpen) return
    function onClickOutside(e: MouseEvent) {
      if (orgMenuRef.current && !orgMenuRef.current.contains(e.target as Node)) {
        setOrgMenuOpen(false)
      }
    }
    document.addEventListener('mousedown', onClickOutside)
    return () => document.removeEventListener('mousedown', onClickOutside)
  }, [orgMenuOpen])

  return (
    <aside
      className="sidebar flex flex-col bg-bg-secondary overflow-hidden"
      style={{
        width: collapsed ? '56px' : '240px',
        transition: 'width 250ms var(--ease-out), transform 300ms var(--ease-drawer)',
        minWidth: collapsed ? '56px' : '240px',
        height: '100%',
        // Mobile: fixed overlay, slides in
        // Desktop: in-flow, controlled by CSS class
      } as React.CSSProperties}
      data-mobile-open={mobileOpen ? 'true' : 'false'}
    >
      {/* Logo */}
      <div
        className="shrink-0 flex items-center justify-between"
        style={{ height: '56px', padding: collapsed ? '0 16px' : '0 20px' }}
      >
        <div
          className="overflow-hidden"
          style={{
            width: collapsed ? '0' : '180px',
            opacity: collapsed ? 0 : 1,
            transition: 'width 200ms var(--ease-out), opacity 150ms var(--ease-out)',
            whiteSpace: 'nowrap',
          }}
        >
          <div style={{ lineHeight: 1 }}>
            <div style={{
              fontSize: '15px', fontWeight: 700, letterSpacing: '0.1em',
              fontFamily: "'Space Grotesk', sans-serif",
              color: '#EDEDED',
            }}>
              MAIL<span style={{ color: 'var(--color-accent)' }}>Ø</span>X
            </div>
            <div style={{
              fontSize: '9px', letterSpacing: '0.18em', marginTop: '6px',
              color: '#2e2e34',
              fontFamily: "'JetBrains Mono', monospace",
              textTransform: 'uppercase',
            }}>
              by Khaøtic Security
            </div>
          </div>
        </div>

        {/* Close button — mobile only, shown via CSS */}
        <button
          onClick={onMobileClose}
          className="sidebar-close-btn"
          style={{
            display: 'none',
            background: 'transparent',
            border: 'none',
            cursor: 'pointer',
            padding: '6px',
            color: '#666672',
            borderRadius: '5px',
            flexShrink: 0,
          }}
        >
          <X size={16} />
        </button>
      </div>

      {/* Nav — main sections + scrollable */}
      <nav className="flex-1 overflow-y-auto" style={{ padding: collapsed ? '12px 8px' : '12px' }}>
        {NAV_SECTIONS_TOP.map((section) => (
          <NavSection key={section.label} section={section} collapsed={collapsed} />
        ))}
      </nav>

      {/* Workspace — pinned above profile */}
      <div className="border-t border-border shrink-0" style={{ padding: collapsed ? '8px' : '8px 12px' }}>
        <NavSection section={workspaceSection} collapsed={collapsed} />
      </div>

      {/* Bottom: user profile + collapse */}
      <div className="border-t border-border shrink-0">
        <UserProfile collapsed={collapsed} onToggle={onToggle} />
      </div>
    </aside>
  )
}

// ── NavSection ────────────────────────────────────────────────────────────────

type NavItem = { label: string; to: string; icon: React.ComponentType<{ size?: number; style?: React.CSSProperties }> }

function NavSection({ section, collapsed }: { section: { label: string; items: NavItem[] }; collapsed: boolean }) {
  return (
    <div style={{ marginBottom: collapsed ? '4px' : '20px' }}>
      <div
        style={{
          height: collapsed ? '0' : 'auto',
          opacity: collapsed ? 0 : 1,
          overflow: 'hidden',
          transition: 'opacity 150ms var(--ease-out)',
          marginBottom: collapsed ? 0 : '6px',
          marginLeft: '12px',
        }}
      >
        <span className="label" style={{ fontSize: '9.5px', letterSpacing: '2px', color: '#44444e' }}>
          {section.label}
        </span>
      </div>

      {section.items.map((item, i) => {
        const delay = STAGGER_DELAYS[Math.min(i, STAGGER_DELAYS.length - 1)]
        const Icon = item.icon
        return (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === '/'}
            title={collapsed ? item.label : undefined}
            className={({ isActive }) =>
              clsx('nav-enter flex items-center mb-0.5', isActive ? 'text-accent' : 'text-text-muted nav-inactive')
            }
            style={({ isActive }) => ({
              '--nav-delay': `${delay}ms`,
              letterSpacing: 0,
              transition: 'color 150ms var(--ease-out), background-color 150ms var(--ease-out)',
              padding: collapsed ? '8px 0' : '7px 12px',
              justifyContent: collapsed ? 'center' : 'flex-start',
              gap: collapsed ? 0 : '10px',
              borderLeft: isActive ? '2px solid var(--color-accent)' : '2px solid transparent',
              borderRadius: isActive ? '0 5px 5px 0' : '5px',
              background: isActive
                ? 'linear-gradient(90deg, rgba(var(--color-accent-rgb, 229,57,53), 0.14) 0%, rgba(var(--color-accent-rgb, 229,57,53), 0.04) 65%, transparent 100%)'
                : 'transparent',
              boxShadow: 'none',
            } as React.CSSProperties)}
          >
            <Icon size={15} style={{ flexShrink: 0 }} />
            <span
              className="text-sm truncate"
              style={{
                width: collapsed ? '0' : 'auto',
                opacity: collapsed ? 0 : 1,
                overflow: 'hidden',
                transition: 'opacity 150ms var(--ease-out)',
                whiteSpace: 'nowrap',
              }}
            >
              {item.label}
            </span>
          </NavLink>
        )
      })}
    </div>
  )
}

// ── UserProfile ───────────────────────────────────────────────────────────────

function UserProfile({ collapsed, onToggle }: { collapsed: boolean; onToggle: () => void }) {
  const { user } = useAuth()
  const fileRef = React.useRef<HTMLInputElement>(null)

  const avatarKey = user?.id ? `mailox_avatar_${user.id}` : null

  const [avatarUrl, setAvatarUrl] = React.useState<string | null>(() => {
    try { return avatarKey ? localStorage.getItem(avatarKey) : null } catch { return null }
  })

  // Sync when Account page updates storage
  React.useEffect(() => {
    function onStorage(e: StorageEvent) {
      if (avatarKey && e.key === avatarKey) setAvatarUrl(e.newValue)
    }
    window.addEventListener('storage', onStorage)
    return () => window.removeEventListener('storage', onStorage)
  }, [avatarKey])

  function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = (ev) => {
      const result = ev.target?.result as string
      setAvatarUrl(result)
      try { if (avatarKey) localStorage.setItem(avatarKey, result) } catch { /* quota */ }
    }
    reader.readAsDataURL(file)
    e.target.value = ''
  }

  const rawName = user?.full_name || user?.email || ''
  const initials = (() => {
    const parts = rawName.trim().split(/\s+/)
    if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase()
    return rawName.slice(0, 2).toUpperCase()
  })()

  const displayName = user?.full_name || user?.email?.split('@')[0] || '—'
  const displayEmail = user?.email ?? ''

  return (
    <div
      style={{
        padding: collapsed ? '10px 8px' : '10px 12px',
        display: 'flex',
        flexDirection: 'column',
        gap: '8px',
      }}
    >
      {/* Avatar + name row */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: collapsed ? 0 : '10px',
          overflow: 'hidden',
        }}
      >
        {/* Avatar — clickable to upload photo */}
        <div style={{ position: 'relative', flexShrink: 0 }}>
          <button
            onClick={() => fileRef.current?.click()}
            title="Change profile photo"
            style={{
              width: '34px',
              height: '34px',
              borderRadius: '9px',
              overflow: 'hidden',
              border: '1px solid #2a2a2a',
              background: avatarUrl ? 'transparent' : 'rgba(var(--color-accent-rgb, 229,57,53), 0.12)',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              position: 'relative',
              flexShrink: 0,
              transition: 'border-color 150ms var(--ease-out)',
            }}
            onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.borderColor = '#3a3a44' }}
            onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.borderColor = '#2a2a2a' }}
          >
            {avatarUrl ? (
              <img
                src={avatarUrl}
                alt="Profile"
                style={{ width: '100%', height: '100%', objectFit: 'cover' }}
              />
            ) : (
              <span style={{ fontSize: '11px', color: 'var(--color-accent)', fontWeight: 600 }}>{initials}</span>
            )}
            {/* Camera overlay on hover */}
            <span
              className="avatar-cam-overlay"
              style={{
                position: 'absolute',
                inset: 0,
                background: 'rgba(0,0,0,0.55)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                opacity: 0,
                transition: 'opacity 150ms var(--ease-out)',
              }}
            >
              <Camera size={12} style={{ color: '#fff' }} />
            </span>
          </button>
          <input
            ref={fileRef}
            type="file"
            accept="image/*"
            onChange={handleFileChange}
            style={{ display: 'none' }}
          />
        </div>

        {/* Name + email — hidden when collapsed */}
        <div
          style={{
            overflow: 'hidden',
            width: collapsed ? '0' : 'auto',
            opacity: collapsed ? 0 : 1,
            transition: 'width 200ms var(--ease-out), opacity 150ms var(--ease-out)',
            whiteSpace: 'nowrap',
            flex: 1,
            minWidth: 0,
          }}
        >
          <div
            className="truncate"
            style={{ fontSize: '13px', color: '#c8ccd4', fontWeight: 500 }}
          >
            {displayName}
          </div>
          <div
            className="truncate"
            style={{ fontSize: '11px', color: '#3a3a44', marginTop: '1px' }}
          >
            {displayEmail}
          </div>
        </div>

        {/* Collapse toggle — only shown when expanded */}
        {!collapsed && (
          <button
            onClick={onToggle}
            title="Collapse sidebar"
            style={{
              width: '26px',
              height: '26px',
              border: '1px solid #1f1f1f',
              background: 'transparent',
              cursor: 'pointer',
              borderRadius: '5px',
              color: '#3a3a44',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
              transition: 'background-color 150ms var(--ease-out), color 150ms var(--ease-out)',
            }}
            onMouseEnter={(e) => {
              const el = e.currentTarget as HTMLElement
              el.style.backgroundColor = 'rgba(26,26,26,0.8)'
              el.style.color = '#c8ccd4'
            }}
            onMouseLeave={(e) => {
              const el = e.currentTarget as HTMLElement
              el.style.backgroundColor = ''
              el.style.color = '#3a3a44'
            }}
          >
            <ChevronLeft size={13} />
          </button>
        )}
      </div>

      {/* Collapsed: expand button only */}
      {collapsed && (
        <button
          onClick={onToggle}
          title="Expand sidebar"
          style={{
            width: '100%',
            height: '28px',
            border: '1px solid #1f1f1f',
            background: 'transparent',
            cursor: 'pointer',
            borderRadius: '5px',
            color: '#3a3a44',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            transition: 'background-color 150ms var(--ease-out), color 150ms var(--ease-out)',
          }}
          onMouseEnter={(e) => {
            const el = e.currentTarget as HTMLElement
            el.style.backgroundColor = 'rgba(26,26,26,0.8)'
            el.style.color = '#c8ccd4'
          }}
          onMouseLeave={(e) => {
            const el = e.currentTarget as HTMLElement
            el.style.backgroundColor = ''
            el.style.color = '#3a3a44'
          }}
        >
          <ChevronLeft size={13} style={{ transform: 'rotate(180deg)' }} />
        </button>
      )}
    </div>
  )
}
