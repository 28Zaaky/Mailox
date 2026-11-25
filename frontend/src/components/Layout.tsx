import React, { useEffect, useRef, useState } from 'react'
import { ChevronDown, LogOut, Menu, Search, Settings, User } from 'lucide-react'
import { Link } from 'react-router-dom'
import { Sidebar } from './Sidebar'
import { CommandPalette } from './CommandPalette'
import { NotificationBell } from './NotificationBell'
import { ScanProgressBar } from './ScanProgressBar'
import { useAuth } from '../lib/auth'
import { prefs } from '../lib/preferences'

interface LayoutProps {
  children: React.ReactNode
}

export function Layout({ children }: LayoutProps) {
  const { user, logout, localMode } = useAuth()
  const [collapsed, setCollapsed] = useState(() => prefs.getSidebarCollapsed())
  const [mobileOpen, setMobileOpen] = useState(false)
  const [mobileClosing, setMobileClosing] = useState(false)
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [userMenuOpen, setUserMenuOpen] = useState(false)
  const [userMenuVisible, setUserMenuVisible] = useState(false)
  const [userMenuClosing, setUserMenuClosing] = useState(false)
  const userMenuRef = useRef<HTMLDivElement>(null)

  function toggleSidebar() {
    setCollapsed((c) => {
      const next = !c
      prefs.setSidebarCollapsed(next)
      return next
    })
  }

  // User menu mount with exit animation
  useEffect(() => {
    if (userMenuOpen) {
      setUserMenuVisible(true)
      setUserMenuClosing(false)
    } else if (userMenuVisible) {
      setUserMenuClosing(true)
      const t = setTimeout(() => {
        setUserMenuVisible(false)
        setUserMenuClosing(false)
      }, 150)
      return () => clearTimeout(t)
    }
  }, [userMenuOpen, userMenuVisible])

  // Mobile overlay exit animation
  function closeMobile() {
    setMobileClosing(true)
    setTimeout(() => {
      setMobileOpen(false)
      setMobileClosing(false)
    }, 150)
  }

  // Close mobile sidebar on route change
  useEffect(() => {
    setMobileOpen(false)
  }, [])

  // Ctrl+K / Cmd+K → command palette
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault()
        setPaletteOpen((o) => !o)
      }
      // Escape closes mobile sidebar
      if (e.key === 'Escape') closeMobile()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  // Close user menu on outside click
  useEffect(() => {
    function onClickOutside(e: MouseEvent) {
      if (userMenuRef.current && !userMenuRef.current.contains(e.target as Node)) {
        setUserMenuOpen(false)
      }
    }
    document.addEventListener('mousedown', onClickOutside)
    return () => document.removeEventListener('mousedown', onClickOutside)
  }, [])

  // Lock body scroll when mobile sidebar open
  useEffect(() => {
    if (mobileOpen) {
      document.body.style.overflow = 'hidden'
    } else {
      document.body.style.overflow = ''
    }
    return () => { document.body.style.overflow = '' }
  }, [mobileOpen])

  const initials = (() => {
    const name = user?.full_name ?? user?.email ?? ''
    const parts = name.trim().split(/\s+/)
    if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase()
    return name.slice(0, 2).toUpperCase()
  })()

  const avatarKey = user?.id ? `mailox_avatar_${user.id}` : null

  const [avatarUrl, setAvatarUrl] = useState<string | null>(() => {
    try { return avatarKey ? localStorage.getItem(avatarKey) : null } catch { return null }
  })

  useEffect(() => {
    function onStorage(e: StorageEvent) {
      if (avatarKey && e.key === avatarKey) setAvatarUrl(e.newValue)
    }
    window.addEventListener('storage', onStorage)
    return () => window.removeEventListener('storage', onStorage)
  }, [avatarKey])

  return (
    <div className="flex bg-bg-base" style={{ height: '100dvh', overflow: 'hidden' }}>
      {/* Mobile overlay backdrop */}
      {(mobileOpen || mobileClosing) && (
        <div
          onClick={closeMobile}
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.6)',
            backdropFilter: 'blur(2px)',
            zIndex: 30,
            animation: mobileClosing
              ? 'fade 150ms ease reverse both'
              : 'fade 150ms ease both',
          }}
        />
      )}

      {/* Sidebar — desktop: in flow, mobile: fixed overlay */}
      <div
        className="sidebar-container"
        style={{
          position: 'relative',
          zIndex: 40,
          flexShrink: 0,
          height: '100%',
        }}
      >
        <Sidebar
          collapsed={collapsed}
          onToggle={toggleSidebar}
          mobileOpen={mobileOpen}
          onMobileClose={closeMobile}
        />
        {/* Neon right border — full height, crosses topbar */}
        <div style={{
          position: 'absolute',
          top: 0,
          right: 0,
          bottom: 0,
          width: '1px',
          background: 'rgba(var(--color-accent-rgb, 229,57,53), 0.28)',
          boxShadow: '1px 0 10px rgba(var(--color-accent-rgb, 229,57,53), 0.3), 2px 0 24px rgba(var(--color-accent-rgb, 229,57,53), 0.1)',
          pointerEvents: 'none',
          zIndex: 1,
        }} />
      </div>

      <div className="flex-1 flex flex-col min-w-0" style={{ height: '100%', overflow: 'hidden' }}>
        {/* Topbar */}
        <header
          className="topbar-neon shrink-0 border-b border-border flex items-center justify-between gap-3"
          style={{
            height: '56px',
            paddingLeft: '16px',
            paddingRight: '16px',
            background: 'rgba(10,10,10,0.96)',
            backdropFilter: 'blur(20px)',
            position: 'sticky',
            top: 0,
            zIndex: 20,
          }}
        >
          {/* Left: hamburger (mobile only) + search */}
          <div className="flex items-center gap-2 min-w-0">
            {/* Hamburger — mobile only */}
            <button
              onClick={() => setMobileOpen(true)}
              className="topbar-hamburger"
              title="Open menu"
              style={{
                background: 'transparent',
                border: 'none',
                cursor: 'pointer',
                padding: '6px',
                color: '#666672',
                borderRadius: '5px',
                display: 'none', // shown via CSS media query
                flexShrink: 0,
                transition: 'color 150ms var(--ease-out)',
              }}
            >
              <Menu size={18} />
            </button>

            {/* Search trigger */}
            <button
              onClick={() => setPaletteOpen(true)}
              className="flex items-center gap-2 text-text-muted topbar-search"
              style={{
                border: '1px solid #1f1f1f',
                padding: '5px 12px',
                background: 'rgba(26,26,26,0.5)',
                cursor: 'pointer',
                borderRadius: '5px',
                transition: 'border-color 150ms var(--ease-out), color 150ms var(--ease-out)',
                minWidth: 0,
              }}
              onMouseEnter={(e) => {
                const el = e.currentTarget as HTMLElement
                el.style.borderColor = '#3a3a44'
                el.style.color = '#c8ccd4'
              }}
              onMouseLeave={(e) => {
                const el = e.currentTarget as HTMLElement
                el.style.borderColor = '#1f1f1f'
                el.style.color = ''
              }}
            >
              <Search size={13} style={{ flexShrink: 0 }} />
              <span className="text-sm topbar-search-label" style={{ whiteSpace: 'nowrap' }}>
                Search…
              </span>
              <span
                className="label topbar-search-kbd"
                style={{ fontSize: '10px', border: '1px solid #1f1f1f', padding: '1px 5px', flexShrink: 0 }}
              >
                ⌘K
              </span>
            </button>
          </div>

          {/* Right: notifications + user */}
          <div className="flex items-center gap-2" style={{ flexShrink: 0 }}>
            <NotificationBell />

            {/* User avatar + dropdown */}
            <div className="relative" ref={userMenuRef}>
              <button
                onClick={() => setUserMenuOpen((o) => !o)}
                className="flex items-center gap-2"
                style={{
                  background: 'transparent',
                  border: 'none',
                  cursor: 'pointer',
                  padding: '4px 8px',
                  transition: 'background-color 150ms var(--ease-out)',
                  borderRadius: '6px',
                }}
                onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.backgroundColor = 'rgba(26,26,26,0.8)' }}
                onMouseLeave={(e) => { if (!userMenuOpen) (e.currentTarget as HTMLElement).style.backgroundColor = '' }}
              >
                <div
                  className="flex items-center justify-center text-xs font-medium overflow-hidden"
                  style={{
                    width: '28px',
                    height: '28px',
                    background: avatarUrl ? 'transparent' : 'rgba(var(--color-accent-rgb, 229,57,53), 0.15)',
                    border: '1px solid rgba(var(--color-accent-rgb, 229,57,53), 0.3)',
                    color: 'var(--color-accent)',
                    letterSpacing: 0,
                    flexShrink: 0,
                    borderRadius: '7px',
                  }}
                >
                  {avatarUrl
                    ? <img src={avatarUrl} alt="" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
                    : initials}
                </div>
                <span className="text-sm text-text-secondary topbar-username max-w-[120px] truncate">
                  {user?.full_name ?? user?.email?.split('@')[0] ?? '—'}
                </span>
                <ChevronDown
                  size={12}
                  style={{
                    color: '#3a3a44',
                    transform: userMenuOpen ? 'rotate(180deg)' : 'rotate(0)',
                    transition: 'transform 200ms var(--ease-out)',
                  }}
                />
              </button>

              {userMenuVisible && (
                <div
                  className="absolute right-0 mt-1 border border-border overflow-hidden"
                  style={{
                    background: '#121212',
                    minWidth: '200px',
                    top: '100%',
                    zIndex: 50,
                    animation: userMenuClosing
                      ? 'cardLeave 150ms var(--ease-out) both'
                      : 'cardEnter 150ms var(--ease-out) both',
                    transformOrigin: 'top right',
                    borderRadius: '8px',
                  }}
                >
                  <div className="px-4 py-3 border-b border-border">
                    <div className="text-sm text-text-primary">{user?.full_name ?? '—'}</div>
                    <div className="text-xs text-text-muted mt-0.5">{user?.email}</div>
                  </div>

                  {[
                    { label: 'My Account', icon: User, to: '/account' },
                    { label: 'Preferences', icon: Settings, to: '/preferences' },
                  ].map((item) => {
                    const Icon = item.icon
                    return (
                      <Link
                        key={item.to}
                        to={item.to}
                        onClick={() => setUserMenuOpen(false)}
                        className="flex items-center gap-3 px-4 py-2.5 text-sm text-text-muted"
                        style={{ transition: 'background-color 150ms var(--ease-out), color 150ms var(--ease-out)' }}
                        onMouseEnter={(e) => {
                          const el = e.currentTarget as HTMLElement
                          el.style.backgroundColor = 'rgba(26,26,26,0.8)'
                          el.style.color = '#c8ccd4'
                        }}
                        onMouseLeave={(e) => {
                          const el = e.currentTarget as HTMLElement
                          el.style.backgroundColor = ''
                          el.style.color = ''
                        }}
                      >
                        <Icon size={14} />
                        {item.label}
                      </Link>
                    )
                  })}

                  {!localMode && <div className="border-t border-border" />}

                  {!localMode && (
                  <button
                    onClick={() => {
                      setUserMenuOpen(false)
                      // Local session is cleared even if the API call fails; nothing else to do.
                      logout().catch(() => {})
                    }}
                    className="w-full flex items-center gap-3 px-4 py-2.5 text-sm text-text-muted"
                    style={{
                      background: 'transparent',
                      border: 'none',
                      cursor: 'pointer',
                      transition: 'background-color 150ms var(--ease-out), color 150ms var(--ease-out)',
                      textAlign: 'left',
                    }}
                    onMouseEnter={(e) => {
                      const el = e.currentTarget as HTMLElement
                      el.style.backgroundColor = 'rgba(var(--color-accent-rgb, 229,57,53), 0.08)'
                      el.style.color = 'var(--color-accent)'
                    }}
                    onMouseLeave={(e) => {
                      const el = e.currentTarget as HTMLElement
                      el.style.backgroundColor = ''
                      el.style.color = ''
                    }}
                  >
                    <LogOut size={14} />
                    Sign out
                  </button>
                  )}
                </div>
              )}
            </div>
          </div>
        </header>

        {/* Floating scan progress popup */}
        <ScanProgressBar />

        {/* Page content */}
        <main className="flex-1 overflow-y-auto" style={{ display: 'flex', flexDirection: 'column' }}>
          <div className="layout-content" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
            {children}
          </div>
        </main>
      </div>

      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
    </div>
  )
}

// ── Page header ───────────────────────────────────────────────────────────────

interface PageHeaderProps {
  title: string
  subtitle?: string
  /** Longer explanatory line rendered under the subtitle */
  description?: string
  action?: React.ReactNode
}

export function PageHeader({ title, subtitle, description, action }: PageHeaderProps) {
  return (
    <div className="flex items-start justify-between gap-4 mb-8 flex-wrap">
      <div>
        <h1 className="text-xl text-text-primary" style={{ letterSpacing: '-0.01em', fontWeight: 600 }}>
          {title}
        </h1>
        {subtitle && (
          <p className="text-sm mt-1" style={{ color: '#666672' }}>
            {subtitle}
          </p>
        )}
        {description && (
          <p className="text-xs mt-1" style={{ color: '#3a3a44' }}>
            {description}
          </p>
        )}
      </div>
      {action && <div className="shrink-0">{action}</div>}
    </div>
  )
}
