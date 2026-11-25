import React, { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { useNavigate } from 'react-router-dom'
import {
  Bell,
  CheckCheck,
  Trash2,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Loader2,
  AlertCircle,
  Search,
  X,
} from 'lucide-react'
import { useScanMonitor } from '../lib/scan-monitor'
import { useAuth } from '../lib/auth'
import type { AppNotification, NotifType } from '../lib/scan-monitor'

function relativeTime(ts: number): string {
  const diff = (Date.now() - ts) / 1000
  if (diff < 60) return 'just now'
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

function notifIcon(type: NotifType) {
  switch (type) {
    case 'scan_completed':   return <CheckCircle  size={14} style={{ color: '#4ade80',                             flexShrink: 0 }} />
    case 'scan_partial':     return <AlertCircle  size={14} style={{ color: '#facc15',                             flexShrink: 0 }} />
    case 'scan_failed':      return <XCircle      size={14} style={{ color: 'var(--color-accent)',                 flexShrink: 0 }} />
    case 'scan_cancelled':   return <X            size={14} style={{ color: '#52525b',                             flexShrink: 0 }} />
    case 'scan_started':     return <Loader2      size={14} style={{ color: '#60a5fa',                             flexShrink: 0 }} />
    case 'critical_finding': return <AlertTriangle size={14} style={{ color: 'var(--color-accent)',                flexShrink: 0 }} />
    case 'new_discovery':    return <Search       size={14} style={{ color: '#a78bfa',                             flexShrink: 0 }} />
    default:                 return <Bell         size={14} style={{ color: '#52525b',                             flexShrink: 0 }} />
  }
}

// Group notifications by domain (falling back to scan_id prefix)
function groupByDomain(notifications: AppNotification[]): { domain: string; items: AppNotification[] }[] {
  const map = new Map<string, AppNotification[]>()
  for (const n of notifications) {
    const key = n.domain ?? (n.scan_id ? n.scan_id.slice(0, 8) : '__ungrouped__')
    const existing = map.get(key)
    if (existing) existing.push(n)
    else map.set(key, [n])
  }
  return Array.from(map.entries()).map(([domain, items]) => ({ domain, items }))
}

export function NotificationBell() {
  const { notifications, unreadCount, markAllRead, markRead, clearNotifications } = useScanMonitor()
  const { currentOrg } = useAuth()
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const [closing, setClosing] = useState(false)
  const prevUnread = useRef(unreadCount)
  const [pulse, setPulse] = useState(false)

  // Pulse bell when new notifications arrive
  useEffect(() => {
    if (unreadCount > prevUnread.current) {
      setPulse(true)
      const t = setTimeout(() => setPulse(false), 1200)
      prevUnread.current = unreadCount
      return () => clearTimeout(t)
    }
    prevUnread.current = unreadCount
  }, [unreadCount])

  function openPanel() {
    setClosing(false)
    setOpen(true)
  }

  function closePanel() {
    setClosing(true)
    setTimeout(() => {
      setOpen(false)
      setClosing(false)
    }, 220)
  }

  function handleNotifClick(n: AppNotification) {
    markRead(n.id)
    if (n.scan_id && currentOrg) {
      navigate(`/assessments/${n.scan_id}`)
      closePanel()
    }
  }

  const groups = groupByDomain(notifications)

  return (
    <>
      {/* Bell button */}
      <button
        onClick={() => (open ? closePanel() : openPanel())}
        title="Notifications"
        style={{
          position: 'relative',
          background: 'transparent',
          border: 'none',
          cursor: 'pointer',
          padding: '6px',
          color: unreadCount > 0 ? '#c8ccd4' : '#3a3a44',
          borderRadius: '5px',
          transition: 'color 150ms var(--ease-out)',
          animation: pulse ? 'notifPulse 400ms ease-out' : undefined,
        }}
        onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.color = '#c8ccd4' }}
        onMouseLeave={(e) => {
          if (unreadCount === 0 && !open) (e.currentTarget as HTMLElement).style.color = '#3a3a44'
        }}
      >
        <Bell size={16} />
        {unreadCount > 0 && (
          <span
            style={{
              position: 'absolute',
              top: '2px',
              right: '2px',
              minWidth: '15px',
              height: '15px',
              background: 'var(--color-accent)',
              borderRadius: '99px',
              fontSize: '9px',
              fontWeight: 700,
              color: '#fff',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              padding: '0 3px',
              lineHeight: 1,
              boxShadow: '0 0 6px rgba(var(--color-accent-rgb,229,57,53),0.6)',
            }}
          >
            {unreadCount > 99 ? '99+' : unreadCount}
          </span>
        )}
      </button>

      {/* Keyframes injected once */}
      <style>{`
        @keyframes notifPulse {
          0%   { transform: rotate(0deg) scale(1); }
          20%  { transform: rotate(-12deg) scale(1.15); }
          40%  { transform: rotate(10deg) scale(1.1); }
          60%  { transform: rotate(-6deg) scale(1.05); }
          80%  { transform: rotate(4deg) scale(1.02); }
          100% { transform: rotate(0deg) scale(1); }
        }
        @keyframes slideInRight {
          from { transform: translateX(100%); opacity: 0.6; }
          to   { transform: translateX(0);    opacity: 1; }
        }
        @keyframes slideOutRight {
          from { transform: translateX(0);    opacity: 1; }
          to   { transform: translateX(100%); opacity: 0.6; }
        }
        @keyframes fadeInOverlay {
          from { opacity: 0; }
          to   { opacity: 1; }
        }
        @keyframes fadeOutOverlay {
          from { opacity: 1; }
          to   { opacity: 0; }
        }
      `}</style>

      {/* Overlay + panel, portalled to <body>: the topbar's backdrop-filter makes it the
          containing block of fixed descendants, which squashed the panel into its 56px */}
      {(open || closing) && createPortal(
        <>
          {/* Semi-transparent backdrop */}
          <div
            onClick={closePanel}
            style={{
              position: 'fixed',
              inset: 0,
              zIndex: 90,
              background: 'rgba(0,0,0,0.45)',
              backdropFilter: 'blur(1px)',
              animation: closing ? 'fadeOutOverlay 220ms ease both' : 'fadeInOverlay 200ms ease both',
            }}
          />

          {/* Slide-out panel */}
          <div
            style={{
              position: 'fixed',
              top: '56px',   // below topbar
              right: 0,
              bottom: 0,
              width: '380px',
              maxWidth: '100vw',
              background: '#0d0d0d',
              borderLeft: '1px solid #1f1f1f',
              zIndex: 95,
              display: 'flex',
              flexDirection: 'column',
              animation: closing
                ? 'slideOutRight 220ms ease both'
                : 'slideInRight 220ms ease both',
              boxShadow: '-8px 0 32px rgba(0,0,0,0.5)',
            }}
          >
            {/* Panel header */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '14px 16px',
                borderBottom: '1px solid #1a1a1a',
                flexShrink: 0,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: '13px', fontWeight: 600, color: '#c8ccd4' }}>
                  Notifications
                </span>
                {unreadCount > 0 && (
                  <span
                    style={{
                      fontSize: '10px',
                      fontWeight: 700,
                      color: 'var(--color-accent)',
                      background: 'rgba(var(--color-accent-rgb,229,57,53),0.12)',
                      padding: '1px 6px',
                      borderRadius: '99px',
                    }}
                  >
                    {unreadCount} new
                  </span>
                )}
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                {notifications.length > 0 && (
                  <>
                    <button
                      onClick={markAllRead}
                      title="Mark all read"
                      style={iconBtn}
                      onMouseEnter={btnHover}
                      onMouseLeave={btnLeave}
                    >
                      <CheckCheck size={13} />
                    </button>
                    <button
                      onClick={clearNotifications}
                      title="Clear all"
                      style={iconBtn}
                      onMouseEnter={btnHover}
                      onMouseLeave={btnLeave}
                    >
                      <Trash2 size={13} />
                    </button>
                  </>
                )}
                <button
                  onClick={closePanel}
                  title="Close"
                  style={{ ...iconBtn, marginLeft: '4px' }}
                  onMouseEnter={btnHover}
                  onMouseLeave={btnLeave}
                >
                  <X size={14} />
                </button>
              </div>
            </div>

            {/* Notification list */}
            <div style={{ flex: 1, overflowY: 'auto' }}>
              {notifications.length === 0 ? (
                <div
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                    height: '100%',
                    gap: '10px',
                    color: '#27272a',
                  }}
                >
                  <Bell size={28} style={{ opacity: 0.3 }} />
                  <span style={{ fontSize: '13px' }}>No notifications yet</span>
                </div>
              ) : (
                groups.map(({ domain, items }) => (
                  <div key={domain}>
                    {/* Group header */}
                    <div
                      style={{
                        padding: '10px 16px 6px',
                        fontSize: '10px',
                        fontWeight: 700,
                        letterSpacing: '0.1em',
                        textTransform: 'uppercase',
                        color: '#3a3a44',
                        fontFamily: "'JetBrains Mono', monospace",
                        borderBottom: '1px solid rgba(255,255,255,0.03)',
                      }}
                    >
                      {domain === '__ungrouped__' ? 'Other' : domain}
                    </div>

                    {/* Notification items in this group */}
                    {items.map((n) => (
                      <NotifRow
                        key={n.id}
                        n={n}
                        onClick={() => handleNotifClick(n)}
                      />
                    ))}
                  </div>
                ))
              )}
            </div>

            {/* Footer */}
            {notifications.length > 0 && (
              <div
                style={{
                  padding: '10px 16px',
                  borderTop: '1px solid #1a1a1a',
                  fontSize: '11px',
                  color: '#27272a',
                  flexShrink: 0,
                }}
              >
                {notifications.length} event{notifications.length !== 1 ? 's' : ''} stored
              </div>
            )}
          </div>
        </>,
        document.body,
      )}
    </>
  )
}

// ── NotifRow ──────────────────────────────────────────────────────────────────

function NotifRow({ n, onClick }: { n: AppNotification; onClick: () => void }) {
  const isClickable = !!n.scan_id

  return (
    <div
      onClick={isClickable ? onClick : undefined}
      style={{
        display: 'flex',
        alignItems: 'flex-start',
        gap: '10px',
        padding: '10px 16px',
        cursor: isClickable ? 'pointer' : 'default',
        borderBottom: '1px solid rgba(255,255,255,0.025)',
        background: n.read ? 'transparent' : 'rgba(var(--color-accent-rgb,229,57,53),0.03)',
        transition: 'background 120ms',
      }}
      onMouseEnter={(e) => {
        if (isClickable) (e.currentTarget as HTMLElement).style.background = 'rgba(255,255,255,0.03)'
      }}
      onMouseLeave={(e) => {
        (e.currentTarget as HTMLElement).style.background = n.read
          ? 'transparent'
          : 'rgba(var(--color-accent-rgb,229,57,53),0.03)'
      }}
    >
      {/* Unread dot */}
      <div style={{ paddingTop: '2px', flexShrink: 0, width: '8px' }}>
        {!n.read && (
          <div
            style={{
              width: '6px',
              height: '6px',
              borderRadius: '50%',
              background: 'var(--color-accent)',
              boxShadow: '0 0 4px rgba(var(--color-accent-rgb,229,57,53),0.6)',
            }}
          />
        )}
      </div>

      {notifIcon(n.type)}

      <div style={{ flex: 1, minWidth: 0 }}>
        <div
          style={{
            fontSize: '12px',
            fontWeight: n.read ? 400 : 600,
            color: n.read ? '#52525b' : '#c8ccd4',
            marginBottom: '2px',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          }}
        >
          {n.title}
        </div>
        <div
          style={{
            fontSize: '11px',
            color: '#3a3a44',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          }}
        >
          {n.body}
        </div>
      </div>

      <span style={{ fontSize: '10px', color: '#27272a', flexShrink: 0, whiteSpace: 'nowrap', paddingTop: '1px' }}>
        {relativeTime(n.timestamp)}
      </span>
    </div>
  )
}

// ── Style helpers ─────────────────────────────────────────────────────────────

const iconBtn: React.CSSProperties = {
  background: 'transparent',
  border: 'none',
  cursor: 'pointer',
  padding: '5px',
  color: '#3a3a44',
  borderRadius: '4px',
  transition: 'color 150ms, background-color 150ms',
  display: 'flex',
  alignItems: 'center',
}

function btnHover(e: React.MouseEvent<HTMLButtonElement>) {
  const el = e.currentTarget as HTMLElement
  el.style.color = '#c8ccd4'
  el.style.backgroundColor = 'rgba(255,255,255,0.05)'
}

function btnLeave(e: React.MouseEvent<HTMLButtonElement>) {
  const el = e.currentTarget as HTMLElement
  el.style.color = '#3a3a44'
  el.style.backgroundColor = ''
}
