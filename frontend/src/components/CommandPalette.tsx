import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Activity,
  AlertTriangle,
  BarChart2,
  FileText,
  Globe,
  Key,
  Lock,
  Mail,
  Plus,
  Search,
  Server,
  Settings,
  Shield,
  User,
  Users,
  Zap,
} from 'lucide-react'

interface Command {
  id: string
  label: string
  description?: string
  icon: React.ComponentType<{ size?: number; style?: React.CSSProperties }>
  action: () => void
  keywords?: string
}

interface CommandPaletteProps {
  open: boolean
  onClose: () => void
}

export function CommandPalette({ open, onClose }: CommandPaletteProps) {
  const navigate = useNavigate()
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const [mounted, setMounted] = useState(false)
  const [closing, setClosing] = useState(false)

  const commands: Command[] = [
    { id: 'overview', label: 'Go to Overview', icon: BarChart2, action: () => navigate('/'), keywords: 'dashboard home' },
    { id: 'assessments', label: 'Go to Assessments', icon: Activity, action: () => navigate('/assessments') },
    { id: 'new-assessment', label: 'New Assessment', description: 'Launch a new scan', icon: Plus, action: () => navigate('/assessments'), keywords: 'scan create new' },
    { id: 'findings', label: 'Go to Findings', icon: AlertTriangle, action: () => navigate('/findings'), keywords: 'vulnerabilities' },
    { id: 'reports', label: 'Go to Reports', icon: FileText, action: () => navigate('/reports') },
    { id: 'assets', label: 'Go to Assets', icon: Server, action: () => navigate('/assets') },
    { id: 'team', label: 'Go to Team', icon: Users, action: () => navigate('/team'), keywords: 'members organization' },
    { id: 'settings', label: 'Go to Settings', icon: Settings, action: () => navigate('/settings'), keywords: 'mfa config' },
    { id: 'account', label: 'My Account', icon: User, action: () => navigate('/account'), keywords: 'profile me user' },
    { id: 'preferences', label: 'Preferences', icon: Settings, action: () => navigate('/preferences'), keywords: 'appearance theme density' },
    { id: 'smtp-discovery', label: 'SMTP Discovery', icon: Search, action: () => navigate('/smtp-discovery') },
    { id: 'smtp-security', label: 'SMTP Security', icon: Shield, action: () => navigate('/smtp-security') },
    { id: 'dns-auth', label: 'DNS & Authentication', icon: Globe, action: () => navigate('/dns-auth'), keywords: 'spf dkim dmarc' },
    { id: 'tls', label: 'TLS Analysis', icon: Lock, action: () => navigate('/tls'), keywords: 'ssl certificate' },
    { id: 'webmail', label: 'Webmail Security', icon: Mail, action: () => navigate('/webmail') },
    { id: 'vuln-intel', label: 'Vulnerability Intelligence', icon: Zap, action: () => navigate('/vuln-intel'), keywords: 'cve cisa kev' },
    { id: 'credentials', label: 'Credential Exposure', icon: Key, action: () => navigate('/secrets'), keywords: 'secrets leaked passwords' },
  ]

  const filtered = query.trim() === ''
    ? commands.slice(0, 8)
    : commands.filter((c) => {
        const q = query.toLowerCase()
        return (
          c.label.toLowerCase().includes(q) ||
          c.description?.toLowerCase().includes(q) ||
          c.keywords?.toLowerCase().includes(q)
        )
      })

  // Mount/unmount with exit animation
  useEffect(() => {
    if (open) {
      setMounted(true)
      setClosing(false)
      setQuery('')
      setSelected(0)
      setTimeout(() => inputRef.current?.focus(), 10)
    } else if (mounted) {
      setClosing(true)
      const t = setTimeout(() => {
        setMounted(false)
        setClosing(false)
      }, 180)
      return () => clearTimeout(t)
    }
  }, [open])

  // Keyboard navigation
  useEffect(() => {
    if (!open) return
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        onClose()
      } else if (e.key === 'ArrowDown') {
        e.preventDefault()
        setSelected((s) => Math.min(s + 1, filtered.length - 1))
      } else if (e.key === 'ArrowUp') {
        e.preventDefault()
        setSelected((s) => Math.max(s - 1, 0))
      } else if (e.key === 'Enter') {
        e.preventDefault()
        if (filtered[selected]) {
          filtered[selected].action()
          onClose()
        }
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, filtered, selected, onClose])

  // Reset selection on query change
  useEffect(() => { setSelected(0) }, [query])

  if (!mounted) return null

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-50"
        style={{
          background: 'rgba(10,10,10,0.75)',
          backdropFilter: 'blur(4px)',
          animation: closing ? 'fade 180ms var(--ease-out) reverse both' : 'fade 180ms var(--ease-out) both',
        }}
        onClick={onClose}
      />

      {/* Palette */}
      <div
        className="fixed z-50 w-full"
        style={{ top: '15vh', padding: '0 16px', maxWidth: '560px', left: '50%', transform: 'translateX(-50%)' }}
      >
        <div
          className="border border-border overflow-hidden"
          style={{
            background: '#121212',
            borderTop: '2px solid #E8173A',
            animation: closing
              ? 'cardLeave 180ms var(--ease-out) both'
              : 'cardEnter 220ms var(--ease-out) both',
          }}
        >
          {/* Search input */}
          <div className="flex items-center gap-3 px-4 py-3 border-b border-border">
            <Search size={15} style={{ color: '#666672', flexShrink: 0 }} />
            <input
              ref={inputRef}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search commands…"
              className="flex-1 bg-transparent text-sm text-text-primary outline-none"
              style={{ letterSpacing: '0.5px' }}
            />
            <span
              className="label"
              style={{ fontSize: '10px', border: '1px solid #1f1f1f', padding: '2px 6px' }}
            >
              ESC
            </span>
          </div>

          {/* Command list */}
          <div style={{ maxHeight: '340px', overflowY: 'auto' }}>
            {filtered.length === 0 && (
              <div className="px-4 py-8 text-center text-sm text-text-muted" style={{ letterSpacing: '1px' }}>
                No commands found
              </div>
            )}
            {filtered.map((cmd, i) => {
              const Icon = cmd.icon
              return (
                <button
                  key={cmd.id}
                  onClick={() => { cmd.action(); onClose() }}
                  className="w-full flex items-center gap-3 px-4 py-3 text-left"
                  style={{
                    background: selected === i ? 'rgba(232,23,58,0.08)' : 'transparent',
                    borderLeft: selected === i ? '2px solid #E8173A' : '2px solid transparent',
                    transition: 'background-color 100ms var(--ease-out)',
                  }}
                  onMouseEnter={() => setSelected(i)}
                >
                  <Icon size={15} style={{ color: selected === i ? '#E8173A' : '#666672', flexShrink: 0 }} />
                  <div className="flex-1 min-w-0">
                    <div
                      className="text-sm"
                      style={{ color: selected === i ? '#e8ecf2' : '#c8ccd4', letterSpacing: '0.5px' }}
                    >
                      {cmd.label}
                    </div>
                    {cmd.description && (
                      <div className="text-xs text-text-muted" style={{ letterSpacing: '0.5px' }}>
                        {cmd.description}
                      </div>
                    )}
                  </div>
                  {selected === i && (
                    <span className="label" style={{ fontSize: '10px', border: '1px solid #3a3a44', padding: '2px 6px' }}>
                      ENTER
                    </span>
                  )}
                </button>
              )
            })}
          </div>

          {/* Footer */}
          <div className="px-4 py-2 border-t border-border flex items-center gap-4">
            <span className="text-xs text-text-muted" style={{ letterSpacing: '0.5px' }}>
              ↑↓ navigate · Enter select · Esc close
            </span>
          </div>
        </div>
      </div>
    </>
  )
}
