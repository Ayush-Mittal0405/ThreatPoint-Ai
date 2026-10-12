/**
 * Global Search / Command Palette (Ctrl+K)
 * Unified search across Incidents, Alerts, Threat Hunting shortcuts, and Navigation destinations.
 */
import { useState, useEffect, useRef, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Search, AlertTriangle, Radio, Shield, Target,
  BarChart2, Activity, ArrowRight, CornerDownLeft, Sparkles, X
} from 'lucide-react'
import { api, Incident, Alert } from '../services/api'

interface SearchItem {
  id: string
  category: 'navigation' | 'incident' | 'alert' | 'hunt'
  title: string
  subtitle?: string
  badge?: string
  badgeColor?: string
  icon: any
  action: () => void
}

const STATIC_PAGES = [
  { path: '/',          title: 'SOC Overview',    subtitle: 'Real-time telemetry and stats dashboard', icon: Activity },
  { path: '/incidents', title: 'Incidents',       subtitle: 'Correlated security incidents and investigations', icon: AlertTriangle },
  { path: '/alerts',    title: 'Alerts',          subtitle: 'Detection rules and security alert feed', icon: Radio },
  { path: '/hunting',   title: 'Threat Hunting',  subtitle: 'Autonomous AI natural language threat hunter', icon: Search },
  { path: '/response',  title: 'Response Center', subtitle: 'Remediation actions and verification loop', icon: Target },
  { path: '/models',    title: 'Model Eval',      subtitle: 'Agent precision, recall, and hallucination metrics', icon: BarChart2 },
]

const HUNT_TEMPLATES = [
  "Hunt for encoded PowerShell executions originating from Office applications",
  "Hunt for outbound C2 network traffic on port 4444",
  "Hunt for multiple failed logon attempts followed by privilege escalation",
  "Hunt for suspicious scheduled tasks and service installations",
]

interface GlobalSearchProps {
  isOpen: boolean
  onClose: () => void
}

export default function GlobalSearch({ isOpen, onClose }: GlobalSearchProps) {
  const [query, setQuery] = useState('')
  const [selectedIndex, setSelectedIndex] = useState(0)
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [alerts, setAlerts] = useState<Alert[]>([])
  const inputRef = useRef<HTMLInputElement>(null)
  const navigate = useNavigate()

  // Load incidents & alerts for instant fuzzy search
  useEffect(() => {
    if (isOpen) {
      setQuery('')
      setSelectedIndex(0)
      setTimeout(() => inputRef.current?.focus(), 50)

      api.getIncidents().then(d => setIncidents(d.incidents || [])).catch(() => {})
      api.getAlerts().then(d => setAlerts(d || [])).catch(() => {})
    }
  }, [isOpen])

  // Build searchable items
  const items = useMemo(() => {
    const q = query.toLowerCase().trim()
    const results: SearchItem[] = []

    // 1. Navigation Pages
    STATIC_PAGES.forEach(p => {
      if (!q || p.title.toLowerCase().includes(q) || p.subtitle.toLowerCase().includes(q)) {
        results.push({
          id: `nav-${p.path}`,
          category: 'navigation',
          title: p.title,
          subtitle: p.subtitle,
          icon: p.icon,
          action: () => { navigate(p.path); onClose() },
        })
      }
    })

    // 2. Incidents
    incidents.forEach(inc => {
      const match =
        !q ||
        inc.incident_id.toLowerCase().includes(q) ||
        inc.title.toLowerCase().includes(q) ||
        (inc.entities?.hosts || []).some(h => h.toLowerCase().includes(q))
      if (match) {
        results.push({
          id: `inc-${inc.id}`,
          category: 'incident',
          title: `${inc.incident_id}: ${inc.title}`,
          subtitle: `Severity: ${inc.severity.toUpperCase()} · Status: ${inc.status} · Hosts: ${(inc.entities?.hosts || []).join(', ') || 'N/A'}`,
          badge: inc.severity,
          badgeColor: inc.severity === 'critical' ? 'var(--critical)' : 'var(--high)',
          icon: AlertTriangle,
          action: () => { navigate('/incidents'); onClose() },
        })
      }
    })

    // 3. Alerts
    alerts.forEach(alt => {
      const match =
        !q ||
        alt.alert_id.toLowerCase().includes(q) ||
        alt.title.toLowerCase().includes(q) ||
        (alt.host || '').toLowerCase().includes(q)
      if (match) {
        results.push({
          id: `alt-${alt.id}`,
          category: 'alert',
          title: `${alt.alert_id}: ${alt.title}`,
          subtitle: `Host: ${alt.host || 'N/A'} · Status: ${alt.status}`,
          badge: alt.severity,
          badgeColor: alt.severity === 'critical' ? 'var(--critical)' : 'var(--medium)',
          icon: Radio,
          action: () => { navigate('/alerts'); onClose() },
        })
      }
    })

    // 4. Pre-canned / dynamic Threat Hunts
    HUNT_TEMPLATES.forEach((tmpl, i) => {
      if (!q || tmpl.toLowerCase().includes(q) || 'hunt'.includes(q)) {
        results.push({
          id: `hunt-${i}`,
          category: 'hunt',
          title: tmpl,
          subtitle: 'Launch natural-language threat hunting query',
          badge: 'HUNT',
          badgeColor: 'var(--info)',
          icon: Sparkles,
          action: () => { navigate('/hunting'); onClose() },
        })
      }
    })

    return results.slice(0, 15) // Top 15 results
  }, [query, incidents, alerts, navigate, onClose])

  // Keyboard navigation
  useEffect(() => {
    if (!isOpen) return

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'ArrowDown') {
        e.preventDefault()
        setSelectedIndex(prev => (prev + 1) % Math.max(1, items.length))
      } else if (e.key === 'ArrowUp') {
        e.preventDefault()
        setSelectedIndex(prev => (prev - 1 + items.length) % Math.max(1, items.length))
      } else if (e.key === 'Enter') {
        e.preventDefault()
        if (items[selectedIndex]) {
          items[selectedIndex].action()
        }
      } else if (e.key === 'Escape') {
        e.preventDefault()
        onClose()
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, items, selectedIndex, onClose])

  if (!isOpen) return null

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(5, 8, 16, 0.82)',
        backdropFilter: 'blur(8px)',
        zIndex: 10000,
        display: 'flex',
        alignItems: 'flex-start',
        justifyContent: 'center',
        paddingTop: '12vh',
      }}
      onClick={onClose}
    >
      <div
        className="glass-panel fade-in"
        style={{
          width: '100%',
          maxWidth: 640,
          background: 'var(--bg-surface)',
          border: '1px solid var(--border-bright)',
          borderRadius: 14,
          boxShadow: '0 20px 60px rgba(0,0,0,0.6), 0 0 40px rgba(99,179,237,0.15)',
          overflow: 'hidden',
        }}
        onClick={e => e.stopPropagation()}
      >
        {/* ── Input Bar ─────────────────────────────────────────────── */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            padding: '16px 20px',
            borderBottom: '1px solid var(--border-subtle)',
          }}
        >
          <Search size={18} color="var(--text-accent)" />
          <input
            ref={inputRef}
            value={query}
            onChange={e => {
              setQuery(e.target.value)
              setSelectedIndex(0)
            }}
            placeholder="Type a command or search incidents, alerts, telemetry..."
            style={{
              flex: 1,
              background: 'transparent',
              border: 'none',
              outline: 'none',
              color: 'var(--text-primary)',
              fontFamily: 'var(--font-sans)',
              fontSize: 15,
            }}
          />
          <span
            style={{
              fontSize: 10,
              fontFamily: 'var(--font-mono)',
              background: 'var(--bg-overlay)',
              border: '1px solid var(--border-dim)',
              padding: '2px 6px',
              borderRadius: 4,
              color: 'var(--text-muted)',
            }}
          >
            ESC
          </span>
          <button
            onClick={onClose}
            style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
          >
            <X size={16} />
          </button>
        </div>

        {/* ── Results List ──────────────────────────────────────────── */}
        <div style={{ maxHeight: 380, overflowY: 'auto', padding: '8px 6px' }}>
          {items.length === 0 ? (
            <div style={{ padding: '32px 20px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
              No matches found for "{query}"
            </div>
          ) : (
            items.map((item, idx) => {
              const isSelected = idx === selectedIndex
              const Icon = item.icon
              return (
                <div
                  key={item.id}
                  onClick={item.action}
                  onMouseEnter={() => setSelectedIndex(idx)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 12,
                    padding: '10px 14px',
                    borderRadius: 8,
                    cursor: 'pointer',
                    background: isSelected ? 'var(--bg-raised)' : 'transparent',
                    border: `1px solid ${isSelected ? 'var(--border-dim)' : 'transparent'}`,
                    transition: 'background 0.1s ease',
                  }}
                >
                  <div
                    style={{
                      width: 28,
                      height: 28,
                      borderRadius: 6,
                      background: isSelected ? 'rgba(99,179,237,0.15)' : 'var(--bg-deep)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      flexShrink: 0,
                    }}
                  >
                    <Icon size={14} color={isSelected ? 'var(--text-accent)' : 'var(--text-secondary)'} />
                  </div>

                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div
                      style={{
                        fontSize: 13,
                        fontWeight: 600,
                        color: isSelected ? 'var(--text-primary)' : 'var(--text-secondary)',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {item.title}
                    </div>
                    {item.subtitle && (
                      <div
                        style={{
                          fontSize: 11,
                          color: 'var(--text-muted)',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                          marginTop: 1,
                        }}
                      >
                        {item.subtitle}
                      </div>
                    )}
                  </div>

                  {item.badge && (
                    <span
                      style={{
                        fontSize: 10,
                        fontFamily: 'var(--font-mono)',
                        fontWeight: 700,
                        textTransform: 'uppercase',
                        padding: '2px 6px',
                        borderRadius: 4,
                        background: `color-mix(in srgb, ${item.badgeColor || 'var(--text-accent)'} 15%, transparent)`,
                        color: item.badgeColor || 'var(--text-accent)',
                        border: `1px solid ${item.badgeColor || 'var(--border-dim)'}`,
                      }}
                    >
                      {item.badge}
                    </span>
                  )}

                  {isSelected && <CornerDownLeft size={13} color="var(--text-muted)" />}
                </div>
              )
            })
          )}
        </div>

        {/* ── Footer ────────────────────────────────────────────────── */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '10px 16px',
            background: 'var(--bg-deep)',
            borderTop: '1px solid var(--border-subtle)',
            fontSize: 11,
            color: 'var(--text-muted)',
          }}
        >
          <div style={{ display: 'flex', gap: 12 }}>
            <span><kbd style={{ fontFamily: 'var(--font-mono)' }}>↑↓</kbd> navigate</span>
            <span><kbd style={{ fontFamily: 'var(--font-mono)' }}>↵</kbd> select</span>
            <span><kbd style={{ fontFamily: 'var(--font-mono)' }}>esc</kbd> close</span>
          </div>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10 }}>ThreatPoint Ai SOC Command</span>
        </div>
      </div>
    </div>
  )
}
