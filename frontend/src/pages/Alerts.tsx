/**
 * Alerts Page — full table with filters, detail panel, and status management.
 * Falls back to mock data when backend is not connected.
 */
import { useState, useEffect, useMemo } from 'react'
import { Radio, Search, RefreshCw, ChevronRight, X, CheckCircle, AlertTriangle, XCircle } from 'lucide-react'
import { api, Alert } from '../services/api'

// ── Helpers ───────────────────────────────────────────────────────────────────

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'informational']
function sevRank(s: string) { return SEV_ORDER.indexOf(s.toLowerCase()) }

function SeverityBadge({ s }: { s: string }) {
  return <span className={`badge-severity ${s}`}>{s}</span>
}
function StatusBadge({ s }: { s: string }) {
  return <span className={`badge-status ${s}`}>{s.replace('_', ' ')}</span>
}
function TimeAgo({ ts }: { ts: string }) {
  if (!ts) return <span style={{ color: 'var(--text-muted)' }}>—</span>
  const diff = Date.now() - new Date(ts).getTime()
  const m = Math.floor(diff / 60000)
  if (m < 1)  return <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>just now</span>
  if (m < 60) return <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>{m}m ago</span>
  const h = Math.floor(m / 60)
  if (h < 24) return <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>{h}h ago</span>
  return <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>{Math.floor(h / 24)}d ago</span>
}

import { usePolling } from '../hooks/usePolling'

// ── Status action definitions ─────────────────────────────────────────────────

const STATUS_ACTIONS = [
  { status: 'acknowledged', label: 'Acknowledge', icon: CheckCircle, color: 'var(--info)' },
  { status: 'false_positive', label: 'False Positive', icon: XCircle, color: 'var(--medium)' },
  { status: 'closed', label: 'Close', icon: X, color: 'var(--low)' },
]

// ── Main Component ─────────────────────────────────────────────────────────────

type FilterStatus = 'all' | 'open' | 'acknowledged' | 'in_incident' | 'false_positive' | 'closed'
type FilterSeverity = 'all' | 'critical' | 'high' | 'medium' | 'low'

export default function AlertsPage() {
  const [alerts, setAlerts]         = useState<Alert[]>([])
  const [loading, setLoading]       = useState(true)
  const [selected, setSelected]     = useState<Alert | null>(null)
  const [filterStatus, setFStatus]  = useState<FilterStatus>('all')
  const [filterSev, setFSev]        = useState<FilterSeverity>('all')
  const [searchText, setSearchText] = useState('')
  const [updatingId, setUpdatingId] = useState<string | null>(null)

  const load = async () => {
    try {
      const data = await api.getAlerts()
      setAlerts(data || [])
    } catch {
      // Backend offline or error — display empty list gracefully
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])
  usePolling(load, 2_000)

  // Apply filters
  const filtered = useMemo(() => {
    return alerts
      .filter(a => filterStatus === 'all' || a.status === filterStatus)
      .filter(a => filterSev    === 'all' || a.severity === filterSev)
      .filter(a => {
        if (!searchText) return true
        const q = searchText.toLowerCase()
        return (
          a.title.toLowerCase().includes(q) ||
          a.alert_id.toLowerCase().includes(q) ||
          (a.host || '').toLowerCase().includes(q) ||
          (a.user || '').toLowerCase().includes(q)
        )
      })
      .sort((a, b) => sevRank(a.severity) - sevRank(b.severity))
  }, [alerts, filterStatus, filterSev, searchText])

  const updateStatus = async (alert: Alert, newStatus: string) => {
    setUpdatingId(alert.id)
    // Optimistic update
    setAlerts(prev => prev.map(a => a.id === alert.id ? { ...a, status: newStatus } : a))
    if (selected?.id === alert.id) setSelected(prev => prev ? { ...prev, status: newStatus } : null)
    try {
      await api.updateAlertStatus(alert.id, newStatus)
    } catch {
      // Revert on error
      setAlerts(prev => prev.map(a => a.id === alert.id ? alert : a))
    }
    setUpdatingId(null)
  }

  const openCounts = {
    all:      alerts.length,
    open:     alerts.filter(a => a.status === 'open').length,
    critical: alerts.filter(a => a.severity === 'critical' && a.status === 'open').length,
  }

  return (
    <div className="fade-in" style={{ display: 'grid', gridTemplateColumns: selected ? '1fr 380px' : '1fr', gap: 20 }}>

      {/* ── Left: Alert List ─────────────────────────────────────────── */}
      <div>
        {/* Header */}
        <div className="page-header">
          <div>
            <h1 className="page-title">Alerts</h1>
            <p className="page-subtitle">
              {openCounts.open} open · {openCounts.critical} critical · {openCounts.all} total
            </p>
          </div>
          <button className="btn btn-ghost" style={{ fontSize: 11 }} onClick={load} disabled={loading}>
            <RefreshCw size={11} /> Refresh
          </button>
        </div>

        {/* Filter Bar */}
        <div className="card" style={{ marginBottom: 14, padding: '12px 16px' }}>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
            {/* Search */}
            <div style={{ position: 'relative', flex: '1 1 200px', minWidth: 160 }}>
              <Search size={12} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', pointerEvents: 'none' }} />
              <input
                value={searchText}
                onChange={e => setSearchText(e.target.value)}
                placeholder="Search alerts, hosts, users..."
                style={{
                  width: '100%', background: 'var(--bg-deep)', border: '1px solid var(--border-dim)',
                  borderRadius: 'var(--radius-md)', padding: '6px 10px 6px 30px',
                  color: 'var(--text-primary)', fontFamily: 'var(--font-sans)', fontSize: 12, outline: 'none',
                }}
              />
            </div>

            {/* Status filter */}
            <div style={{ display: 'flex', gap: 4 }}>
              {(['all', 'open', 'acknowledged', 'in_incident', 'false_positive', 'closed'] as FilterStatus[]).map(s => (
                <button
                  key={s}
                  onClick={() => setFStatus(s)}
                  style={{
                    fontSize: 11, padding: '4px 10px', borderRadius: 6, cursor: 'pointer',
                    background: filterStatus === s ? 'var(--bg-overlay)' : 'transparent',
                    border: `1px solid ${filterStatus === s ? 'var(--border-bright)' : 'transparent'}`,
                    color: filterStatus === s ? 'var(--text-accent)' : 'var(--text-muted)',
                    transition: 'all 0.15s',
                  }}
                >
                  {s.replace('_', ' ')}
                </button>
              ))}
            </div>

            {/* Severity filter */}
            <div style={{ display: 'flex', gap: 4 }}>
              {(['all', 'critical', 'high', 'medium', 'low'] as FilterSeverity[]).map(sv => (
                <button
                  key={sv}
                  onClick={() => setFSev(sv)}
                  style={{
                    fontSize: 11, padding: '4px 10px', borderRadius: 6, cursor: 'pointer',
                    background: filterSev === sv ? 'var(--bg-overlay)' : 'transparent',
                    border: `1px solid ${filterSev === sv ? 'var(--border-bright)' : 'transparent'}`,
                    color: filterSev === sv ? `var(--${sv === 'all' ? 'text-accent' : sv})` : 'var(--text-muted)',
                    transition: 'all 0.15s',
                  }}
                >
                  {sv}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Table */}
        <div className="card">
          {loading ? (
            <div className="empty-state"><div className="spinner" /></div>
          ) : filtered.length === 0 ? (
            <div className="empty-state">
              <Radio size={36} />
              <p>No alerts match the current filters.</p>
            </div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th style={{ minWidth: 280 }}>Title</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Host</th>
                  <th>User</th>
                  <th>MITRE</th>
                  <th>Time</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {filtered.map(alert => (
                  <tr
                    key={alert.id}
                    onClick={() => setSelected(selected?.id === alert.id ? null : alert)}
                    style={{
                      cursor: 'pointer',
                      background: selected?.id === alert.id ? 'var(--bg-raised)' : '',
                      opacity: updatingId === alert.id ? 0.5 : 1,
                      transition: 'opacity 0.2s',
                    }}
                  >
                    <td><span className="mono" style={{ fontSize: 10 }}>{alert.alert_id}</span></td>
                    <td style={{ color: 'var(--text-primary)', maxWidth: 300 }}>
                      <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 12 }}>
                        {alert.title}
                      </div>
                    </td>
                    <td><SeverityBadge s={alert.severity} /></td>
                    <td><StatusBadge s={alert.status} /></td>
                    <td>
                      {alert.host
                        ? <span className="mono" style={{ fontSize: 11 }}>{alert.host}</span>
                        : <span style={{ color: 'var(--text-muted)' }}>—</span>
                      }
                    </td>
                    <td>
                      {alert.user
                        ? <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{alert.user}</span>
                        : <span style={{ color: 'var(--text-muted)' }}>—</span>
                      }
                    </td>
                    <td style={{ fontSize: 10 }}>
                      {(alert.mitre_techniques || []).slice(0, 2).map(t => (
                        <span key={t} className="mono" style={{ marginRight: 4 }}>{t}</span>
                      ))}
                    </td>
                    <td><TimeAgo ts={alert.created_at} /></td>
                    <td>
                      <ChevronRight size={13} color="var(--text-muted)" />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {filtered.length > 0 && !loading && (
            <div style={{ padding: '8px 14px', borderTop: '1px solid var(--border-subtle)', fontSize: 11, color: 'var(--text-muted)' }}>
              Showing {filtered.length} of {alerts.length} alerts
            </div>
          )}
        </div>
      </div>

      {/* ── Right: Detail Panel ─────────────────────────────────────── */}
      {selected && (
        <div className="fade-in">
          {/* Alert Info Card */}
          <div className="card" style={{ marginBottom: 14 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
              <div>
                <span className="mono" style={{ fontSize: 10, color: 'var(--text-muted)' }}>{selected.alert_id}</span>
                <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', marginTop: 4, lineHeight: 1.4 }}>
                  {selected.title}
                </div>
              </div>
              <button
                onClick={() => setSelected(null)}
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', flexShrink: 0, marginLeft: 8 }}
              >✕</button>
            </div>

            <div style={{ display: 'flex', gap: 6, marginBottom: 12 }}>
              <SeverityBadge s={selected.severity} />
              <StatusBadge s={selected.status} />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 12 }}>
              {[
                { label: 'Host',   value: selected.host || '—' },
                { label: 'User',   value: selected.user || '—' },
                { label: 'Time',   value: new Date(selected.created_at).toLocaleString() },
                { label: 'Status', value: selected.status.replace('_', ' ') },
              ].map(({ label, value }) => (
                <div key={label}>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700, marginBottom: 2 }}>{label}</div>
                  <div className="mono" style={{ fontSize: 12 }}>{value}</div>
                </div>
              ))}
            </div>

            {/* MITRE */}
            {(selected.mitre_techniques || []).length > 0 && (
              <div>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700, marginBottom: 6 }}>MITRE ATT&CK</div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {(selected.mitre_techniques || []).map(t => (
                    <span key={t} className="mono" style={{
                      fontSize: 11, padding: '2px 8px',
                      background: 'rgba(99,179,237,0.08)', border: '1px solid var(--border-dim)', borderRadius: 4,
                    }}>
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Actions Card */}
          {selected.status !== 'closed' && (
            <div className="card" style={{ marginBottom: 14 }}>
              <div className="card-title">Actions</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {STATUS_ACTIONS.map(({ status, label, icon: Icon, color }) => {
                  if (status === selected.status) return null
                  return (
                    <button
                      key={status}
                      onClick={() => updateStatus(selected, status)}
                      disabled={!!updatingId}
                      style={{
                        display: 'flex', alignItems: 'center', gap: 10,
                        background: 'var(--bg-deep)', border: `1px solid var(--border-dim)`,
                        borderRadius: 8, padding: '10px 14px', cursor: 'pointer',
                        color: 'var(--text-primary)', textAlign: 'left',
                        transition: 'all 0.15s',
                      }}
                      onMouseEnter={e => (e.currentTarget.style.borderColor = color)}
                      onMouseLeave={e => (e.currentTarget.style.borderColor = 'var(--border-dim)')}
                    >
                      <Icon size={14} color={color} />
                      <div>
                        <div style={{ fontSize: 13, fontWeight: 600 }}>{label}</div>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                          Mark alert as {status.replace('_', ' ')}
                        </div>
                      </div>
                    </button>
                  )
                })}
              </div>
            </div>
          )}

          {/* Timeline stub */}
          <div className="card">
            <div className="card-title">Alert Timeline</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
              {[
                { label: 'Alert detected', time: selected.created_at, color: 'var(--critical)' },
                { label: 'Added to queue', time: selected.created_at, color: 'var(--medium)' },
                ...(selected.status !== 'open' ? [{ label: `Status → ${selected.status}`, time: new Date().toISOString(), color: 'var(--low)' }] : []),
              ].map(({ label, time, color }, i) => (
                <div key={i} style={{ display: 'flex', gap: 12, padding: '8px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                  <div style={{ width: 8, height: 8, borderRadius: '50%', background: color, marginTop: 5, flexShrink: 0 }} />
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 12, color: 'var(--text-primary)' }}>{label}</div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: 1 }}>
                      {new Date(time).toLocaleString()}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
