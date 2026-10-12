/**
 * Endpoints — real enrolled ThreatPoint Ai endpoint agents.
 *
 * Distinct from the synthetic Fleet (100+ mock hosts): this page shows agents
 * that have actually enrolled via /api/v1/endpoints and are streaming live
 * telemetry. Overview cards, a filterable table, and a slide-over detail drawer
 * with recent activity, detections, incidents, and a security timeline.
 */
import { useState, useEffect } from 'react'
import {
  MonitorSmartphone, RefreshCw, Search, X, Activity, ShieldAlert,
  Clock, Wifi, WifiOff, AlertTriangle, Plus, Copy, Check, KeyRound,
} from 'lucide-react'
import {
  api, EndpointAgent, EndpointStats, EndpointDetail, EnrollmentTokenCreated,
} from '../services/api'
import { useToast } from '../components/Toast'
import { usePolling } from '../hooks/usePolling'

const STATUS_COLORS: Record<string, string> = {
  online: 'var(--low)',
  warning: 'var(--medium)',
  offline: 'var(--text-muted)',
  unhealthy: 'var(--high)',
  revoked: 'var(--critical)',
}

function timeAgo(iso: string): string {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000)
  if (s < 60) return `${Math.floor(s)}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}

function riskClass(score: number): string {
  if (score >= 75) return 'critical'
  if (score >= 60) return 'high'
  if (score >= 30) return 'medium'
  return 'low'
}

export default function EndpointsPage() {
  const [agents, setAgents] = useState<EndpointAgent[]>([])
  const [stats, setStats] = useState<EndpointStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [osFilter, setOsFilter] = useState('')
  const [selected, setSelected] = useState<EndpointAgent | null>(null)
  const [detail, setDetail] = useState<EndpointDetail | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [enrollOpen, setEnrollOpen] = useState(false)
  const toast = useToast()

  const loadData = async () => {
    try {
      const [agentData, statsData] = await Promise.all([
        api.getEndpoints({
          search: search || undefined,
          status: statusFilter || undefined,
          os: osFilter || undefined,
        }),
        api.getEndpointStats(),
      ])
      setAgents(agentData)
      setStats(statsData)
    } catch {
      // backend/DB may be offline — keep UI usable
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadData() }, [search, statusFilter, osFilter])
  usePolling(loadData, 2_000)

  const openDetail = async (a: EndpointAgent) => {
    setSelected(a)
    setDetail(null)
    setDetailLoading(true)
    try {
      setDetail(await api.getEndpointDetail(a.agent_id))
    } catch {
      toast.error('Failed loading endpoint detail')
    } finally {
      setDetailLoading(false)
    }
  }

  const cards: Array<{ label: string; value: number; sub: string; color: string }> = stats ? [
    { label: 'Total Endpoints', value: stats.total, sub: 'enrolled agents', color: 'var(--text-accent)' },
    { label: 'Online', value: stats.online, sub: 'reporting', color: 'var(--low)' },
    { label: 'Warning', value: stats.warning, sub: 'stale heartbeat', color: 'var(--medium)' },
    { label: 'Offline', value: stats.offline, sub: 'not reporting', color: 'var(--text-muted)' },
    { label: 'Unhealthy', value: stats.unhealthy, sub: 'agent degraded', color: 'var(--high)' },
    { label: 'Suspicious', value: stats.suspicious, sub: 'risk ≥ 60', color: 'var(--critical)' },
  ] : []

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <h1 className="page-title"><MonitorSmartphone size={22} style={{ verticalAlign: -4, marginRight: 8 }} />Endpoints</h1>
          <p className="page-subtitle">Real enrolled endpoint agents streaming live security telemetry</p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-primary" onClick={() => setEnrollOpen(true)}>
            <Plus size={14} /> Add Endpoint
          </button>
          <button className="btn btn-ghost" onClick={loadData}><RefreshCw size={14} /> Refresh</button>
        </div>
      </div>

      {/* Overview cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 12, marginBottom: 18 }}>
        {cards.map(c => (
          <div key={c.label} className="stat-card">
            <div className="stat-label">{c.label}</div>
            <div className="stat-value" style={{ color: c.color }}>{c.value}</div>
            <div className="stat-sub">{c.sub}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="card" style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 14, flexWrap: 'wrap' }}>
        <div style={{ position: 'relative', flex: '1 1 240px' }}>
          <Search size={14} style={{ position: 'absolute', left: 10, top: 9, color: 'var(--text-muted)' }} />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search hostname or agent id…"
            style={{ width: '100%', padding: '7px 10px 7px 30px', background: 'var(--bg-surface)', border: '1px solid var(--border-dim)', borderRadius: 6, color: 'var(--text-primary)', fontSize: 13 }}
          />
        </div>
        <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)} className="filter-select">
          <option value="">All statuses</option>
          {['online', 'warning', 'offline', 'unhealthy', 'revoked'].map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select value={osFilter} onChange={e => setOsFilter(e.target.value)} className="filter-select">
          <option value="">All OS</option>
          {['windows', 'linux', 'macos'].map(s => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>

      {/* Table */}
      <div className="card">
        <div className="card-title">Enrolled Agents ({agents.length})</div>
        {loading ? (
          <p style={{ color: 'var(--text-muted)', padding: 16 }}>Loading…</p>
        ) : agents.length === 0 ? (
          <div className="empty-state">
            <MonitorSmartphone size={48} />
            <h2 style={{ color: 'var(--text-secondary)', fontSize: 16 }}>No endpoints enrolled yet</h2>
            <p style={{ fontSize: 13 }}>Install the ThreatPoint Ai agent on a client PC and enroll it to see it here.</p>
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Hostname</th><th>Agent ID</th><th>OS</th><th>Status</th>
                  <th>Last Seen</th><th>Version</th><th>Risk</th><th>Open Alerts</th>
                </tr>
              </thead>
              <tbody>
                {agents.map(a => (
                  <tr key={a.agent_id} style={{ cursor: 'pointer' }} onClick={() => openDetail(a)}>
                    <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{a.hostname}</td>
                    <td className="mono" style={{ fontSize: 12 }}>{a.agent_id}</td>
                    <td>{a.operating_system || '—'}</td>
                    <td>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, color: STATUS_COLORS[a.status] || 'var(--text-muted)' }}>
                        {a.status === 'offline' ? <WifiOff size={13} /> : <Wifi size={13} />}
                        {a.status}
                      </span>
                    </td>
                    <td style={{ color: 'var(--text-secondary)' }}>{timeAgo(a.last_seen)}</td>
                    <td className="mono" style={{ fontSize: 12 }}>{a.agent_version || '—'}</td>
                    <td><span className={`badge-severity ${riskClass(a.risk_score)}`}>{a.risk_score}</span></td>
                    <td>{a.open_alerts > 0 ? <span className="badge-severity high">{a.open_alerts}</span> : '0'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {selected && (
        <EndpointDrawer
          agent={selected}
          detail={detail}
          loading={detailLoading}
          onClose={() => { setSelected(null); setDetail(null) }}
        />
      )}

      {enrollOpen && <EnrollModal onClose={() => setEnrollOpen(false)} />}
    </div>
  )
}

// ── Add-endpoint / enrollment-token modal ──────────────────────────────────────

function EnrollModal({ onClose }: { onClose: () => void }) {
  // The admin key is supplied by the analyst, never bundled in the build. Kept in
  // sessionStorage so it survives a refresh but is cleared when the tab closes.
  const [adminKey, setAdminKey] = useState(() => sessionStorage.getItem('ThreatPoint Ai_admin_key') || '')
  const [remember, setRemember] = useState(true)
  const [label, setLabel] = useState('')
  const [maxUses, setMaxUses] = useState(1)
  const [ttlHours, setTtlHours] = useState(24)
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<EnrollmentTokenCreated | null>(null)
  const [copied, setCopied] = useState<string | null>(null)
  const toast = useToast()

  const serverUrl = window.location.origin.replace(':3000', ':8008')

  const submit = async () => {
    if (!adminKey.trim()) { toast.error('Admin API key is required'); return }
    setBusy(true)
    try {
      const res = await api.createEnrollmentToken(adminKey.trim(), {
        label: label.trim() || undefined,
        max_uses: maxUses,
        ttl_seconds: ttlHours * 3600,
      })
      setResult(res)
      if (remember) sessionStorage.setItem('ThreatPoint Ai_admin_key', adminKey.trim())
      else sessionStorage.removeItem('ThreatPoint Ai_admin_key')
      toast.success('Enrollment token created')
    } catch (e: any) {
      const status = e?.response?.status
      toast.error(status === 401 ? 'Invalid admin API key' : 'Failed to create token')
    } finally {
      setBusy(false)
    }
  }

  const copy = (text: string, what: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(what)
      setTimeout(() => setCopied(null), 1800)
    })
  }

  const winCmd = result
    ? `powershell -ExecutionPolicy Bypass -File .\\scripts\\enroll.ps1 -Token "${result.enrollment_token}" -Server "${serverUrl}"`
    : ''
  const nixCmd = result
    ? `./scripts/enroll.sh --token "${result.enrollment_token}" --server "${serverUrl}"`
    : ''

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', zIndex: 60, display: 'flex', alignItems: 'center', justifyContent: 'center' }} onClick={onClose}>
      <div
        onClick={e => e.stopPropagation()}
        style={{ width: 'min(620px, 94vw)', maxHeight: '90vh', overflowY: 'auto', background: 'var(--bg-deep)', border: '1px solid var(--border-bright)', borderRadius: 10, padding: 22 }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
          <h2 style={{ fontSize: 17, color: 'var(--text-primary)', margin: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
            <KeyRound size={17} /> Add Endpoint
          </h2>
          <button className="btn btn-ghost" onClick={onClose}><X size={16} /></button>
        </div>
        <p style={{ color: 'var(--text-muted)', fontSize: 12, marginTop: 0, marginBottom: 16 }}>
          Generate a one-time enrollment token, then run the enroll command on the client PC.
        </p>

        {!result ? (
          <>
            <Field label="Admin API key">
              <input
                type="password" value={adminKey} onChange={e => setAdminKey(e.target.value)}
                placeholder="ThreatPoint Ai_ADMIN_API_KEY from the server .env"
                style={inputStyle}
              />
            </Field>
            <label style={{ display: 'flex', alignItems: 'center', gap: 7, fontSize: 12, color: 'var(--text-muted)', marginBottom: 12 }}>
              <input type="checkbox" checked={remember} onChange={e => setRemember(e.target.checked)} />
              Remember for this browser session only
            </label>

            <Field label="Label (optional)">
              <input value={label} onChange={e => setLabel(e.target.value)}
                placeholder="e.g. laptop-jdoe" style={inputStyle} />
            </Field>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              <Field label="Max uses">
                <input type="number" min={1} max={1000} value={maxUses}
                  onChange={e => setMaxUses(Math.max(1, Number(e.target.value)))} style={inputStyle} />
              </Field>
              <Field label="Valid for (hours)">
                <input type="number" min={1} max={8760} value={ttlHours}
                  onChange={e => setTtlHours(Math.max(1, Number(e.target.value)))} style={inputStyle} />
              </Field>
            </div>

            <div style={{ display: 'flex', gap: 8, marginTop: 16 }}>
              <button className="btn btn-primary" onClick={submit} disabled={busy}>
                {busy ? 'Generating…' : 'Generate Token'}
              </button>
              <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
            </div>
          </>
        ) : (
          <>
            <div style={{ background: 'rgba(250,204,21,0.10)', border: '1px solid rgba(250,204,21,0.3)', borderRadius: 6, padding: '8px 12px', marginBottom: 14, color: 'var(--medium)', fontSize: 12 }}>
              ⚠ This token is shown once and cannot be retrieved again. Copy it now.
              Expires {new Date(result.expires_at).toLocaleString()} · {result.max_uses} use(s).
            </div>

            <Field label="Enrollment token">
              <CopyBox text={result.enrollment_token} onCopy={() => copy(result.enrollment_token, 'token')} copied={copied === 'token'} />
            </Field>

            <Field label="Windows client — run in the ThreatPoint Ai-agent folder">
              <CopyBox text={winCmd} onCopy={() => copy(winCmd, 'win')} copied={copied === 'win'} small />
            </Field>

            <Field label="Linux / macOS client">
              <CopyBox text={nixCmd} onCopy={() => copy(nixCmd, 'nix')} copied={copied === 'nix'} small />
            </Field>

            <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
              <button className="btn btn-primary" onClick={onClose}>Done</button>
              <button className="btn btn-ghost" onClick={() => setResult(null)}>Generate another</button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}

const inputStyle: React.CSSProperties = {
  width: '100%', padding: '7px 10px', background: 'var(--bg-surface)',
  border: '1px solid var(--border-dim)', borderRadius: 6,
  color: 'var(--text-primary)', fontSize: 13,
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 5 }}>{label}</div>
      {children}
    </div>
  )
}

function CopyBox({ text, onCopy, copied, small }: { text: string; onCopy: () => void; copied: boolean; small?: boolean }) {
  return (
    <div style={{ display: 'flex', gap: 6, alignItems: 'stretch' }}>
      <code className="mono" style={{
        flex: 1, background: 'var(--bg-surface)', border: '1px solid var(--border-dim)',
        borderRadius: 6, padding: '8px 10px', fontSize: small ? 11 : 13,
        color: 'var(--text-primary)', wordBreak: 'break-all',
      }}>{text}</code>
      <button className="btn btn-ghost" onClick={onCopy} title="Copy" style={{ flexShrink: 0 }}>
        {copied ? <Check size={14} color="var(--low)" /> : <Copy size={14} />}
      </button>
    </div>
  )
}

// ── Slide-over detail drawer ───────────────────────────────────────────────────

function EndpointDrawer({ agent, detail, loading, onClose }: {
  agent: EndpointAgent
  detail: EndpointDetail | null
  loading: boolean
  onClose: () => void
}) {
  const kindIcon = (kind: string) => kind === 'incident' ? <ShieldAlert size={14} color="var(--critical)" />
    : kind === 'detection' ? <AlertTriangle size={14} color="var(--high)" />
    : <Activity size={14} color="var(--text-accent)" />

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 50, display: 'flex', justifyContent: 'flex-end' }} onClick={onClose}>
      <div
        onClick={e => e.stopPropagation()}
        style={{ width: 'min(680px, 96vw)', height: '100%', background: 'var(--bg-deep)', borderLeft: '1px solid var(--border-bright)', overflowY: 'auto', padding: 22 }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
          <div>
            <h2 style={{ fontSize: 18, color: 'var(--text-primary)', margin: 0 }}>{agent.hostname}</h2>
            <p className="mono" style={{ color: 'var(--text-muted)', fontSize: 12, margin: '4px 0 0' }}>{agent.agent_id}</p>
          </div>
          <button className="btn btn-ghost" onClick={onClose}><X size={16} /></button>
        </div>

        {/* Overview grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: 10, marginBottom: 18 }}>
          <Meta label="Status" value={agent.status} color={STATUS_COLORS[agent.status]} />
          <Meta label="OS" value={`${agent.operating_system || '—'} ${agent.os_version ? `(${agent.os_version.slice(0, 18)})` : ''}`} />
          <Meta label="IP" value={agent.ip_address || '—'} />
          <Meta label="Agent Version" value={agent.agent_version || '—'} />
          <Meta label="Risk" value={String(agent.risk_score)} />
          <Meta label="Open Alerts" value={String(agent.open_alerts)} />
          <Meta label="First Seen" value={timeAgo(agent.first_seen)} />
          <Meta label="Last Seen" value={timeAgo(agent.last_seen)} />
        </div>

        {loading ? <p style={{ color: 'var(--text-muted)' }}>Loading telemetry…</p> : detail && (
          <>
            <Section icon={<Clock size={15} />} title={`Security Timeline (${detail.timeline.length})`}>
              {detail.timeline.length === 0 ? <Empty text="No timeline activity yet" /> : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {detail.timeline.map((t, i) => (
                    <div key={i} style={{ display: 'flex', gap: 10, alignItems: 'baseline', padding: '5px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                      <span className="mono" style={{ fontSize: 11, color: 'var(--text-muted)', minWidth: 130 }}>{new Date(t.timestamp).toLocaleString()}</span>
                      {kindIcon(t.kind)}
                      <span style={{ fontSize: 13, color: 'var(--text-primary)' }}>
                        {t.title}
                        {t.detail ? <span className="mono" style={{ display: 'block', fontSize: 11, color: 'var(--text-muted)', wordBreak: 'break-all' }}>{t.detail.slice(0, 160)}</span> : null}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </Section>

            <Section icon={<ShieldAlert size={15} />} title={`Detections (${detail.detections.length})`}>
              {detail.detections.length === 0 ? <Empty text="No detections" /> : detail.detections.map((d, i) => (
                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', gap: 8, padding: '6px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                  <span style={{ fontSize: 13, color: 'var(--text-primary)' }}>{d.title}</span>
                  <span className={`badge-severity ${d.severity || 'info'}`}>{d.severity}</span>
                </div>
              ))}
            </Section>

            <Section icon={<ShieldAlert size={15} />} title={`Incidents (${detail.incidents.length})`}>
              {detail.incidents.length === 0 ? <Empty text="No incidents" /> : detail.incidents.map((inc, i) => (
                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', gap: 8, padding: '6px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                  <span style={{ fontSize: 13, color: 'var(--text-primary)' }}><span className="mono" style={{ color: 'var(--text-muted)', marginRight: 8 }}>{inc.incident_id}</span>{inc.title}</span>
                  <span className={`badge-severity ${inc.severity || 'info'}`}>{inc.severity}</span>
                </div>
              ))}
            </Section>

            <Section icon={<Activity size={15} />} title={`Recent Events (${detail.recent_events.length})`}>
              {detail.recent_events.length === 0 ? <Empty text="No events" /> : (
                <div style={{ overflowX: 'auto' }}>
                  <table className="data-table">
                    <thead><tr><th>Time</th><th>Type</th><th>Process</th><th>Detail</th></tr></thead>
                    <tbody>
                      {detail.recent_events.slice(0, 40).map((e, i) => (
                        <tr key={i}>
                          <td className="mono" style={{ fontSize: 11 }}>{new Date(e.timestamp).toLocaleTimeString()}</td>
                          <td>{e.event_type}</td>
                          <td>{e.process || '—'}</td>
                          <td className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                            {e.command_line ? e.command_line.slice(0, 60)
                              : e.dst_ip ? `${e.dst_ip}:${e.dst_port || ''}`
                              : e.user || ''}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Section>
          </>
        )}
      </div>
    </div>
  )
}

function Meta({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-dim)', borderRadius: 6, padding: '8px 10px' }}>
      <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>{label}</div>
      <div style={{ fontSize: 13, color: color || 'var(--text-primary)', marginTop: 2 }}>{value}</div>
    </div>
  )
}

function Section({ icon, title, children }: { icon: React.ReactNode; title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 20 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8, color: 'var(--text-secondary)', fontSize: 13, fontWeight: 600 }}>
        {icon} {title}
      </div>
      {children}
    </div>
  )
}

function Empty({ text }: { text: string }) {
  return <p style={{ color: 'var(--text-muted)', fontSize: 12, margin: '4px 0' }}>{text}</p>
}
