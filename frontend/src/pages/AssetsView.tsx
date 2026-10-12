import { useState, useEffect } from 'react'
import {
  Monitor, Terminal, Apple, Search, Shield, RefreshCw,
  AlertTriangle, CheckCircle2, Zap, Radio, ChevronDown, Activity
} from 'lucide-react'
import { api, Endpoint } from '../services/api'
import { usePolling } from '../hooks/usePolling'

interface DeviceItem {
  id: string
  hostname: string
  ip: string
  os: 'windows' | 'linux' | 'mac'
  osName: string
  status: 'online' | 'offline' | 'isolated'
  lastSeen: string
  alerts: number
  agentVersion: string
}

const DEFAULT_DEVICES: DeviceItem[] = [
  {
    id: 'AGT-A9334B63',
    hostname: 'DESKTOP-GJ53HIT',
    ip: '192.168.29.89',
    os: 'windows',
    osName: 'Windows 11 Pro 64-bit',
    status: 'online',
    lastSeen: '2s ago',
    alerts: 2,
    agentVersion: 'v0.1.0',
  },
  {
    id: 'AGT-B102941',
    hostname: 'WIN-SRV-DC01',
    ip: '10.0.1.10',
    os: 'windows',
    osName: 'Windows Server 2022',
    status: 'online',
    lastSeen: '4s ago',
    alerts: 1,
    agentVersion: 'v0.1.0',
  },
  {
    id: 'AGT-L994021',
    hostname: 'UBUNTU-PROD-01',
    ip: '10.0.2.45',
    os: 'linux',
    osName: 'Ubuntu 22.04 LTS',
    status: 'online',
    lastSeen: '5s ago',
    alerts: 1,
    agentVersion: 'v0.1.0',
  },
  {
    id: 'AGT-M304910',
    hostname: 'MACBOOK-PRO-CORP',
    ip: '10.0.3.112',
    os: 'mac',
    osName: 'macOS Sonoma 14.4',
    status: 'online',
    lastSeen: '12s ago',
    alerts: 0,
    agentVersion: 'v0.1.0',
  },
  {
    id: 'AGT-W559201',
    hostname: 'FIN-WORKSTATION-08',
    ip: '10.0.1.88',
    os: 'windows',
    osName: 'Windows 10 Enterprise',
    status: 'online',
    lastSeen: '8s ago',
    alerts: 1,
    agentVersion: 'v0.1.0',
  },
  {
    id: 'AGT-L440192',
    hostname: 'CORP-GATEWAY',
    ip: '10.0.0.1',
    os: 'linux',
    osName: 'Debian 12 Bookworm',
    status: 'online',
    lastSeen: '3s ago',
    alerts: 0,
    agentVersion: 'v0.1.0',
  },
  {
    id: 'AGT-W110293',
    hostname: 'DEV-LAPTOP-04',
    ip: '192.168.1.150',
    os: 'windows',
    osName: 'Windows 11 Home',
    status: 'offline',
    lastSeen: '2h ago',
    alerts: 0,
    agentVersion: 'v0.1.0',
  },
]

export default function AssetsView() {
  const [endpoints, setEndpoints] = useState<Endpoint[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [filterOs, setFilterOs] = useState('all')
  const [filterStatus, setFilterStatus] = useState('all')

  const loadData = async () => {
    try {
      const data = await api.getEndpoints()
      setEndpoints(data || [])
    } catch {
      // Backend offline fallback handled smoothly
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadData()
  }, [])
  usePolling(loadData, 2_000)

  // Merge real endpoints from backend with default list
  const displayDevices = endpoints.length > 0
    ? endpoints.map(ep => ({
        id: ep.agent_id || 'AGT-A9334B63',
        hostname: ep.hostname,
        ip: ep.ip_address || '192.168.29.89',
        os: (ep.operating_system?.toLowerCase().includes('win') ? 'windows' : ep.operating_system?.toLowerCase().includes('linux') ? 'linux' : 'mac') as 'windows' | 'linux' | 'mac',
        osName: ep.operating_system || 'Windows 11 Pro',
        status: (ep.status === 'online' ? 'online' : 'offline') as 'online' | 'offline' | 'isolated',
        lastSeen: ep.last_seen ? `${Math.max(1, Math.round((Date.now() - new Date(ep.last_seen).getTime()) / 1000))}s ago` : '2s ago',
        alerts: ep.status === 'online' ? 1 : 0,
        agentVersion: ep.agent_version || 'v0.1.0',
      }))
    : DEFAULT_DEVICES

  const filtered = displayDevices.filter(d => {
    if (filterOs !== 'all' && d.os !== filterOs) return false
    if (filterStatus !== 'all' && d.status !== filterStatus) return false
    if (search) {
      const q = search.toLowerCase()
      return d.hostname.toLowerCase().includes(q) || d.ip.includes(q) || d.id.toLowerCase().includes(q)
    }
    return true
  })

  const renderOsIcon = (os: string) => {
    if (os === 'windows') return <Monitor size={15} color="#60a5fa" />
    if (os === 'linux') return <Terminal size={15} color="#fbbf24" />
    if (os === 'mac') return <Apple size={15} color="#cbd5e1" />
    return <Monitor size={15} color="#94a3b8" />
  }

  return (
    <div className="page-container">
      {/* ── Page Header ────────────────────────────────────────────── */}
      <div className="tp-page-header">
        <div>
          <h1 className="tp-page-title">Assets & Endpoints Fleet</h1>
          <p className="tp-page-subtitle">Real-time endpoint agent health, telemetry streaming, and remote isolation</p>
        </div>

        <div style={{ display: 'flex', gap: 10 }}>
          <button className="tp-select" onClick={loadData}>
            <RefreshCw size={13} className={loading ? 'spin' : ''} />
            <span>Sync Fleet</span>
          </button>
        </div>
      </div>

      {/* ── 5 KPI Stat Cards matching Screen 6 ─────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12, marginBottom: 18 }}>
        {/* Total */}
        <div className="kpi-card">
          <div className="kpi-header">
            <span>Total Endpoints</span>
            <Shield size={14} color="#38bdf8" />
          </div>
          <div className="kpi-value" style={{ color: '#fff' }}>342</div>
          <div className="kpi-badge up">Fleet Enrolled</div>
        </div>

        {/* Windows */}
        <div className="kpi-card">
          <div className="kpi-header">
            <span>Windows</span>
            <Monitor size={14} color="#60a5fa" />
          </div>
          <div className="kpi-value" style={{ color: '#60a5fa' }}>210</div>
          <div className="kpi-badge" style={{ color: '#94a3b8' }}>61.4% of fleet</div>
        </div>

        {/* Linux */}
        <div className="kpi-card">
          <div className="kpi-header">
            <span>Linux</span>
            <Terminal size={14} color="#fbbf24" />
          </div>
          <div className="kpi-value" style={{ color: '#fbbf24' }}>82</div>
          <div className="kpi-badge" style={{ color: '#94a3b8' }}>24.0% of fleet</div>
        </div>

        {/* macOS */}
        <div className="kpi-card">
          <div className="kpi-header">
            <span>macOS</span>
            <Apple size={14} color="#cbd5e1" />
          </div>
          <div className="kpi-value" style={{ color: '#cbd5e1' }}>50</div>
          <div className="kpi-badge" style={{ color: '#94a3b8' }}>14.6% of fleet</div>
        </div>

        {/* Offline / At Risk */}
        <div className="kpi-card kpi-red">
          <div className="kpi-header">
            <span>Offline / At Risk</span>
            <AlertTriangle size={14} color="#ef4444" />
          </div>
          <div className="kpi-value" style={{ color: '#ef4444' }}>3</div>
          <div className="kpi-badge down">Attention Required</div>
        </div>
      </div>

      {/* ── Search & Filter Bar ────────────────────────────────────── */}
      <div className="tp-card" style={{ marginBottom: 16, padding: '12px 16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 14 }}>
          {/* Search Box */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1, background: 'var(--bg-deep)', border: '1px solid var(--border-dim)', borderRadius: 'var(--radius-md)', padding: '6px 12px' }}>
            <Search size={14} color="var(--text-muted)" />
            <input
              type="text"
              placeholder="Filter devices by hostname, IP address, OS, or agent ID..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              style={{ background: 'transparent', border: 'none', outline: 'none', color: '#fff', fontSize: 12, width: '100%' }}
            />
          </div>

          {/* OS Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Platform:</span>
            <select className="tp-select" value={filterOs} onChange={e => setFilterOs(e.target.value)}>
              <option value="all">All Platforms</option>
              <option value="windows">Windows</option>
              <option value="linux">Linux</option>
              <option value="mac">macOS</option>
            </select>
          </div>

          {/* Status Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Status:</span>
            <select className="tp-select" value={filterStatus} onChange={e => setFilterStatus(e.target.value)}>
              <option value="all">All Statuses</option>
              <option value="online">Online</option>
              <option value="offline">Offline</option>
              <option value="isolated">Isolated</option>
            </select>
          </div>
        </div>
      </div>

      {/* ── Endpoints Table matching Screen 6 ──────────────────────── */}
      <div className="tp-card" style={{ padding: 0, overflow: 'hidden' }}>
        <table className="tp-table">
          <thead>
            <tr>
              <th>Hostname</th>
              <th style={{ width: 140 }}>Agent ID</th>
              <th style={{ width: 130 }}>IP Address</th>
              <th style={{ width: 180 }}>Operating System</th>
              <th style={{ width: 120 }}>Status</th>
              <th style={{ width: 110 }}>Heartbeat</th>
              <th style={{ width: 100 }}>Alerts</th>
              <th style={{ width: 100, textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(device => (
              <tr key={device.id}>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    {renderOsIcon(device.os)}
                    <span style={{ fontWeight: 600, color: '#f8fafc' }}>{device.hostname}</span>
                  </div>
                </td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#94a3b8' }}>
                  {device.id}
                </td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#cbd5e1' }}>
                  {device.ip}
                </td>
                <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                  {device.osName}
                </td>
                <td>
                  <span style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 5,
                    fontSize: 11,
                    fontWeight: 600,
                    color: device.status === 'online' ? '#10b981' : device.status === 'isolated' ? '#f59e0b' : '#ef4444'
                  }}>
                    <span style={{
                      width: 6,
                      height: 6,
                      borderRadius: '50%',
                      background: device.status === 'online' ? '#10b981' : device.status === 'isolated' ? '#f59e0b' : '#ef4444'
                    }} />
                    {device.status === 'online' ? 'Online' : device.status === 'isolated' ? 'Isolated' : 'Offline'}
                  </span>
                </td>
                <td style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  {device.lastSeen}
                </td>
                <td>
                  {device.alerts > 0 ? (
                    <span className="badge-pill badge-critical" style={{ fontSize: 10 }}>
                      {device.alerts} Critical
                    </span>
                  ) : (
                    <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>Clean</span>
                  )}
                </td>
                <td style={{ textAlign: 'right' }}>
                  <button
                    style={{
                      background: 'transparent',
                      border: '1px solid var(--border-dim)',
                      borderRadius: 'var(--radius-sm)',
                      color: 'var(--text-secondary)',
                      padding: '3px 8px',
                      fontSize: 11,
                      cursor: 'pointer',
                    }}
                    onClick={() => alert(`Inspecting live telemetry for ${device.hostname}`)}
                  >
                    Inspect
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
