/**
 * Enterprise Fleet Management (100+ Real PCs & Servers).
 * Real-time asset inventory, health monitoring, and active endpoint containment actions.
 */
import { useState, useEffect } from 'react'
import {
  Server, Laptop, Database, Cpu, ShieldAlert, ShieldCheck,
  Search, RefreshCw, Filter, CheckCircle2, AlertTriangle,
  Play, Lock, Unlock, Zap, Terminal, X, ArrowRight, Eye, Grid, List
} from 'lucide-react'
import { api, FleetDevice, DeviceActionAudit, FleetStats } from '../services/api'
import { useToast } from '../components/Toast'
import { usePolling } from '../hooks/usePolling'

export default function FleetPage() {
  const [devices, setDevices] = useState<FleetDevice[]>([])
  const [stats, setStats] = useState<FleetStats | null>(null)
  const [auditLogs, setAuditLogs] = useState<DeviceActionAudit[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedDevice, setSelectedDevice] = useState<FleetDevice | null>(null)
  const [deviceDetail, setDeviceDetail] = useState<any | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [viewMode, setViewMode] = useState<'table' | 'grid'>('table')
  const [activeTab, setActiveTab] = useState<'fleet' | 'audit'>('fleet')

  // Filters
  const [search, setSearch] = useState('')
  const [department, setDepartment] = useState('')
  const [osFilter, setOsFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [containmentFilter, setContainmentFilter] = useState('')

  // Multi-select bulk actions
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [actionLoading, setActionLoading] = useState<string | null>(null)

  const toast = useToast()

  const loadData = async () => {
    setLoading(true)
    try {
      const [devData, statsData, auditData] = await Promise.all([
        api.getFleetDevices({
          search: search || undefined,
          department: department || undefined,
          os: osFilter || undefined,
          status: statusFilter || undefined,
          containment_status: containmentFilter || undefined,
          limit: 200,
        }),
        api.getFleetStats(),
        api.getFleetActionAudit(),
      ])
      setDevices(devData.devices)
      setStats(statsData)
      setAuditLogs(auditData)
    } catch {
      toast.error('Failed loading fleet data')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadData()
  }, [search, department, osFilter, statusFilter, containmentFilter])
  usePolling(loadData, 2_000)

  const openInspector = async (dev: FleetDevice) => {
    setSelectedDevice(dev)
    setDetailLoading(true)
    try {
      const detail = await api.getFleetDevice(dev.id)
      setDeviceDetail(detail)
    } catch {
      toast.error('Failed fetching device telemetry')
    } finally {
      setDetailLoading(false)
    }
  }

  const handleAction = async (devId: string, actionName: string, target?: string) => {
    setActionLoading(`${devId}-${actionName}`)
    try {
      const res = await api.executeDeviceAction(devId, actionName, target)
      toast.success(res.message)
      // Update device in list
      setDevices(prev => prev.map(d => d.id === devId ? res.device : d))
      if (selectedDevice?.id === devId) {
        setSelectedDevice(res.device)
      }
      // Refresh audit logs
      api.getFleetActionAudit().then(setAuditLogs)
      api.getFleetStats().then(setStats)
    } catch {
      toast.error(`Action ${actionName} failed`)
    } finally {
      setActionLoading(null)
    }
  }

  const handleBulkAction = async (actionName: string) => {
    if (selectedIds.size === 0) return
    const ids = Array.from(selectedIds)
    setActionLoading(`bulk-${actionName}`)
    try {
      const res = await api.executeBulkAction(ids, actionName)
      toast.success(`Bulk ${actionName} executed on ${res.affected_count} endpoints!`)
      setSelectedIds(new Set())
      loadData()
    } catch {
      toast.error('Bulk action failed')
    } finally {
      setActionLoading(null)
    }
  }

  const toggleSelect = (id: string) => {
    setSelectedIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const toggleSelectAll = () => {
    if (selectedIds.size === devices.length) {
      setSelectedIds(new Set())
    } else {
      setSelectedIds(new Set(devices.map(d => d.id)))
    }
  }

  const getDeviceIcon = (type: string) => {
    if (type === 'domain_controller' || type === 'server') return Server
    if (type === 'database') return Database
    return Laptop
  }

  return (
    <div className="fade-in">
      {/* ── Header ──────────────────────────────────────────────────────── */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Enterprise Fleet Management</h1>
          <p className="page-subtitle">
            Active monitoring and host containment execution across 100+ enterprise PCs and servers
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <div style={{ display: 'flex', background: 'var(--bg-deep)', borderRadius: 8, padding: 3, border: '1px solid var(--border-dim)' }}>
            <button
              onClick={() => setActiveTab('fleet')}
              style={{
                background: activeTab === 'fleet' ? 'var(--bg-raised)' : 'transparent',
                color: activeTab === 'fleet' ? 'var(--text-accent)' : 'var(--text-muted)',
                border: activeTab === 'fleet' ? '1px solid var(--border-bright)' : 'none',
                borderRadius: 6, padding: '4px 12px', fontSize: 12, fontWeight: 600, cursor: 'pointer'
              }}
            >
              Fleet Inventory ({devices.length})
            </button>
            <button
              onClick={() => setActiveTab('audit')}
              style={{
                background: activeTab === 'audit' ? 'var(--bg-raised)' : 'transparent',
                color: activeTab === 'audit' ? 'var(--text-accent)' : 'var(--text-muted)',
                border: activeTab === 'audit' ? '1px solid var(--border-bright)' : 'none',
                borderRadius: 6, padding: '4px 12px', fontSize: 12, fontWeight: 600, cursor: 'pointer'
              }}
            >
              Action Audit Trail ({auditLogs.length})
            </button>
          </div>
          <button className="btn btn-ghost" style={{ fontSize: 11 }} onClick={loadData} disabled={loading}>
            <RefreshCw size={11} /> Refresh
          </button>
        </div>
      </div>

      {/* ── KPI Cards ────────────────────────────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 14, marginBottom: 20 }}>
        {[
          { label: 'Total Endpoints', value: stats?.total_devices ?? 110, icon: Server, color: 'var(--text-accent)' },
          { label: 'Active Telemetry', value: stats?.online_count ?? 106, icon: CheckCircle2, color: 'var(--low)' },
          { label: 'Isolated Devices', value: stats?.isolated_count ?? 2, icon: Lock, color: 'var(--critical)' },
          { label: 'High Risk Endpoints', value: stats?.high_risk_count ?? 3, icon: AlertTriangle, color: 'var(--high)' },
          { label: 'Stream Rate', value: `${stats?.events_per_sec ?? 1420} EPS`, icon: Zap, color: 'var(--medium)' },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="card" style={{ padding: '14px 18px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700, marginBottom: 4 }}>
                  {label}
                </div>
                <div style={{ fontSize: 24, fontWeight: 800, color, fontFamily: 'var(--font-mono)' }}>
                  {value}
                </div>
              </div>
              <div style={{ width: 32, height: 32, borderRadius: 8, background: `color-mix(in srgb, ${color} 15%, transparent)`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Icon size={16} color={color} />
              </div>
            </div>
          </div>
        ))}
      </div>

      {activeTab === 'fleet' ? (
        <>
          {/* ── Filters & Controls ────────────────────────────────────────── */}
          <div className="card" style={{ padding: '12px 16px', marginBottom: 16 }}>
            <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
              {/* Search */}
              <div style={{ display: 'flex', alignItems: 'center', background: 'var(--bg-deep)', padding: '6px 12px', borderRadius: 6, border: '1px solid var(--border-dim)', flex: 1, minWidth: 220 }}>
                <Search size={14} color="var(--text-muted)" style={{ marginRight: 8 }} />
                <input
                  type="text"
                  placeholder="Search 100+ hosts, IP, user, department..."
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  style={{ background: 'none', border: 'none', color: '#fff', fontSize: 12, outline: 'none', width: '100%' }}
                />
                {search && <button onClick={() => setSearch('')} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>✕</button>}
              </div>

              {/* Department Dropdown */}
              <select
                value={department}
                onChange={e => setDepartment(e.target.value)}
                style={{ background: 'var(--bg-deep)', border: '1px solid var(--border-dim)', color: 'var(--text-secondary)', padding: '6px 10px', borderRadius: 6, fontSize: 12 }}
              >
                <option value="">All Departments</option>
                <option value="Engineering">Engineering (25)</option>
                <option value="Finance">Finance (15)</option>
                <option value="Human Resources">Human Resources (10)</option>
                <option value="Executive">Executive (5)</option>
                <option value="Identity">IAM & Domain Controllers (4)</option>
                <option value="Cloud">Cloud & Production (20)</option>
                <option value="Data">Data Infrastructure (6)</option>
                <option value="Container">Kubernetes Nodes (10)</option>
              </select>

              {/* Status Filter */}
              <select
                value={containmentFilter}
                onChange={e => setContainmentFilter(e.target.value)}
                style={{ background: 'var(--bg-deep)', border: '1px solid var(--border-dim)', color: 'var(--text-secondary)', padding: '6px 10px', borderRadius: 6, fontSize: 12 }}
              >
                <option value="">All Containment States</option>
                <option value="normal">Normal (Connected)</option>
                <option value="isolated">Isolated (Contained)</option>
              </select>

              {/* View Toggle */}
              <div style={{ display: 'flex', background: 'var(--bg-deep)', borderRadius: 6, border: '1px solid var(--border-dim)', padding: 2, marginLeft: 'auto' }}>
                <button
                  onClick={() => setViewMode('table')}
                  style={{ background: viewMode === 'table' ? 'var(--bg-raised)' : 'transparent', border: 'none', color: viewMode === 'table' ? 'var(--text-accent)' : 'var(--text-muted)', padding: '4px 8px', borderRadius: 4, cursor: 'pointer' }}
                  title="Table View"
                >
                  <List size={14} />
                </button>
                <button
                  onClick={() => setViewMode('grid')}
                  style={{ background: viewMode === 'grid' ? 'var(--bg-raised)' : 'transparent', border: 'none', color: viewMode === 'grid' ? 'var(--text-accent)' : 'var(--text-muted)', padding: '4px 8px', borderRadius: 4, cursor: 'pointer' }}
                  title="Grid Visualizer"
                >
                  <Grid size={14} />
                </button>
              </div>
            </div>

            {/* Bulk Action Toolbar */}
            {selectedIds.size > 0 && (
              <div style={{ marginTop: 12, paddingTop: 10, borderTop: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', gap: 12 }}>
                <span style={{ fontSize: 12, color: 'var(--text-accent)', fontWeight: 600 }}>
                  {selectedIds.size} endpoints selected
                </span>
                <button
                  onClick={() => handleBulkAction('isolate_host')}
                  className="btn"
                  style={{ background: 'rgba(239, 68, 68, 0.2)', color: 'var(--critical)', border: '1px solid var(--critical)', fontSize: 11, padding: '4px 10px' }}
                >
                  <Lock size={12} /> Bulk Isolate
                </button>
                <button
                  onClick={() => handleBulkAction('unisolate_host')}
                  className="btn"
                  style={{ background: 'rgba(34, 197, 94, 0.2)', color: 'var(--low)', border: '1px solid var(--low)', fontSize: 11, padding: '4px 10px' }}
                >
                  <Unlock size={12} /> Bulk Un-isolate
                </button>
                <button
                  onClick={() => handleBulkAction('run_threat_scan')}
                  className="btn btn-ghost"
                  style={{ fontSize: 11, padding: '4px 10px' }}
                >
                  <Search size={12} /> Bulk Threat Scan
                </button>
                <button
                  onClick={() => setSelectedIds(new Set())}
                  style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: 11, cursor: 'pointer', marginLeft: 'auto' }}
                >
                  Clear Selection
                </button>
              </div>
            )}
          </div>

          {/* ── Devices Layout ────────────────────────────────────────────── */}
          <div style={{ display: 'grid', gridTemplateColumns: selectedDevice ? '1fr 400px' : '1fr', gap: 16 }}>
            {viewMode === 'table' ? (
              <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th style={{ width: 30 }}>
                        <input
                          type="checkbox"
                          checked={selectedIds.size === devices.length && devices.length > 0}
                          onChange={toggleSelectAll}
                        />
                      </th>
                      <th>Device / Hostname</th>
                      <th>IP & Mac</th>
                      <th>Department</th>
                      <th>Assigned User</th>
                      <th>OS Platform</th>
                      <th>Risk Score</th>
                      <th>Status</th>
                      <th>Containment</th>
                      <th style={{ textAlign: 'right' }}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {devices.map(dev => {
                      const Icon = getDeviceIcon(dev.device_type)
                      const isIsolated = dev.containment_status === 'isolated'
                      return (
                        <tr
                          key={dev.id}
                          style={{
                            cursor: 'pointer',
                            background: selectedDevice?.id === dev.id ? 'var(--bg-raised)' : isIsolated ? 'rgba(239, 68, 68, 0.05)' : '',
                          }}
                          onClick={() => openInspector(dev)}
                        >
                          <td onClick={e => e.stopPropagation()}>
                            <input
                              type="checkbox"
                              checked={selectedIds.has(dev.id)}
                              onChange={() => toggleSelect(dev.id)}
                            />
                          </td>
                          <td>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                              <div style={{ width: 26, height: 26, borderRadius: 6, background: 'var(--bg-deep)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                                <Icon size={14} color={isIsolated ? 'var(--critical)' : dev.risk_score >= 60 ? 'var(--high)' : 'var(--text-accent)'} />
                              </div>
                              <div>
                                <div style={{ fontWeight: 700, color: 'var(--text-primary)', fontSize: 13 }}>{dev.hostname}</div>
                                <div style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{dev.device_type}</div>
                              </div>
                            </div>
                          </td>
                          <td>
                            <div className="mono" style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{dev.ip_address}</div>
                            <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>{dev.mac_address}</div>
                          </td>
                          <td>
                            <span style={{ fontSize: 11, padding: '2px 8px', borderRadius: 4, background: 'var(--bg-deep)', color: 'var(--text-secondary)' }}>
                              {dev.department}
                            </span>
                          </td>
                          <td>
                            <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{dev.assigned_user || '—'}</span>
                          </td>
                          <td>
                            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{dev.os}</span>
                          </td>
                          <td>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                              <div style={{ width: 40, height: 6, background: 'var(--bg-deep)', borderRadius: 3, overflow: 'hidden' }}>
                                <div style={{ width: `${dev.risk_score}%`, height: '100%', background: dev.risk_score >= 75 ? 'var(--critical)' : dev.risk_score >= 50 ? 'var(--high)' : 'var(--low)' }} />
                              </div>
                              <span className="mono" style={{ fontSize: 11, fontWeight: 700, color: dev.risk_score >= 75 ? 'var(--critical)' : dev.risk_score >= 50 ? 'var(--high)' : 'var(--low)' }}>
                                {dev.risk_score}
                              </span>
                            </div>
                          </td>
                          <td>
                            <span style={{ fontSize: 10, fontWeight: 700, color: dev.status === 'online' ? 'var(--low)' : 'var(--text-muted)' }}>
                              ● {dev.status.toUpperCase()}
                            </span>
                          </td>
                          <td>
                            {isIsolated ? (
                              <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 6px', borderRadius: 4, background: 'rgba(239, 68, 68, 0.2)', color: 'var(--critical)', border: '1px solid var(--critical)' }}>
                                🔒 ISOLATED
                              </span>
                            ) : (
                              <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>Normal</span>
                            )}
                          </td>
                          <td style={{ textAlign: 'right' }} onClick={e => e.stopPropagation()}>
                            <div style={{ display: 'flex', gap: 4, justifyContent: 'flex-end' }}>
                              {isIsolated ? (
                                <button
                                  onClick={() => handleAction(dev.id, 'unisolate_host')}
                                  className="btn btn-ghost"
                                  style={{ padding: '3px 8px', fontSize: 10, color: 'var(--low)' }}
                                  title="Restore Network Connectivity"
                                >
                                  <Unlock size={11} /> Un-isolate
                                </button>
                              ) : (
                                <button
                                  onClick={() => handleAction(dev.id, 'isolate_host')}
                                  className="btn btn-ghost"
                                  style={{ padding: '3px 8px', fontSize: 10, color: 'var(--critical)' }}
                                  title="Isolate Host Firewall"
                                >
                                  <Lock size={11} /> Isolate
                                </button>
                              )}
                              <button
                                onClick={() => openInspector(dev)}
                                className="btn btn-ghost"
                                style={{ padding: '3px 8px', fontSize: 10 }}
                              >
                                <Eye size={11} /> Inspect
                              </button>
                            </div>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              /* Grid View */
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 12 }}>
                {devices.map(dev => {
                  const Icon = getDeviceIcon(dev.device_type)
                  const isIsolated = dev.containment_status === 'isolated'
                  return (
                    <div
                      key={dev.id}
                      className="card"
                      style={{
                        padding: 12,
                        cursor: 'pointer',
                        borderColor: selectedDevice?.id === dev.id ? 'var(--border-bright)' : isIsolated ? 'var(--critical)' : 'var(--border-dim)',
                        background: selectedDevice?.id === dev.id ? 'var(--bg-raised)' : 'var(--bg-surface)',
                      }}
                      onClick={() => openInspector(dev)}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <Icon size={16} color={isIsolated ? 'var(--critical)' : dev.risk_score >= 60 ? 'var(--high)' : 'var(--text-accent)'} />
                          <span style={{ fontWeight: 700, fontSize: 12, color: 'var(--text-primary)' }}>{dev.hostname}</span>
                        </div>
                        <span style={{ fontSize: 9, fontWeight: 700, color: dev.status === 'online' ? 'var(--low)' : 'var(--text-muted)' }}>
                          ● {dev.status.toUpperCase()}
                        </span>
                      </div>

                      <div className="mono" style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 4 }}>{dev.ip_address}</div>
                      <div style={{ fontSize: 10, color: 'var(--text-secondary)', marginBottom: 8 }}>{dev.department}</div>

                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid var(--border-subtle)', paddingTop: 8 }}>
                        <span className="mono" style={{ fontSize: 10, color: dev.risk_score >= 60 ? 'var(--high)' : 'var(--low)' }}>
                          Risk: {dev.risk_score}
                        </span>
                        {isIsolated ? (
                          <span style={{ fontSize: 9, fontWeight: 700, color: 'var(--critical)' }}>🔒 ISOLATED</span>
                        ) : (
                          <button
                            onClick={e => { e.stopPropagation(); handleAction(dev.id, 'isolate_host') }}
                            style={{ background: 'none', border: 'none', color: 'var(--critical)', fontSize: 10, cursor: 'pointer', padding: 0 }}
                          >
                            Isolate
                          </button>
                        )}
                      </div>
                    </div>
                  )
                })}
              </div>
            )}

            {/* ── Slide-over Device Inspector Drawer ────────────────────────── */}
            {selectedDevice && (
              <div className="card fade-in" style={{ padding: 18, border: '1px solid var(--border-bright)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 14 }}>
                  <div>
                    <div style={{ fontSize: 10, textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 700 }}>
                      Endpoint Telemetry Inspector
                    </div>
                    <h2 style={{ fontSize: 16, fontWeight: 800, color: 'var(--text-primary)', marginTop: 2 }}>
                      {selectedDevice.hostname}
                    </h2>
                  </div>
                  <button
                    onClick={() => setSelectedDevice(null)}
                    style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 16 }}
                  >
                    ✕
                  </button>
                </div>

                {/* Quick Action Buttons */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, marginBottom: 16 }}>
                  {selectedDevice.containment_status === 'isolated' ? (
                    <button
                      onClick={() => handleAction(selectedDevice.id, 'unisolate_host')}
                      className="btn"
                      style={{ background: 'rgba(34, 197, 94, 0.2)', color: 'var(--low)', border: '1px solid var(--low)', fontSize: 11 }}
                    >
                      <Unlock size={12} /> Un-isolate Host
                    </button>
                  ) : (
                    <button
                      onClick={() => handleAction(selectedDevice.id, 'isolate_host')}
                      className="btn"
                      style={{ background: 'rgba(239, 68, 68, 0.2)', color: 'var(--critical)', border: '1px solid var(--critical)', fontSize: 11 }}
                    >
                      <Lock size={12} /> Isolate Host
                    </button>
                  )}
                  <button
                    onClick={() => handleAction(selectedDevice.id, 'kill_process', 'powershell.exe')}
                    className="btn btn-ghost"
                    style={{ fontSize: 11 }}
                  >
                    <Zap size={12} /> Kill Process
                  </button>
                  <button
                    onClick={() => handleAction(selectedDevice.id, 'revoke_user_sessions')}
                    className="btn btn-ghost"
                    style={{ fontSize: 11 }}
                  >
                    👤 Revoke User
                  </button>
                  <button
                    onClick={() => handleAction(selectedDevice.id, 'run_threat_scan')}
                    className="btn btn-ghost"
                    style={{ fontSize: 11 }}
                  >
                    🔍 Threat Scan
                  </button>
                </div>

                {/* Device Spec Cards */}
                <div style={{ background: 'var(--bg-deep)', padding: 10, borderRadius: 6, fontSize: 11, marginBottom: 14 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ color: 'var(--text-muted)' }}>IP Address:</span>
                    <span className="mono" style={{ color: 'var(--text-accent)' }}>{selectedDevice.ip_address}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ color: 'var(--text-muted)' }}>Operating System:</span>
                    <span style={{ color: 'var(--text-primary)' }}>{selectedDevice.os}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ color: 'var(--text-muted)' }}>Department:</span>
                    <span style={{ color: 'var(--text-primary)' }}>{selectedDevice.department}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ color: 'var(--text-muted)' }}>Assigned User:</span>
                    <span style={{ color: 'var(--text-primary)' }}>{selectedDevice.assigned_user || 'SYSTEM'}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--text-muted)' }}>Agent Version:</span>
                    <span className="mono" style={{ color: 'var(--low)' }}>{selectedDevice.agent_version}</span>
                  </div>
                </div>

                {/* Live Process Telemetry */}
                <div style={{ marginBottom: 14 }}>
                  <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 6 }}>
                    Active Running Processes
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    {(deviceDetail?.processes || []).map((p: any, idx: number) => (
                      <div
                        key={idx}
                        style={{
                          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                          padding: '6px 8px', borderRadius: 4,
                          background: p.flagged ? 'rgba(239, 68, 68, 0.15)' : 'var(--bg-deep)',
                          border: p.flagged ? '1px solid rgba(239, 68, 68, 0.4)' : '1px solid var(--border-subtle)',
                          fontSize: 10,
                        }}
                      >
                        <div>
                          <span style={{ fontWeight: 700, color: p.flagged ? 'var(--critical)' : 'var(--text-primary)' }}>
                            {p.name}
                          </span>
                          <span className="mono" style={{ color: 'var(--text-muted)', marginLeft: 6 }}>PID {p.pid}</span>
                        </div>
                        {p.flagged ? (
                          <button
                            onClick={() => handleAction(selectedDevice.id, 'kill_process', p.name)}
                            style={{ background: 'var(--critical)', color: '#fff', border: 'none', borderRadius: 4, padding: '2px 6px', fontSize: 9, cursor: 'pointer', fontWeight: 700 }}
                          >
                            KILL
                          </button>
                        ) : (
                          <span style={{ color: 'var(--text-muted)' }}>{p.cpu_pct}% CPU</span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Active Network Connections */}
                <div>
                  <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 6 }}>
                    Open Network Sockets
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    {(deviceDetail?.network_sockets || []).map((s: any, idx: number) => (
                      <div
                        key={idx}
                        style={{
                          padding: '6px 8px', borderRadius: 4,
                          background: s.flagged ? 'rgba(239, 68, 68, 0.15)' : 'var(--bg-deep)',
                          border: s.flagged ? '1px solid rgba(239, 68, 68, 0.4)' : '1px solid var(--border-subtle)',
                          fontSize: 10,
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', color: s.flagged ? 'var(--critical)' : 'var(--text-secondary)' }}>
                          <span className="mono">{s.local} → {s.remote}</span>
                          <span style={{ fontWeight: 700 }}>{s.state}</span>
                        </div>
                        <div style={{ fontSize: 9, color: 'var(--text-muted)', marginTop: 2 }}>Process: {s.process}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        </>
      ) : (
        /* ── Action Audit Trail Tab ─────────────────────────────────────── */
        <div className="card">
          <div className="card-title">Fleet Containment & Action Execution Audit Trail</div>
          <table className="data-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Target Device</th>
                <th>Action</th>
                <th>Target Scope</th>
                <th>Executed By</th>
                <th>Status</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {auditLogs.map((log, idx) => (
                <tr key={idx}>
                  <td className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                    {new Date(log.executed_at).toLocaleTimeString()}
                  </td>
                  <td>
                    <span style={{ fontWeight: 700, color: 'var(--text-primary)', fontSize: 12 }}>
                      {log.hostname}
                    </span>
                  </td>
                  <td>
                    <span style={{
                      fontSize: 10, fontWeight: 700, padding: '2px 6px', borderRadius: 4,
                      background: log.action.includes('isolate') ? 'rgba(239, 68, 68, 0.15)' : 'rgba(56, 189, 248, 0.15)',
                      color: log.action.includes('isolate') ? 'var(--critical)' : 'var(--text-accent)',
                      border: '1px solid currentColor',
                    }}>
                      {log.action.toUpperCase()}
                    </span>
                  </td>
                  <td className="mono" style={{ fontSize: 11 }}>{log.target || '—'}</td>
                  <td><span style={{ fontSize: 11 }}>{log.analyst}</span></td>
                  <td>
                    <span style={{ color: log.status === 'success' ? 'var(--low)' : 'var(--critical)', fontWeight: 700, fontSize: 11 }}>
                      ● {log.status.toUpperCase()}
                    </span>
                  </td>
                  <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                    {log.details ? JSON.stringify(log.details) : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
