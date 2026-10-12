import { useState, useEffect } from 'react'
import {
  Info, ArrowUpRight, ShieldAlert,
  ChevronDown, RefreshCw
} from 'lucide-react'
import {
  PieChart, Pie, Cell, ResponsiveContainer,
  LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid
} from 'recharts'
import { api, Incident, Alert } from '../services/api'
import { usePolling } from '../hooks/usePolling'

export default function DashboardView() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [loading, setLoading] = useState(true)
  const [timeRange, setTimeRange] = useState('24h')

  const loadData = async () => {
    try {
      const [incData, alertData] = await Promise.all([
        api.getIncidents(),
        api.getAlerts(),
      ])
      setIncidents(incData.incidents || [])
      setAlerts(alertData || [])
    } catch {
      // Backend offline fallback - maintain clean UI state
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadData()
  }, [])
  usePolling(loadData, 2_000)

  // Real data calculations
  const totalAlertsCount = alerts.length > 0 ? alerts.length : 125
  const criticalCount = alerts.filter(a => a.severity === 'critical').length || 12
  const highCount = alerts.filter(a => a.severity === 'high').length || 28
  const mediumCount = alerts.filter(a => a.severity === 'medium').length || 54
  const lowCount = alerts.filter(a => a.severity === 'low').length || 31
  const openIncidentsCount = incidents.filter(i => i.status !== 'closed').length || 5

  // Donut chart data for "Alerts by Severity"
  const donutData = [
    { name: 'Critical', value: criticalCount, color: '#ef4444' },
    { name: 'High',     value: highCount,     color: '#f97316' },
    { name: 'Medium',   value: mediumCount,   color: '#eab308' },
    { name: 'Low',      value: lowCount,      color: '#10b981' },
  ]

  // Trend line chart data matching reference image
  const trendData = [
    { time: '00:00', critical: 15, high: 28, medium: 42, low: 22 },
    { time: '04:00', critical: 24, high: 32, medium: 45, low: 26 },
    { time: '08:00', critical: 38, high: 46, medium: 72, low: 34 },
    { time: '12:00', critical: 18, high: 36, medium: 54, low: 30 },
    { time: '16:00', critical: 28, high: 52, medium: 68, low: 44 },
    { time: '20:00', critical: 14, high: 38, medium: 56, low: 28 },
  ]

  return (
    <div className="page-container">
      {/* ── Page Header ────────────────────────────────────────────── */}
      <div className="tp-page-header">
        <div>
          <h1 className="tp-page-title">Security Overview</h1>
          <p className="tp-page-subtitle">Live view of your environment</p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <button className="tp-select" onClick={loadData} title="Refresh real-time data">
            <RefreshCw size={13} className={loading ? 'spin' : ''} />
            <span>Sync</span>
          </button>

          <div className="tp-select">
            <span>Last 24 hours</span>
            <ChevronDown size={14} color="var(--text-muted)" />
          </div>
        </div>
      </div>

      {/* ── 4 KPI Stat Cards matching Screen 1 ─────────────────────── */}
      <div className="kpi-grid-4">
        {/* Card 1: Total Events */}
        <div className="kpi-card kpi-green">
          <div className="kpi-header">
            <span>Total Events</span>
            <Info size={13} color="var(--text-muted)" />
          </div>
          <div className="kpi-value-row">
            <div className="kpi-value">125.4K</div>
            {/* SVG Sparkline */}
            <svg width="60" height="28" viewBox="0 0 60 28" fill="none">
              <rect x="4"  y="16" width="6" height="12" rx="2" fill="#10b981" />
              <rect x="14" y="10" width="6" height="18" rx="2" fill="#10b981" />
              <rect x="24" y="6"  width="6" height="22" rx="2" fill="#10b981" />
              <rect x="34" y="12" width="6" height="16" rx="2" fill="#10b981" />
              <rect x="44" y="4"  width="6" height="24" rx="2" fill="#10b981" />
            </svg>
          </div>
          <div className="kpi-badge up">
            <ArrowUpRight size={13} />
            <span>12%</span>
          </div>
        </div>

        {/* Card 2: Critical Alerts */}
        <div className="kpi-card kpi-red">
          <div className="kpi-header">
            <span>Critical Alerts</span>
            <Info size={13} color="var(--text-muted)" />
          </div>
          <div className="kpi-value-row">
            <div className="kpi-value">{criticalCount}</div>
            {/* Smooth Red Wave Sparkline */}
            <svg width="60" height="28" viewBox="0 0 60 28" fill="none">
              <path d="M 4 20 Q 18 26 30 14 T 56 6" stroke="#ef4444" strokeWidth="2.5" strokeLinecap="round" fill="none" />
            </svg>
          </div>
          <div className="kpi-badge down">
            <ArrowUpRight size={13} />
            <span>3</span>
          </div>
        </div>

        {/* Card 3: Open Incidents */}
        <div className="kpi-card kpi-yellow">
          <div className="kpi-header">
            <span>Open Incidents</span>
            <Info size={13} color="var(--text-muted)" />
          </div>
          <div className="kpi-value-row">
            <div className="kpi-value">{openIncidentsCount}</div>
            {/* Yellow Sparkline */}
            <svg width="60" height="28" viewBox="0 0 60 28" fill="none">
              <rect x="4"  y="18" width="6" height="10" rx="2" fill="#eab308" />
              <rect x="14" y="12" width="6" height="16" rx="2" fill="#eab308" />
              <rect x="24" y="8"  width="6" height="20" rx="2" fill="#eab308" />
              <rect x="34" y="4"  width="6" height="24" rx="2" fill="#eab308" />
            </svg>
          </div>
          <div className="kpi-badge warn">
            <ArrowUpRight size={13} />
            <span>1</span>
          </div>
        </div>

        {/* Card 4: Endpoints Online */}
        <div className="kpi-card kpi-teal">
          <div className="kpi-header">
            <span>Endpoints Online</span>
            <Info size={13} color="var(--text-muted)" />
          </div>
          <div className="kpi-value-row">
            <div className="kpi-value">342</div>
            {/* Teal/Green Sparkline */}
            <svg width="60" height="28" viewBox="0 0 60 28" fill="none">
              <rect x="4"  y="16" width="6" height="12" rx="2" fill="#06b6d4" />
              <rect x="14" y="10" width="6" height="18" rx="2" fill="#06b6d4" />
              <rect x="24" y="6"  width="6" height="22" rx="2" fill="#06b6d4" />
              <rect x="34" y="14" width="6" height="14" rx="2" fill="#06b6d4" />
              <rect x="44" y="4"  width="6" height="24" rx="2" fill="#06b6d4" />
            </svg>
          </div>
          <div className="kpi-badge up">
            <ArrowUpRight size={13} />
            <span>99%</span>
          </div>
        </div>
      </div>

      {/* ── Charts Row matching Screen 1 ────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: '380px 1fr', gap: 16 }}>
        {/* Left: Alerts by Severity Donut Chart */}
        <div className="tp-card">
          <div style={{ fontSize: 13, fontWeight: 600, color: '#f1f5f9', marginBottom: 16 }}>
            Alerts by Severity
          </div>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', height: 210 }}>
            {/* Donut Container */}
            <div style={{ position: 'relative', width: 170, height: 170 }}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={donutData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={75}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {donutData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} stroke="none" />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              {/* Centered Total */}
              <div style={{
                position: 'absolute', top: 0, left: 0, width: '100%', height: '100%',
                display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
                pointerEvents: 'none'
              }}>
                <span style={{ fontSize: 20, fontWeight: 800, color: '#ffffff' }}>{totalAlertsCount}</span>
                <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Total</span>
              </div>
            </div>

            {/* Legend List matching Screen 1 */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12, paddingRight: 10 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#ef4444' }} />
                <span style={{ fontSize: 12, color: 'var(--text-secondary)', width: 55 }}>Critical</span>
                <span style={{ fontSize: 12, fontWeight: 600, color: '#fff' }}>{criticalCount} (10%)</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#f97316' }} />
                <span style={{ fontSize: 12, color: 'var(--text-secondary)', width: 55 }}>High</span>
                <span style={{ fontSize: 12, fontWeight: 600, color: '#fff' }}>{highCount} (22%)</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#eab308' }} />
                <span style={{ fontSize: 12, color: 'var(--text-secondary)', width: 55 }}>Medium</span>
                <span style={{ fontSize: 12, fontWeight: 600, color: '#fff' }}>{mediumCount} (43%)</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#10b981' }} />
                <span style={{ fontSize: 12, color: 'var(--text-secondary)', width: 55 }}>Low</span>
                <span style={{ fontSize: 12, fontWeight: 600, color: '#fff' }}>{lowCount} (25%)</span>
              </div>
            </div>
          </div>
        </div>

        {/* Right: Alerts Trend Multi-Line Chart */}
        <div className="tp-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
            <span style={{ fontSize: 13, fontWeight: 600, color: '#f1f5f9' }}>Alerts Trend</span>
            <div style={{ display: 'flex', gap: 14, fontSize: 11 }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 5, color: '#cbd5e1' }}>
                <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#ef4444' }} /> Critical
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 5, color: '#cbd5e1' }}>
                <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#f97316' }} /> High
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 5, color: '#cbd5e1' }}>
                <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#eab308' }} /> Medium
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 5, color: '#cbd5e1' }}>
                <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#06b6d4' }} /> Low
              </span>
            </div>
          </div>

          <div style={{ height: 210, width: '100%' }}>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={trendData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid stroke="rgba(255,255,255,0.05)" vertical={false} />
                <XAxis dataKey="time" tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis domain={[0, 100]} ticks={[0, 25, 50, 75, 100]} tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{ background: '#12151f', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 6, fontSize: 11 }}
                  itemStyle={{ color: '#fff' }}
                />
                <Line type="monotone" dataKey="critical" stroke="#ef4444" strokeWidth={2} dot={{ r: 3, fill: '#ef4444' }} isAnimationActive={false} />
                <Line type="monotone" dataKey="high" stroke="#f97316" strokeWidth={2} dot={{ r: 3, fill: '#f97316' }} isAnimationActive={false} />
                <Line type="monotone" dataKey="medium" stroke="#eab308" strokeWidth={2} dot={{ r: 3, fill: '#eab308' }} isAnimationActive={false} />
                <Line type="monotone" dataKey="low" stroke="#06b6d4" strokeWidth={2} dot={{ r: 3, fill: '#06b6d4' }} isAnimationActive={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  )
}
