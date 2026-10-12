import { useState } from 'react'
import {
  FileText, Download, BarChart2, Shield, Clock, TrendingUp,
  Calendar, CheckCircle2, ChevronDown
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend
} from 'recharts'

const MONTHLY_ALERTS_DATA = [
  { week: 'Week 1', critical: 32, high: 64, medium: 140, low: 90 },
  { week: 'Week 2', critical: 24, high: 78, medium: 165, low: 110 },
  { week: 'Week 3', critical: 45, high: 92, medium: 190, low: 130 },
  { week: 'Week 4', critical: 28, high: 60, medium: 155, low: 95 },
]

const MITRE_RANKING_DATA = [
  { name: 'T1059.001 PowerShell Execution', hits: 142, color: '#ef4444' },
  { name: 'T1003.001 LSASS Memory Dumping', hits: 98, color: '#f97316' },
  { name: 'T1071.001 Web Protocols (C2)', hits: 84, color: '#eab308' },
  { name: 'T1053.005 Scheduled Tasks', hits: 65, color: '#06b6d4' },
  { name: 'T1021.001 Remote Desktop Protocol', hits: 48, color: '#6366f1' },
  { name: 'T1218.011 Rundll32 Execution', hits: 36, color: '#ec4899' },
]

export default function ReportsView() {
  const [downloading, setDownloading] = useState(false)
  const [downloaded, setDownloaded] = useState(false)

  const handleDownload = () => {
    setDownloading(true)
    setTimeout(() => {
      setDownloading(false)
      setDownloaded(true)
      setTimeout(() => setDownloaded(false), 3000)
    }, 1200)
  }

  return (
    <div className="page-container">
      {/* ── Page Header ────────────────────────────────────────────── */}
      <div className="tp-page-header">
        <div>
          <h1 className="tp-page-title">SOC Reports & Threat Analytics</h1>
          <p className="tp-page-subtitle">Executive compliance, detection velocity, and MITRE ATT&CK coverage metrics</p>
        </div>

        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <div className="tp-select">
            <Calendar size={13} color="var(--text-muted)" />
            <span>This Month (October 2026)</span>
            <ChevronDown size={14} color="var(--text-muted)" />
          </div>

          <button
            onClick={handleDownload}
            style={{
              background: 'var(--magenta)',
              color: '#fff',
              border: 'none',
              borderRadius: 'var(--radius-md)',
              padding: '6px 14px',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              boxShadow: '0 0 10px var(--magenta-glow)'
            }}
          >
            <Download size={13} />
            <span>{downloading ? 'Compiling PDF...' : downloaded ? 'Report Generated!' : 'Generate Executive PDF'}</span>
          </button>
        </div>
      </div>

      {/* ── 4 KPI Summary Cards matching Screen 7 ──────────────────── */}
      <div className="kpi-grid-4">
        {/* Total Alerts */}
        <div className="kpi-card">
          <div className="kpi-header">
            <span>Total Alerts Processed</span>
            <FileText size={14} color="#38bdf8" />
          </div>
          <div className="kpi-value-row">
            <div className="kpi-value">2.4K</div>
            <div className="kpi-badge up">+8.2% MoM</div>
          </div>
        </div>

        {/* MITRE Coverage */}
        <div className="kpi-card">
          <div className="kpi-header">
            <span>MITRE Techniques Detected</span>
            <Shield size={14} color="#ec4899" />
          </div>
          <div className="kpi-value-row">
            <div className="kpi-value" style={{ color: '#ec4899' }}>86</div>
            <div className="kpi-badge" style={{ color: '#94a3b8' }}>74% Framework Coverage</div>
          </div>
        </div>

        {/* MTTD */}
        <div className="kpi-card kpi-green">
          <div className="kpi-header">
            <span>Mean Time to Detect (MTTD)</span>
            <Clock size={14} color="#10b981" />
          </div>
          <div className="kpi-value-row">
            <div className="kpi-value" style={{ color: '#10b981' }}>12m</div>
            <div className="kpi-badge up">-4m improvement</div>
          </div>
        </div>

        {/* MTTR */}
        <div className="kpi-card kpi-green">
          <div className="kpi-header">
            <span>Mean Time to Respond (MTTR)</span>
            <TrendingUp size={14} color="#10b981" />
          </div>
          <div className="kpi-value-row">
            <div className="kpi-value" style={{ color: '#10b981' }}>28m</div>
            <div className="kpi-badge up">-15m improvement</div>
          </div>
        </div>
      </div>

      {/* ── Two Main Charts matching Screen 7 ──────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.1fr 1fr', gap: 18 }}>
        {/* Chart 1: Alerts Over Time (Stacked Bars) */}
        <div className="tp-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
            <div>
              <h3 style={{ fontSize: 13, fontWeight: 600, color: '#f1f5f9' }}>Alerts Volume Over Time</h3>
              <p style={{ fontSize: 11, color: 'var(--text-muted)' }}>Weekly breakdown categorized by severity level</p>
            </div>
            <div style={{ display: 'flex', gap: 10, fontSize: 11 }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#cbd5e1' }}>
                <span style={{ width: 7, height: 7, borderRadius: 2, background: '#ef4444' }} /> Critical
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#cbd5e1' }}>
                <span style={{ width: 7, height: 7, borderRadius: 2, background: '#f97316' }} /> High
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#cbd5e1' }}>
                <span style={{ width: 7, height: 7, borderRadius: 2, background: '#eab308' }} /> Medium
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#cbd5e1' }}>
                <span style={{ width: 7, height: 7, borderRadius: 2, background: '#06b6d4' }} /> Low
              </span>
            </div>
          </div>

          <div style={{ height: 260, width: '100%' }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={MONTHLY_ALERTS_DATA} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid stroke="rgba(255,255,255,0.05)" vertical={false} />
                <XAxis dataKey="week" tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{ background: '#12151f', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 6, fontSize: 11 }}
                  itemStyle={{ color: '#fff' }}
                />
                <Bar dataKey="critical" stackId="a" fill="#ef4444" radius={[0, 0, 0, 0]} isAnimationActive={false} />
                <Bar dataKey="high" stackId="a" fill="#f97316" radius={[0, 0, 0, 0]} isAnimationActive={false} />
                <Bar dataKey="medium" stackId="a" fill="#eab308" radius={[0, 0, 0, 0]} isAnimationActive={false} />
                <Bar dataKey="low" stackId="a" fill="#06b6d4" radius={[4, 4, 0, 0]} isAnimationActive={false} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Chart 2: Top MITRE ATT&CK Techniques Horizontal Bars */}
        <div className="tp-card">
          <div style={{ marginBottom: 16 }}>
            <h3 style={{ fontSize: 13, fontWeight: 600, color: '#f1f5f9' }}>Top Observed MITRE Techniques</h3>
            <p style={{ fontSize: 11, color: 'var(--text-muted)' }}>Ranked by detection frequency across all endpoints</p>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            {MITRE_RANKING_DATA.map((item, idx) => (
              <div key={idx}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 5 }}>
                  <span style={{ fontWeight: 600, color: '#fff' }}>{item.name}</span>
                  <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>{item.hits} detections</span>
                </div>
                {/* Horizontal Progress Bar */}
                <div style={{ height: 7, width: '100%', background: 'var(--bg-deep)', borderRadius: 99, overflow: 'hidden' }}>
                  <div
                    style={{
                      height: '100%',
                      width: `${(item.hits / 142) * 100}%`,
                      background: item.color,
                      borderRadius: 99
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
