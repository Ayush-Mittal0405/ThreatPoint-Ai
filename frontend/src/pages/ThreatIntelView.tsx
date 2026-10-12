import { useState } from 'react'
import {
  Globe, Search, ShieldAlert, AlertTriangle, ShieldCheck,
  ExternalLink, BarChart3, Database, Flag, Clock, CheckCircle2,
  Lock, RefreshCw
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid
} from 'recharts'

const SIGHTINGS_DATA = [
  { day: 'Day 1', sightings: 0 },
  { day: 'Day 2', sightings: 0 },
  { day: 'Day 3', sightings: 2 },
  { day: 'Day 4', sightings: 5 },
  { day: 'Day 5', sightings: 12 },
  { day: 'Day 6', sightings: 28 },
  { day: 'Day 7', sightings: 46 },
]

export default function ThreatIntelView() {
  const [subTab, setSubTab] = useState<'ioc' | 'actors' | 'cve' | 'mitre'>('ioc')
  const [iocQuery, setIocQuery] = useState('185.199.110.5')
  const [actionMsg, setActionMsg] = useState<string | null>(null)

  const handleBlock = () => {
    setActionMsg('Pushed fleetwide block for IOC 185.199.110.5 to all 342 endpoints.')
    setTimeout(() => setActionMsg(null), 3500)
  }

  return (
    <div className="page-container">
      {/* ── Page Header ────────────────────────────────────────────── */}
      <div className="tp-page-header">
        <div>
          <h1 className="tp-page-title">Threat Intelligence & IOC Analysis</h1>
          <p className="tp-page-subtitle">Global threat intelligence feeds, adversary attribution, and internal telemetry correlation</p>
        </div>

        <div style={{ display: 'flex', gap: 10 }}>
          <button
            onClick={handleBlock}
            style={{
              background: '#ef4444',
              color: '#fff',
              border: 'none',
              borderRadius: 'var(--radius-md)',
              padding: '6px 14px',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 6
            }}
          >
            <Lock size={13} />
            <span>Block IOC Fleetwide</span>
          </button>
        </div>
      </div>

      {/* ── Sub Navigation Tabs matching Screen 5 ──────────────────── */}
      <div style={{ display: 'flex', gap: 16, borderBottom: '1px solid var(--border-subtle)', marginBottom: 18 }}>
        {[
          { key: 'ioc', label: 'IOC Search' },
          { key: 'actors', label: 'Threat Actors' },
          { key: 'cve', label: 'Vulnerabilities (CVEs)' },
          { key: 'mitre', label: 'MITRE ATT&CK Matrix' },
        ].map(tab => (
          <button
            key={tab.key}
            onClick={() => setSubTab(tab.key as any)}
            style={{
              background: 'transparent',
              border: 'none',
              padding: '8px 4px',
              fontSize: 13,
              fontWeight: subTab === tab.key ? 600 : 500,
              color: subTab === tab.key ? '#fff' : 'var(--text-muted)',
              borderBottom: subTab === tab.key ? '2px solid var(--magenta)' : '2px solid transparent',
              cursor: 'pointer'
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* ── Search Bar matching Screen 5 ───────────────────────────── */}
      <div className="tp-card" style={{ marginBottom: 18, padding: '14px 18px' }}>
        <div style={{ display: 'flex', gap: 10 }}>
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', gap: 10, background: 'var(--bg-deep)', border: '1px solid var(--border-dim)', borderRadius: 6, padding: '8px 14px' }}>
            <Search size={14} color="var(--text-muted)" />
            <input
              type="text"
              placeholder="Enter IP address, domain, file SHA-256 hash, or URL..."
              value={iocQuery}
              onChange={e => setIocQuery(e.target.value)}
              style={{ background: 'transparent', border: 'none', outline: 'none', color: '#fff', fontSize: 13, width: '100%' }}
            />
          </div>
          <button
            style={{
              background: 'var(--magenta)',
              color: '#fff',
              border: 'none',
              borderRadius: 6,
              padding: '0 18px',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
              boxShadow: '0 0 10px var(--magenta-glow)'
            }}
          >
            Analyze IOC
          </button>
        </div>

        {actionMsg && (
          <div style={{ marginTop: 10, fontSize: 11, color: '#10b981', display: 'flex', alignItems: 'center', gap: 6 }}>
            <CheckCircle2 size={13} />
            <span>{actionMsg}</span>
          </div>
        )}
      </div>

      {/* ── Target IOC Card & Sightings Row matching Screen 5 ──────── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: 18 }}>
        {/* Left: Detailed IOC Card */}
        <div className="tp-card" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <span className="badge-pill badge-critical">MALICIOUS</span>
                <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>IPv4 Indicator</span>
              </div>
              <h2 style={{ fontSize: 20, fontWeight: 700, fontFamily: 'var(--font-mono)', color: '#fff', margin: 0 }}>
                185.199.110.5
              </h2>
            </div>

            {/* Score Ring / Pill */}
            <div style={{
              background: 'rgba(239, 68, 68, 0.15)',
              border: '1px solid #ef4444',
              borderRadius: 8,
              padding: '8px 14px',
              textAlign: 'center',
            }}>
              <div style={{ fontSize: 20, fontWeight: 800, color: '#ef4444' }}>85 / 100</div>
              <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Threat Score</div>
            </div>
          </div>

          {/* Metadata Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, padding: '12px 14px', background: 'var(--bg-deep)', borderRadius: 6 }}>
            <div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Autonomous System</div>
              <div style={{ fontSize: 12, fontWeight: 600, color: '#fff', marginTop: 2 }}>AS16276 OVH SAS</div>
            </div>
            <div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Geolocation</div>
              <div style={{ fontSize: 12, fontWeight: 600, color: '#fff', marginTop: 2 }}>Amsterdam, Netherlands 🇳🇱</div>
            </div>
            <div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Attributed Actor</div>
              <div style={{ fontSize: 12, fontWeight: 600, color: '#ec4899', marginTop: 2 }}>APT29 (Cozy Bear)</div>
            </div>
            <div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Associated Malware</div>
              <div style={{ fontSize: 12, fontWeight: 600, color: '#f59e0b', marginTop: 2 }}>Cobalt Strike / Sliver</div>
            </div>
          </div>

          {/* Associated Domains & Hashes */}
          <div>
            <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 8 }}>
              Associated Infrastructure & Hashes
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, padding: '6px 10px', background: 'var(--bg-deep)', borderRadius: 4 }}>
                <span style={{ fontFamily: 'var(--font-mono)', color: '#38bdf8' }}>cdn-telemetry-update.com</span>
                <span style={{ color: 'var(--text-muted)' }}>Domain • High Confidence</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, padding: '6px 10px', background: 'var(--bg-deep)', borderRadius: 4 }}>
                <span style={{ fontFamily: 'var(--font-mono)', color: '#38bdf8' }}>auth-sync-gateway.net</span>
                <span style={{ color: 'var(--text-muted)' }}>Domain • High Confidence</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, padding: '6px 10px', background: 'var(--bg-deep)', borderRadius: 4 }}>
                <span style={{ fontFamily: 'var(--font-mono)', color: '#cbd5e1' }}>e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b...</span>
                <span style={{ color: 'var(--text-muted)' }}>SHA-256</span>
              </div>
            </div>
          </div>
        </div>

        {/* Right: Recent Sightings Internal Bar Chart matching Screen 5 */}
        <div className="tp-card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <h3 style={{ fontSize: 13, fontWeight: 600, color: '#f1f5f9' }}>
                Internal Sightings (Last 7 Days)
              </h3>
              <span style={{ fontSize: 11, color: '#ef4444', fontWeight: 600 }}>
                93 Total Detections
              </span>
            </div>
            <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 16 }}>
              Occurrences of connections or matches to this indicator across your enrolled endpoint agents.
            </p>

            <div style={{ height: 180, width: '100%' }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={SIGHTINGS_DATA} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid stroke="rgba(255,255,255,0.05)" vertical={false} />
                  <XAxis dataKey="day" tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <Tooltip
                    contentStyle={{ background: '#12151f', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 6, fontSize: 11 }}
                    itemStyle={{ color: '#fff' }}
                  />
                  <Bar dataKey="sightings" fill="#ec4899" radius={[4, 4, 0, 0]} isAnimationActive={false} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: 14, display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 11 }}>
            <span style={{ color: 'var(--text-muted)' }}>First detected on DESKTOP-GJ53HIT</span>
            <span style={{ color: 'var(--magenta)', fontWeight: 600 }}>Active C2 Cluster Detected</span>
          </div>
        </div>
      </div>
    </div>
  )
}
