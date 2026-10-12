import { useState } from 'react'
import {
  Settings, Key, Shield, Lock, Bell, CheckCircle2,
  Copy, RefreshCw, Server, Cpu, Database, Save
} from 'lucide-react'

export default function SettingsView() {
  const [adminKey, setAdminKey] = useState('threatpoint-secret-adm-key-2026')
  const [heartbeatInterval, setHeartbeatInterval] = useState('2')
  const [confidenceCutoff, setConfidenceCutoff] = useState('80')
  const [autoIsolate, setAutoIsolate] = useState(true)
  const [saved, setSaved] = useState(false)
  const [copiedToken, setCopiedToken] = useState(false)

  const enrollCommand = `.\\scripts\\enroll.ps1 -Token "M0KV5lSh4Re9NHktidzMXrxCfPoJwCN7gTZ210qz6Pw" -Server "https://192.168.29.89:8008" -Insecure`

  const handleCopy = () => {
    navigator.clipboard.writeText(enrollCommand)
    setCopiedToken(true)
    setTimeout(() => setCopiedToken(false), 2500)
  }

  const handleSave = () => {
    setSaved(true)
    setTimeout(() => setSaved(false), 3000)
  }

  return (
    <div className="page-container">
      {/* ── Page Header ────────────────────────────────────────────── */}
      <div className="tp-page-header">
        <div>
          <h1 className="tp-page-title">Platform Settings & Security Configuration</h1>
          <p className="tp-page-subtitle">Manage ThreatPoint Ai agent enrollment, TLS certificates, neural thresholds, and integrations</p>
        </div>

        <button
          onClick={handleSave}
          style={{
            background: 'var(--magenta)',
            color: '#fff',
            border: 'none',
            borderRadius: 'var(--radius-md)',
            padding: '6px 16px',
            fontSize: 12,
            fontWeight: 600,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            boxShadow: '0 0 10px var(--magenta-glow)'
          }}
        >
          <Save size={13} />
          <span>{saved ? 'Changes Saved!' : 'Save Configuration'}</span>
        </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 18 }}>
        {/* Card 1: Agent Enrollment & Fleet Secrets */}
        <div className="tp-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
            <Key size={16} color="var(--magenta)" />
            <h3 style={{ fontSize: 13, fontWeight: 600, color: '#fff' }}>Agent Enrollment & Provisioning</h3>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div>
              <label style={{ display: 'block', fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>
                Admin API Secret Key (Bearer Authentication)
              </label>
              <input
                type="password"
                value={adminKey}
                onChange={e => setAdminKey(e.target.value)}
                style={{
                  width: '100%',
                  background: 'var(--bg-deep)',
                  border: '1px solid var(--border-dim)',
                  borderRadius: 6,
                  padding: '7px 12px',
                  color: '#fff',
                  fontSize: 12,
                  fontFamily: 'var(--font-mono)'
                }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>
                One-Click Agent Enrollment Command (PowerShell)
              </label>
              <div style={{ position: 'relative' }}>
                <textarea
                  readOnly
                  value={enrollCommand}
                  rows={2}
                  style={{
                    width: '100%',
                    background: 'var(--bg-deep)',
                    border: '1px solid var(--border-dim)',
                    borderRadius: 6,
                    padding: '8px 10px',
                    color: '#cbd5e1',
                    fontSize: 11,
                    fontFamily: 'var(--font-mono)',
                    resize: 'none'
                  }}
                />
                <button
                  onClick={handleCopy}
                  style={{
                    position: 'absolute',
                    top: 8,
                    right: 8,
                    background: 'var(--bg-card)',
                    border: '1px solid var(--border-dim)',
                    borderRadius: 4,
                    padding: '4px 8px',
                    fontSize: 10,
                    color: copiedToken ? '#10b981' : '#fff',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 4
                  }}
                >
                  {copiedToken ? <CheckCircle2 size={12} /> : <Copy size={12} />}
                  <span>{copiedToken ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
              <div>
                <label style={{ display: 'block', fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>
                  Heartbeat Polling Interval
                </label>
                <select
                  className="tp-select"
                  value={heartbeatInterval}
                  onChange={e => setHeartbeatInterval(e.target.value)}
                  style={{ width: '100%' }}
                >
                  <option value="1">1 second (Ultra-Fast)</option>
                  <option value="2">2 seconds (Real-Time Recommended)</option>
                  <option value="5">5 seconds</option>
                  <option value="10">10 seconds</option>
                </select>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>
                  Telemetry Flush Interval
                </label>
                <select className="tp-select" style={{ width: '100%' }}>
                  <option value="1">1 second (Streaming)</option>
                  <option value="3">3 seconds</option>
                </select>
              </div>
            </div>
          </div>
        </div>

        {/* Card 2: Neural AI Configuration */}
        <div className="tp-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
            <Cpu size={16} color="var(--magenta)" />
            <h3 style={{ fontSize: 13, fontWeight: 600, color: '#fff' }}>ThreatPoint AI Reasoning Engine</h3>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Auto-Containment Confidence Cutoff</span>
                <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--magenta)' }}>{confidenceCutoff}%</span>
              </div>
              <input
                type="range"
                min="50"
                max="95"
                value={confidenceCutoff}
                onChange={e => setConfidenceCutoff(e.target.value)}
                style={{ width: '100%', accentColor: 'var(--magenta)' }}
              />
              <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                Attacks with neural confidence above this score will trigger recommended isolation.
              </span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 12px', background: 'var(--bg-deep)', borderRadius: 6 }}>
              <div>
                <div style={{ fontSize: 12, fontWeight: 600, color: '#fff' }}>Autonomous Host Isolation</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Automatically disconnect infected NICs without manual analyst click</div>
              </div>
              <input
                type="checkbox"
                checked={autoIsolate}
                onChange={e => setAutoIsolate(e.target.checked)}
                style={{ accentColor: 'var(--magenta)', width: 16, height: 16, cursor: 'pointer' }}
              />
            </div>

            <div style={{ padding: '10px 12px', background: 'var(--bg-deep)', borderRadius: 6 }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 4 }}>
                Active LLM Architecture
              </div>
              <div style={{ fontSize: 12, color: '#cbd5e1' }}>ThreatPoint Autonomous SOC Reasoner v2.4</div>
              <div style={{ fontSize: 10, color: '#10b981', marginTop: 2 }}>Zero Hallucination Grounding Active</div>
            </div>
          </div>
        </div>

        {/* Card 3: TLS / SSL Certificates */}
        <div className="tp-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
            <Lock size={16} color="#10b981" />
            <h3 style={{ fontSize: 13, fontWeight: 600, color: '#fff' }}>TLS / HTTPS Certificate Status</h3>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 12 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 10px', background: 'var(--bg-deep)', borderRadius: 4 }}>
              <span style={{ color: 'var(--text-muted)' }}>Certificate Location</span>
              <span style={{ fontFamily: 'var(--font-mono)', color: '#fff' }}>backend/certs/cert.pem</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 10px', background: 'var(--bg-deep)', borderRadius: 4 }}>
              <span style={{ color: 'var(--text-muted)' }}>Private Key</span>
              <span style={{ fontFamily: 'var(--font-mono)', color: '#fff' }}>backend/certs/key.pem</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 10px', background: 'var(--bg-deep)', borderRadius: 4 }}>
              <span style={{ color: 'var(--text-muted)' }}>Subject Alt Names</span>
              <span style={{ fontFamily: 'var(--font-mono)', color: '#10b981' }}>IP:192.168.29.89, IP:127.0.0.1, localhost</span>
            </div>
          </div>
        </div>

        {/* Card 4: SIEM & Webhook Egress */}
        <div className="tp-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
            <Bell size={16} color="#eab308" />
            <h3 style={{ fontSize: 13, fontWeight: 600, color: '#fff' }}>SIEM & Alert Webhook Integrations</h3>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 10px', background: 'var(--bg-deep)', borderRadius: 4 }}>
              <div>
                <span style={{ fontWeight: 600, color: '#fff' }}>Slack Incident Channel</span>
                <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>#secops-critical-alerts</div>
              </div>
              <span className="badge-pill" style={{ background: 'rgba(16,185,129,0.15)', color: '#10b981' }}>Connected</span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 10px', background: 'var(--bg-deep)', borderRadius: 4 }}>
              <div>
                <span style={{ fontWeight: 600, color: '#fff' }}>Splunk / Syslog Egress</span>
                <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>syslog-ng:514 (CEF format)</div>
              </div>
              <span className="badge-pill" style={{ background: 'rgba(16,185,129,0.15)', color: '#10b981' }}>Active</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
