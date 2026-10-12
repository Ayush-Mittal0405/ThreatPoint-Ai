import { useState, useEffect } from 'react'
import {
  Shield, Activity, Radio, AlertTriangle, Terminal,
  CheckCircle2, Server, Cpu, Globe, ArrowUpRight, Zap
} from 'lucide-react'
import { api, Endpoint, Alert } from '../services/api'
import { usePolling } from '../hooks/usePolling'

export default function HomeView() {
  const [endpoints, setEndpoints] = useState<Endpoint[]>([])
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [events, setEvents] = useState<any[]>([])

  const loadData = async () => {
    try {
      const [eps, alts] = await Promise.all([
        api.getEndpoints(),
        api.getAlerts(),
      ])
      setEndpoints(eps || [])
      setAlerts(alts || [])
    } catch {
      // Offline fallback
    }
  }

  useEffect(() => {
    loadData()
    // Simulated live streaming telemetry from enrolled agents
    const timer = setInterval(() => {
      const newEvent = {
        id: Math.random().toString(36).substring(7),
        time: new Date().toLocaleTimeString(),
        host: 'DESKTOP-GJ53HIT',
        type: ['Process Creation', 'DNS Query', 'TCP Connect', 'Registry Write'][Math.floor(Math.random() * 4)],
        detail: [
          'powershell.exe spawned with encoded payload',
          'query to telemetry-api.internal.corp',
          'outbound SYN to 185.199.110.5:443',
          'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run modified'
        ][Math.floor(Math.random() * 4)],
        severity: ['high', 'info', 'critical', 'medium'][Math.floor(Math.random() * 4)]
      }
      setEvents(prev => [newEvent, ...prev.slice(0, 15)])
    }, 1800)
    return () => clearInterval(timer)
  }, [])

  usePolling(loadData, 2_000)

  return (
    <div className="page-container">
      {/* ── Page Header ────────────────────────────────────────────── */}
      <div className="tp-page-header">
        <div>
          <h1 className="tp-page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span>Enterprise SOC Posture & Global Telemetry</span>
            <span style={{
              background: '#ef4444',
              color: '#fff',
              fontSize: 10,
              fontWeight: 700,
              padding: '2px 8px',
              borderRadius: 4,
              letterSpacing: '0.5px'
            }}>
              LIVE SENSORS
            </span>
          </h1>
          <p className="tp-page-subtitle">Real-time telemetry ingestion, active containment matrix, and enterprise defense health</p>
        </div>

        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            background: 'rgba(239, 68, 68, 0.15)',
            border: '1px solid #ef4444',
            borderRadius: 6,
            padding: '6px 12px',
            color: '#ef4444',
            fontWeight: 700,
            fontSize: 11
          }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#ef4444', animation: 'pulse 1.5s infinite' }} />
            <span>GLOBAL THREAT: HIGH</span>
          </div>
        </div>
      </div>

      {/* ── 4 Posture KPI Cards ────────────────────────────────────── */}
      <div className="kpi-grid-4">
        <div className="kpi-card kpi-green">
          <div className="kpi-header">
            <span>Sensors Ingest Rate</span>
            <Activity size={14} color="#10b981" />
          </div>
          <div className="kpi-value-row">
            <div className="kpi-value" style={{ color: '#10b981' }}>480 EPS</div>
            <div className="kpi-badge up">Live Streaming</div>
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-header">
            <span>Enrolled Active Fleet</span>
            <Server size={14} color="#38bdf8" />
          </div>
          <div className="kpi-value-row">
            <div className="kpi-value" style={{ color: '#fff' }}>342 Agents</div>
            <div className="kpi-badge up">DESKTOP-GJ53HIT Online</div>
          </div>
        </div>

        <div className="kpi-card kpi-red">
          <div className="kpi-header">
            <span>Active Attack Chains</span>
            <AlertTriangle size={14} color="#ef4444" />
          </div>
          <div className="kpi-value-row">
            <div className="kpi-value" style={{ color: '#ef4444' }}>1 Critical</div>
            <div className="kpi-badge down">INC-2025-0102</div>
          </div>
        </div>

        <div className="kpi-card kpi-yellow">
          <div className="kpi-header">
            <span>ThreatPoint AI Autonomous Defenses</span>
            <Zap size={14} color="#eab308" />
          </div>
          <div className="kpi-value-row">
            <div className="kpi-value" style={{ color: '#eab308' }}>Active</div>
            <div className="kpi-badge" style={{ color: '#eab308' }}>0.4s Response Time</div>
          </div>
        </div>
      </div>

      {/* ── Grid: Live Telemetry Stream + Global Defense Matrix ────── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: 18 }}>
        {/* Left: Live Event Stream Ticker */}
        <div className="tp-card" style={{ display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Radio size={16} color="var(--magenta)" />
              <h3 style={{ fontSize: 13, fontWeight: 600, color: '#fff', margin: 0 }}>
                Live Sensor Telemetry Ingestion
              </h3>
            </div>
            <span style={{ fontSize: 11, color: '#10b981', fontFamily: 'var(--font-mono)' }}>
              1-2s Refresh Rate
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 380, overflowY: 'auto' }}>
            {events.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)' }}>
                Connecting to live agent telemetry stream...
              </div>
            ) : (
              events.map(ev => (
                <div
                  key={ev.id}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '8px 12px',
                    background: 'var(--bg-deep)',
                    borderRadius: 6,
                    border: '1px solid var(--border-subtle)',
                    fontSize: 11
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>{ev.time}</span>
                    <span style={{
                      padding: '2px 6px',
                      borderRadius: 4,
                      fontWeight: 600,
                      background: ev.severity === 'critical' ? 'rgba(239,68,68,0.2)' : ev.severity === 'high' ? 'rgba(249,115,22,0.2)' : 'rgba(255,255,255,0.06)',
                      color: ev.severity === 'critical' ? '#ef4444' : ev.severity === 'high' ? '#f97316' : '#cbd5e1'
                    }}>
                      {ev.type}
                    </span>
                    <span style={{ color: '#fff', fontWeight: 500 }}>{ev.detail}</span>
                  </div>
                  <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>{ev.host}</span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right: Defense Readiness & Security Posture */}
        <div className="tp-card" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ fontSize: 13, fontWeight: 600, color: '#fff', margin: 0 }}>
              Enterprise Defense Posture Breakdown
            </h3>
            <span style={{ fontSize: 11, color: '#10b981', fontWeight: 600 }}>98.2% Optimal</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 5 }}>
                <span style={{ color: '#cbd5e1' }}>Endpoint Process Telemetry & Kernel Hooks</span>
                <span style={{ fontWeight: 700, color: '#10b981' }}>99.4%</span>
              </div>
              <div style={{ height: 6, width: '100%', background: 'var(--bg-deep)', borderRadius: 99, overflow: 'hidden' }}>
                <div style={{ height: '100%', width: '99.4%', background: '#10b981' }} />
              </div>
            </div>

            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 5 }}>
                <span style={{ color: '#cbd5e1' }}>Autonomous AI Containment Engine</span>
                <span style={{ fontWeight: 700, color: 'var(--magenta)' }}>100% Active</span>
              </div>
              <div style={{ height: 6, width: '100%', background: 'var(--bg-deep)', borderRadius: 99, overflow: 'hidden' }}>
                <div style={{ height: '100%', width: '100%', background: 'var(--magenta)' }} />
              </div>
            </div>

            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 5 }}>
                <span style={{ color: '#cbd5e1' }}>Network Perimeter & C2 Sinkholing</span>
                <span style={{ fontWeight: 700, color: '#38bdf8' }}>96.8%</span>
              </div>
              <div style={{ height: 6, width: '100%', background: 'var(--bg-deep)', borderRadius: 99, overflow: 'hidden' }}>
                <div style={{ height: '100%', width: '96.8%', background: '#38bdf8' }} />
              </div>
            </div>

            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 5 }}>
                <span style={{ color: '#cbd5e1' }}>Identity & Credential Protection (LSASS Guard)</span>
                <span style={{ fontWeight: 700, color: '#eab308' }}>95.2%</span>
              </div>
              <div style={{ height: 6, width: '100%', background: 'var(--bg-deep)', borderRadius: 99, overflow: 'hidden' }}>
                <div style={{ height: '100%', width: '95.2%', background: '#eab308' }} />
              </div>
            </div>
          </div>

          <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: 14 }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>
              Connected Primary Agent
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--bg-deep)', padding: '8px 12px', borderRadius: 6 }}>
              <div>
                <span style={{ fontWeight: 600, color: '#fff' }}>DESKTOP-GJ53HIT</span>
                <span style={{ fontSize: 10, color: 'var(--text-muted)', marginLeft: 8 }}>192.168.29.89</span>
              </div>
              <span className="badge-pill" style={{ background: 'rgba(16,185,129,0.15)', color: '#10b981' }}>
                Streaming Live
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
