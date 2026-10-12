/**
 * ThreatPoint Ai API service — typed client for the FastAPI backend.
 */
import axios from 'axios'

// Default to relative paths so requests go through the Vite dev proxy (dev) or
// the nginx `/api/` proxy (prod). Override with VITE_API_BASE_URL only when the
// backend is on a different origin.
const BASE = import.meta.env.VITE_API_BASE_URL || ''

const client = axios.create({
  baseURL: `${BASE}/api/v1`,
  timeout: 60_000,
  headers: { 'Content-Type': 'application/json' },
})

// ── Types ─────────────────────────────────────────────────────────────────────

export interface Incident {
  id: string
  incident_id: string
  title: string
  description?: string
  status: string
  severity: string
  risk_score?: number
  confidence?: number
  entities?: { hosts?: string[]; users?: string[]; ips?: string[] }
  mitre_techniques?: string[]
  attack_story?: Record<string, any>
  recommendations?: Recommendation[]
  verification?: VerificationResult
  created_at: string
  updated_at: string
}

export interface Alert {
  id: string
  alert_id: string
  title: string
  description?: string
  severity: string
  status: string
  host?: string | null
  user?: string | null
  mitre_techniques?: string[]
  created_at: string
}

export interface TraceStep {
  id: string
  agent_name: string
  step: number
  action: string
  tool_name?: string
  tool_args?: Record<string, any>
  reasoning?: string
  success: boolean
  error?: string
  duration_ms?: number
}

export interface Recommendation {
  action: string
  target: string
  reason: string
  expected_impact: string
  priority: number
  risk_level: string
  reversible: boolean
  requires_human_approval: boolean
  approved: boolean
  executed: boolean
  execution_result?: any
}

export interface VerificationResult {
  threat_removed: boolean
  confidence: number
  threat_indicators: number
  recommendation: string
  verified_at: string
}

export interface HuntReport {
  hunt_id: string
  query: string
  hypothesis: string
  findings: string[]
  evidence: Array<{
    iteration: number
    tool: string
    args: Record<string, any>
    result: any
    duration_ms: number
  }>
  mitre_hypotheses: string[]
  conclusion: string
  confidence: number
  iterations: number
  duration_seconds: number
  started_at: string
  finished_at: string
}

// ── API methods ───────────────────────────────────────────────────────────────

export const api = {

  // ── Stats ─────────────────────────────────────────────────────────────────
  async getStats() {
    const [incRes, alertRes] = await Promise.all([
      client.get('/incidents?limit=200'),
      client.get('/alerts?status=open&limit=200'),
    ])
    const incidents: Incident[] = incRes.data.incidents || []
    return {
      total_incidents: incidents.filter(i => i.status !== 'closed').length,
      critical_incidents: incidents.filter(i => i.severity === 'critical' && i.status !== 'closed').length,
      open_alerts: alertRes.data.length,
      active_investigations: incidents.filter(i => i.status === 'investigating').length,
    }
  },

  // ── Incidents ──────────────────────────────────────────────────────────────
  async getIncidents(status?: string) {
    const res = await client.get('/incidents', { params: status ? { status } : {} })
    return res.data as { total: number; incidents: Incident[] }
  },

  async getIncident(id: string) {
    const res = await client.get(`/incidents/${id}`)
    return res.data as Incident
  },

  async getIncidentTrace(id: string) {
    const res = await client.get(`/incidents/${id}/trace`)
    return res.data as TraceStep[]
  },

  async triggerInvestigation(id: string) {
    const res = await client.post(`/agents/investigate/${id}`)
    return res.data
  },

  // ── Alerts ────────────────────────────────────────────────────────────────
  async getAlerts(status?: string) {
    const res = await client.get('/alerts', { params: status ? { status } : {} })
    return res.data as Alert[]
  },

  async updateAlertStatus(id: string, status: string) {
    const res = await client.patch(`/alerts/${id}/status`, { status })
    return res.data as Alert
  },

  // ── Telemetry ─────────────────────────────────────────────────────────────
  async ingestEvent(event: Record<string, any>) {
    const res = await client.post('/telemetry/ingest/single', event)
    return res.data
  },

  async ingestBatch(events: Record<string, any>[]) {
    const res = await client.post('/telemetry/ingest', { events })
    return res.data
  },

  // ── Attack Story ──────────────────────────────────────────────────────────
  async getAttackStory(incidentId: string) {
    const res = await client.get(`/attack-story/${incidentId}`)
    return res.data
  },

  async generateAttackStory(incidentId: string) {
    const res = await client.post(`/attack-story/${incidentId}/generate`)
    return res.data
  },

  // ── Response Workflow ─────────────────────────────────────────────────────
  async getResponseStatus(incidentId: string) {
    const res = await client.get(`/response/${incidentId}/status`)
    return res.data
  },

  async getResponseRecommendations(incidentId: string) {
    const res = await client.post(`/response/${incidentId}/recommend`)
    return res.data
  },

  async approveResponseAction(incidentId: string, actionIndex: number, note = '') {
    const res = await client.post(`/response/${incidentId}/approve`, {
      action_index: actionIndex,
      analyst_note: note,
    })
    return res.data
  },

  async executeResponseAction(incidentId: string, actionIndex: number) {
    const res = await client.post(`/response/${incidentId}/execute`, {
      action_index: actionIndex,
      confirm: true,
    })
    return res.data
  },

  async runVerification(incidentId: string) {
    const res = await client.post(`/response/${incidentId}/verify`)
    return res.data as VerificationResult
  },

  // ── Hunting ───────────────────────────────────────────────────────────────
  async runHunt(query: string, context?: Record<string, any>) {
    const res = await client.post('/hunting/hunt', { query, context })
    return res.data as HuntReport
  },

  async getRecentHunts() {
    const res = await client.get('/hunting/recent')
    return res.data
  },

  // ── RAG ───────────────────────────────────────────────────────────────────
  async searchKnowledge(q: string, k = 5, source?: string) {
    const res = await client.get('/rag/search', { params: { q, k, source } })
    return res.data
  },

  async getKnowledgeStats() {
    const res = await client.get('/rag/stats')
    return res.data
  },

  // ── Model Metrics ─────────────────────────────────────────────────────────
  async getModelMetrics(days = 30) {
    const res = await client.get('/models/metrics', { params: { days } })
    return res.data
  },

  // ── Analyst Feedback ──────────────────────────────────────────────────────
  async submitFeedback(incidentId: string, data: {
    rating: number
    is_false_positive?: boolean
    category?: string
    analyst_note?: string
    corrected_severity?: string
  }) {
    const res = await client.post(`/feedback/${incidentId}`, data)
    return res.data
  },

  async getFeedbackStats() {
    const res = await client.get('/feedback/stats')
    return res.data
  },

  // ── Incident Export ───────────────────────────────────────────────────────
  getIncidentMarkdownExportUrl(incidentId: string) {
    return `/api/v1/incidents/${incidentId}/export/markdown`
  },

  getIncidentHtmlExportUrl(incidentId: string) {
    return `/api/v1/incidents/${incidentId}/export/html`
  },

  // ── Fleet Management (100+ Endpoints) ─────────────────────────────────────
  async getFleetDevices(params?: {
    department?: string
    os?: string
    status?: string
    containment_status?: string
    search?: string
    limit?: number
    offset?: number
  }) {
    const res = await client.get('/fleet/devices', { params })
    return res.data as { total: number; offset: number; limit: number; devices: FleetDevice[] }
  },

  async getFleetDevice(deviceId: string) {
    const res = await client.get(`/fleet/devices/${deviceId}`)
    return res.data as {
      device: FleetDevice
      processes: any[]
      network_sockets: any[]
      action_history: DeviceActionAudit[]
    }
  },

  async executeDeviceAction(deviceId: string, action: string, target?: string, analyst = 'SecOps Analyst') {
    const res = await client.post(`/fleet/devices/${deviceId}/action`, { action, target, analyst })
    return res.data as { status: string; message: string; device: FleetDevice; audit_entry: DeviceActionAudit }
  },

  async executeBulkAction(deviceIds: string[], action: string, target?: string, analyst = 'SecOps Analyst') {
    const res = await client.post('/fleet/bulk-action', { device_ids: deviceIds, action, target, analyst })
    return res.data as { status: string; action: string; affected_count: number; hostnames: string[] }
  },

  async getFleetActionAudit() {
    const res = await client.get('/fleet/actions/audit')
    return res.data as DeviceActionAudit[]
  },

  async getFleetStats() {
    const res = await client.get('/fleet/stats')
    return res.data as FleetStats
  },

  // ── Endpoint Agents (real enrolled agents) ────────────────────────────────
  async getEndpoints(params?: { status?: string; os?: string; search?: string }) {
    const res = await client.get('/endpoints', { params })
    return res.data as EndpointAgent[]
  },

  async getEndpointStats() {
    const res = await client.get('/endpoints/stats')
    return res.data as EndpointStats
  },

  async getEndpointDetail(agentId: string) {
    const res = await client.get(`/endpoints/${agentId}`)
    return res.data as EndpointDetail
  },

  /**
   * Mint a one-time enrollment token. Requires the SOC admin API key, which the
   * analyst supplies in the UI — it is never bundled into the frontend build.
   */
  async createEnrollmentToken(
    adminKey: string,
    body: { label?: string; max_uses?: number; ttl_seconds?: number },
  ) {
    const res = await client.post('/endpoints/enroll-tokens', body, {
      headers: { 'X-Admin-API-Key': adminKey },
    })
    return res.data as EnrollmentTokenCreated
  },

  async revokeEndpoint(adminKey: string, agentId: string) {
    const res = await client.post(`/endpoints/${agentId}/revoke`, {}, {
      headers: { 'X-Admin-API-Key': adminKey },
    })
    return res.data as { status: string; agent_id: string }
  },
}

export interface EnrollmentTokenCreated {
  enrollment_token: string
  label?: string | null
  max_uses: number
  expires_at: string
}

// ── Endpoint agent types ───────────────────────────────────────────────────────

export interface EndpointAgent {
  agent_id: string
  hostname: string
  operating_system?: string | null
  os_version?: string | null
  agent_version?: string | null
  username?: string | null
  ip_address?: string | null
  status: 'online' | 'warning' | 'offline' | 'unhealthy' | 'revoked'
  health: string
  risk_score: number
  open_alerts: number
  first_seen: string
  last_seen: string
}

export type Endpoint = EndpointAgent

export interface EndpointStats {
  total: number
  online: number
  offline: number
  warning: number
  unhealthy: number
  suspicious: number
}

export interface EndpointTimelineEntry {
  timestamp: string
  kind: 'event' | 'detection' | 'incident'
  title: string
  severity?: string | null
  detail?: string | null
}

export interface EndpointDetail {
  agent: EndpointAgent
  recent_events: Array<Record<string, any>>
  detections: Array<Record<string, any>>
  incidents: Array<Record<string, any>>
  timeline: EndpointTimelineEntry[]
}

export interface FleetDevice {
  id: string
  hostname: string
  ip_address: string
  mac_address?: string
  os: string
  device_type: string
  department: string
  assigned_user?: string
  status: 'online' | 'offline' | 'degraded'
  containment_status: 'normal' | 'isolated' | 'quarantined'
  agent_version: string
  risk_score: number
  last_seen: string
  cpu_usage_pct: number
  memory_usage_pct: number
  open_alerts_count: number
}

export interface DeviceActionAudit {
  id: string
  device_id: string
  hostname: string
  action: string
  target?: string
  analyst: string
  status: string
  details?: Record<string, any>
  executed_at: string
}

export interface FleetStats {
  total_devices: number
  online_count: number
  isolated_count: number
  high_risk_count: number
  events_per_sec: number
  avg_cpu_pct: number
  avg_mem_pct: number
  departments: Record<string, number>
  os_breakdown: Record<string, number>
}



