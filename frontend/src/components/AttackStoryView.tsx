import { useState, useCallback } from 'react'
import ReactFlow, {
  Node, Edge, Background, Controls, MiniMap,
  useNodesState, useEdgesState, MarkerType,
} from 'reactflow'
import 'reactflow/dist/style.css'
import { GitBranch } from 'lucide-react'

// ── Node type colors by entity type ──────────────────────────────────────────
const NODE_COLORS: Record<string, string> = {
  host:             '#63b3ed',
  process:          '#f97316',
  user:             '#a78bfa',
  ip:               '#ff4d6d',
  domain:           '#fb923c',
  mitre_technique:  '#facc15',
  mitre_tactic:     '#4ade80',
  incident:         '#94a3b8',
  alert:            '#f43f5e',
}

const STAGE_COLORS: Record<string, string> = {
  'Initial Access':       '#ff4d6d',
  'Execution':            '#f97316',
  'Persistence':          '#facc15',
  'Defense Evasion':      '#a78bfa',
  'Credential Access':    '#fb923c',
  'Command and Control':  '#ef4444',
  'Impact':               '#dc2626',
}

// ── Convert graph JSON to ReactFlow nodes/edges ───────────────────────────────
function graphToFlow(graphData: any): { nodes: Node[]; edges: Edge[] } {
  if (!graphData?.nodes) return { nodes: [], edges: [] }

  const nodes: Node[] = graphData.nodes.map((n: any, i: number) => {
    const type  = n.type || 'host'
    const color = NODE_COLORS[type] || '#94a3b8'
    const col   = (i % 5) * 200
    const row   = Math.floor(i / 5) * 120
    return {
      id: n.id,
      position: { x: col + 50, y: row + 50 },
      data: {
        label: (
          <div style={{ textAlign: 'center', fontSize: 11, color: '#fff' }}>
            <div style={{ fontSize: 9, opacity: 0.6, textTransform: 'uppercase', marginBottom: 2 }}>{type}</div>
            <div style={{ fontWeight: 600, fontFamily: 'var(--font-mono)', maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {n.label || n.id}
            </div>
          </div>
        ),
      },
      style: {
        background: color + '22',
        border: `1px solid ${color}66`,
        borderRadius: 8,
        color,
        padding: '8px 12px',
        minWidth: 120,
      },
    }
  })

  const edges: Edge[] = graphData.edges.map((e: any, i: number) => ({
    id: `e-${i}`,
    source: e.from,
    target: e.to,
    label: e.type,
    style: { stroke: '#475569', strokeWidth: 1 },
    labelStyle: { fill: '#64748b', fontSize: 9 },
    markerEnd: { type: MarkerType.ArrowClosed, color: '#475569' },
  }))

  return { nodes, edges }
}

interface AttackStoryProps {
  incidentId: string
  story: any
}

export default function AttackStoryView({ incidentId, story }: AttackStoryProps) {
  const { nodes: initNodes, edges: initEdges } = graphToFlow(story?.graph)
  const [nodes, , onNodesChange] = useNodesState(initNodes)
  const [edges, , onEdgesChange] = useEdgesState(initEdges)
  const [selectedNode, setSelectedNode] = useState<any | null>(null)

  const handleNodeClick = useCallback((_: any, node: Node) => {
    // Find original node metadata from graph
    const original = story?.graph?.nodes?.find((n: any) => n.id === node.id)
    setSelectedNode(original || { id: node.id, type: 'entity', label: node.id })
  }, [story])

  if (!story) {
    return (
      <div className="empty-state">
        <GitBranch size={40} />
        <p>No attack story yet. Click "Generate Story" on the incident page.</p>
      </div>
    )
  }

  return (
    <div className="fade-in">
      {/* Summary */}
      <div className="card" style={{ marginBottom: 20 }}>
        <div className="card-title">Executive Summary</div>
        <p style={{ fontSize: 14, color: 'var(--text-secondary)', lineHeight: 1.7 }}>
          {story.summary}
        </p>
        <div style={{ display: 'flex', gap: 20, marginTop: 16 }}>
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 700, textTransform: 'uppercase' }}>Risk Score</div>
            <div style={{ fontSize: 28, fontWeight: 800, color: getRiskColor(story.risk_score?.total), fontFamily: 'var(--font-mono)' }}>
              {story.risk_score?.total ?? '—'}/100
            </div>
          </div>
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 700, textTransform: 'uppercase' }}>Confidence</div>
            <div style={{ fontSize: 28, fontWeight: 800, color: 'var(--text-accent)', fontFamily: 'var(--font-mono)' }}>
              {story.confidence ? `${Math.round(story.confidence * 100)}%` : '—'}
            </div>
          </div>
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 700, textTransform: 'uppercase' }}>Evidence</div>
            <div style={{ fontSize: 28, fontWeight: 800, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
              {story.evidence_count ?? 0}
            </div>
          </div>
        </div>
      </div>

      {/* Kill-chain timeline */}
      <div className="card" style={{ marginBottom: 20 }}>
        <div className="card-title">Attack Timeline</div>
        <div style={{ display: 'flex', gap: 0, overflowX: 'auto', paddingBottom: 8 }}>
          {(story.timeline || []).map((stage: any, i: number) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center' }}>
              <div style={{
                background: (STAGE_COLORS[stage.stage] || '#475569') + '22',
                border: `1px solid ${STAGE_COLORS[stage.stage] || '#475569'}66`,
                borderRadius: 8,
                padding: '12px 16px',
                minWidth: 160,
                maxWidth: 200,
              }}>
                <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: STAGE_COLORS[stage.stage] || '#94a3b8', marginBottom: 4 }}>
                  {stage.stage}
                </div>
                {stage.technique_id && (
                  <span className="mono" style={{ fontSize: 10, marginBottom: 4, display: 'block' }}>
                    {stage.technique_id}
                  </span>
                )}
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  {stage.description}
                </div>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4 }}>
                  {stage.evidence?.length || 0} evidence items
                </div>
              </div>
              {i < (story.timeline?.length ?? 0) - 1 && (
                <div style={{ color: 'var(--text-muted)', fontSize: 18, padding: '0 6px' }}>→</div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Entity Graph & Details Split */}
      {nodes.length > 0 && (
        <div className="card" style={{ position: 'relative' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div className="card-title" style={{ margin: 0 }}>Entity Relationship Graph</div>
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Click any node to inspect telemetry details</span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: selectedNode ? '1fr 280px' : '1fr', gap: 12, transition: 'all 0.2s ease' }}>
            <div style={{ height: 420, background: 'var(--bg-deep)', borderRadius: 8, overflow: 'hidden' }}>
              <ReactFlow
                nodes={nodes} edges={edges}
                onNodesChange={onNodesChange} onEdgesChange={onEdgesChange}
                onNodeClick={handleNodeClick}
                fitView
                style={{ background: 'var(--bg-deep)' }}
              >
                <Background color="#1c2e50" gap={20} />
                <Controls style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-dim)' }} />
                <MiniMap style={{ background: 'var(--bg-surface)' }} nodeColor={n => NODE_COLORS[(n.data as any)?.type] || '#94a3b8'} />
              </ReactFlow>
            </div>

            {/* Interactive Node Inspector Drawer */}
            {selectedNode && (
              <div
                className="fade-in"
                style={{
                  background: 'var(--bg-surface)',
                  border: '1px solid var(--border-bright)',
                  borderRadius: 8,
                  padding: 16,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 10,
                  fontSize: 12,
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div>
                    <span
                      style={{
                        fontSize: 9,
                        textTransform: 'uppercase',
                        fontWeight: 700,
                        padding: '2px 6px',
                        borderRadius: 4,
                        background: (NODE_COLORS[selectedNode.type] || '#94a3b8') + '22',
                        color: NODE_COLORS[selectedNode.type] || '#94a3b8',
                        border: `1px solid ${NODE_COLORS[selectedNode.type] || '#94a3b8'}66`,
                      }}
                    >
                      {selectedNode.type}
                    </span>
                    <h3 style={{ fontSize: 13, fontWeight: 700, marginTop: 6, color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                      {selectedNode.label || selectedNode.id}
                    </h3>
                  </div>
                  <button
                    onClick={() => setSelectedNode(null)}
                    style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 14 }}
                  >
                    ✕
                  </button>
                </div>

                <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: 8 }}>
                  <div style={{ fontSize: 10, textTransform: 'uppercase', fontWeight: 700, color: 'var(--text-muted)', marginBottom: 4 }}>
                    Node Identifier
                  </div>
                  <div className="mono" style={{ fontSize: 11, color: 'var(--text-accent)', wordBreak: 'break-all' }}>
                    {selectedNode.id}
                  </div>
                </div>

                {selectedNode.attributes && Object.keys(selectedNode.attributes).length > 0 && (
                  <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: 8 }}>
                    <div style={{ fontSize: 10, textTransform: 'uppercase', fontWeight: 700, color: 'var(--text-muted)', marginBottom: 4 }}>
                      Attributes
                    </div>
                    <pre style={{ fontSize: 10, fontFamily: 'var(--font-mono)', background: 'var(--bg-deep)', padding: 8, borderRadius: 6, overflowX: 'auto' }}>
                      {JSON.stringify(selectedNode.attributes, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}


function getRiskColor(score?: number) {
  if (!score) return 'var(--text-muted)'
  if (score >= 81) return 'var(--critical)'
  if (score >= 61) return 'var(--high)'
  if (score >= 41) return 'var(--medium)'
  return 'var(--low)'
}
