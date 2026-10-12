/**
 * Analyst Feedback & Continuous Learning Modal.
 * Allows SOC analysts to grade agent performance, submit corrections, and flag false positives.
 */
import { useState } from 'react'
import { Star, X, CheckCircle, AlertTriangle, MessageSquare, Send } from 'lucide-react'
import { api, Incident } from '../services/api'
import { useToast } from './Toast'

interface FeedbackModalProps {
  isOpen: boolean
  incident: Incident | null
  onClose: () => void
  onFeedbackSubmitted?: () => void
}

const CATEGORIES = [
  { id: 'accurate',          label: '✓ Accurate & Complete', desc: 'AI reached correct conclusions' },
  { id: 'false_positive',    label: '⚠ False Positive',       desc: 'Benign activity flagged as threat' },
  { id: 'missed_evidence',   label: '🔍 Missed Evidence',     desc: 'Investigation omitted key artifacts' },
  { id: 'wrong_triage',      label: '⚡ Incorrect Severity',  desc: 'Severity / triage needs adjustment' },
  { id: 'wrong_remediation', label: '🛑 Unsafe Remediation',  desc: 'Recommended actions are inaccurate' },
]

export default function FeedbackModal({
  isOpen,
  incident,
  onClose,
  onFeedbackSubmitted,
}: FeedbackModalProps) {
  const [rating, setRating] = useState<number>(5)
  const [category, setCategory] = useState<string>('accurate')
  const [isFalsePositive, setIsFalsePositive] = useState<boolean>(false)
  const [correctedSeverity, setCorrectedSeverity] = useState<string>('')
  const [analystNote, setAnalystNote] = useState<string>('')
  const [submitting, setSubmitting] = useState<boolean>(false)

  const toast = useToast()

  if (!isOpen || !incident) return null

  const handleCategorySelect = (catId: string) => {
    setCategory(catId)
    if (catId === 'false_positive') {
      setIsFalsePositive(true)
    } else {
      setIsFalsePositive(false)
    }
  }

  const handleSubmit = async () => {
    setSubmitting(true)
    try {
      await api.submitFeedback(incident.id, {
        rating,
        is_false_positive: isFalsePositive,
        category,
        analyst_note: analystNote.trim() || undefined,
        corrected_severity: correctedSeverity || undefined,
      })
      toast.success('Feedback recorded! Model tuning dataset updated.')
      if (onFeedbackSubmitted) onFeedbackSubmitted()
      onClose()
    } catch {
      toast.error('Failed to submit feedback — is backend running?')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(5, 8, 16, 0.85)',
        backdropFilter: 'blur(8px)',
        zIndex: 10000,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 20,
      }}
      onClick={onClose}
    >
      <div
        className="glass-panel fade-in"
        style={{
          width: '100%',
          maxWidth: 520,
          background: 'var(--bg-surface)',
          border: '1px solid var(--border-bright)',
          borderRadius: 14,
          boxShadow: '0 20px 60px rgba(0,0,0,0.6)',
          padding: 24,
        }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
          <div>
            <span className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              {incident.incident_id} · Continuous Learning
            </span>
            <h2 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)', marginTop: 4 }}>
              Analyst Feedback & Review
            </h2>
          </div>
          <button
            onClick={onClose}
            style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
          >
            <X size={18} />
          </button>
        </div>

        {/* 1. Star Rating */}
        <div style={{ marginBottom: 18 }}>
          <div style={{ fontSize: 11, textTransform: 'uppercase', fontWeight: 700, color: 'var(--text-muted)', marginBottom: 8 }}>
            Overall Investigation Quality
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            {[1, 2, 3, 4, 5].map(star => (
              <button
                key={star}
                type="button"
                onClick={() => setRating(star)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  cursor: 'pointer',
                  padding: 4,
                  transition: 'transform 0.1s ease',
                }}
              >
                <Star
                  size={24}
                  fill={star <= rating ? '#facc15' : 'transparent'}
                  color={star <= rating ? '#facc15' : 'var(--text-muted)'}
                />
              </button>
            ))}
            <span style={{ marginLeft: 8, fontSize: 13, fontWeight: 600, color: 'var(--text-secondary)', alignSelf: 'center' }}>
              {rating === 5 ? 'Exceptional' : rating === 4 ? 'Accurate' : rating === 3 ? 'Acceptable' : rating === 2 ? 'Needs Work' : 'Inaccurate'}
            </span>
          </div>
        </div>

        {/* 2. Feedback Categories */}
        <div style={{ marginBottom: 18 }}>
          <div style={{ fontSize: 11, textTransform: 'uppercase', fontWeight: 700, color: 'var(--text-muted)', marginBottom: 8 }}>
            Evaluation Category
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            {CATEGORIES.map(cat => {
              const isSelected = category === cat.id
              return (
                <button
                  key={cat.id}
                  type="button"
                  onClick={() => handleCategorySelect(cat.id)}
                  style={{
                    background: isSelected ? 'rgba(99,179,237,0.12)' : 'var(--bg-deep)',
                    border: `1px solid ${isSelected ? 'var(--border-bright)' : 'var(--border-dim)'}`,
                    borderRadius: 8,
                    padding: '8px 10px',
                    textAlign: 'left',
                    cursor: 'pointer',
                    color: isSelected ? 'var(--text-accent)' : 'var(--text-secondary)',
                    transition: 'all 0.15s ease',
                  }}
                >
                  <div style={{ fontSize: 12, fontWeight: 600 }}>{cat.label}</div>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>{cat.desc}</div>
                </button>
              )
            })}
          </div>
        </div>

        {/* 3. Severity Correction (Optional) */}
        {category === 'wrong_triage' && (
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 11, textTransform: 'uppercase', fontWeight: 700, color: 'var(--text-muted)', marginBottom: 6 }}>
              Corrected Severity
            </div>
            <select
              value={correctedSeverity}
              onChange={e => setCorrectedSeverity(e.target.value)}
              style={{
                width: '100%',
                background: 'var(--bg-deep)',
                border: '1px solid var(--border-dim)',
                borderRadius: 'var(--radius-md)',
                padding: '8px 12px',
                color: 'var(--text-primary)',
                fontFamily: 'var(--font-sans)',
                fontSize: 13,
                outline: 'none',
              }}
            >
              <option value="">Keep current ({incident.severity})</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
        )}

        {/* 4. Analyst Notes / Corrections */}
        <div style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 11, textTransform: 'uppercase', fontWeight: 700, color: 'var(--text-muted)', marginBottom: 6 }}>
            Analyst Notes & Corrections (used for fine-tuning)
          </div>
          <textarea
            value={analystNote}
            onChange={e => setAnalystNote(e.target.value)}
            placeholder="Add context on what was missed or how the agent should improve its reasoning..."
            rows={3}
            style={{
              width: '100%',
              background: 'var(--bg-deep)',
              border: '1px solid var(--border-dim)',
              borderRadius: 'var(--radius-md)',
              padding: '10px 12px',
              color: 'var(--text-primary)',
              fontFamily: 'var(--font-sans)',
              fontSize: 13,
              resize: 'vertical',
              outline: 'none',
            }}
          />
        </div>

        {/* Action Buttons */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
          <button className="btn btn-ghost" onClick={onClose} disabled={submitting}>
            Cancel
          </button>
          <button className="btn btn-primary" onClick={handleSubmit} disabled={submitting}>
            {submitting ? (
              <><span className="spinner" style={{ width: 12, height: 12 }} /> Submitting...</>
            ) : (
              <><Send size={12} /> Submit Review</>
            )}
          </button>
        </div>
      </div>
    </div>
  )
}
