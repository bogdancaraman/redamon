'use client'

import type { Project } from '@prisma/client'
import { WikiInfoButton } from '@/components/ui/WikiInfoButton'
import styles from '../ProjectForm.module.css'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface DeserializationSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

// Canonical order: the agent's prompt builder reads the same ids.
const RUNTIMES: { id: string; label: string }[] = [
  { id: 'java', label: 'Java (native)' },
  { id: 'java_typed', label: 'Java JSON / XML / YAML' },
  { id: 'python', label: 'Python' },
  { id: 'php', label: 'PHP' },
  { id: 'node', label: 'Node' },
  { id: 'ruby', label: 'Ruby' },
  { id: 'dotnet', label: '.NET' },
]
const ALL_RUNTIMES = RUNTIMES.map(r => r.id).join(',')

const ROW_STYLE: React.CSSProperties = {
  marginBottom: 'var(--space-4)',
}

const GROUP_HEADER_STYLE: React.CSSProperties = {
  fontSize: 'var(--text-sm)',
  fontWeight: 'var(--font-semibold)',
  color: 'var(--text-primary)',
  marginTop: 'var(--space-5)',
  marginBottom: 'var(--space-3)',
  paddingBottom: 'var(--space-2)',
  borderBottom: '1px solid var(--border-subtle, var(--border-default))',
}

const FIRST_GROUP_HEADER_STYLE: React.CSSProperties = {
  ...GROUP_HEADER_STYLE,
  marginTop: 'var(--space-3)',
}

const CHECKBOX_LABEL_STYLE: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  gap: 'var(--space-2)',
}

const RUNTIME_GRID_STYLE: React.CSSProperties = {
  display: 'flex',
  flexWrap: 'wrap',
  gap: 'var(--space-2) var(--space-4)',
}

function parseRuntimes(value: string | null | undefined): Set<string> {
  const known = new Set(RUNTIMES.map(r => r.id))
  const picked = (value ?? ALL_RUNTIMES).split(',').map(s => s.trim().toLowerCase()).filter(s => known.has(s))
  return new Set(picked.length ? picked : RUNTIMES.map(r => r.id))
}

export function DeserializationSection({ data, updateField }: DeserializationSectionProps) {
  const oobOn = data.deserializationOobCallbackEnabled ?? true
  const runtimes = parseRuntimes(data.deserializationRuntimes)
  const phpOn = runtimes.has('php')

  const toggleRuntime = (id: string, on: boolean) => {
    const next = new Set(runtimes)
    if (on) next.add(id)
    else next.delete(id)
    updateField('deserializationRuntimes', RUNTIMES.map(r => r.id).filter(r => next.has(r)).join(','))
  }

  return (
    <div style={{ padding: 'var(--space-3) var(--space-4)', position: 'relative' }}>
      <div style={{ position: 'absolute', top: 8, right: 16 }}>
        <WikiInfoButton target="https://github.com/samugit83/redamon/wiki/Agent-Skills#insecure-deserialization" title="Open Agent Skills wiki page" />
      </div>
      <p className={styles.sectionDescription} style={{ marginBottom: 'var(--space-4)', paddingRight: '2.5rem' }}>
        Choose which sub-workflows the agent prompt carries. A block whose switch is off is left
        out of the prompt, and the agent is told not to use it.
      </p>

      <h3 style={FIRST_GROUP_HEADER_STYLE}>Confirmation channels</h3>

      <div className={styles.fieldRow} style={ROW_STYLE}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel} style={CHECKBOX_LABEL_STYLE}>
            <input
              type="checkbox"
              checked={oobOn}
              onChange={(e) => updateField('deserializationOobCallbackEnabled', e.target.checked)}
            />
            OOB callback workflow (interactsh)
          </label>
          <span className={styles.fieldHint}>
            Adds the out-of-band oracle: the agent registers a domain on the OOB provider and sends a
            harmless object that makes the target look it up. Disable when external callbacks are
            forbidden; the agent then confirms through the timing and error channels only.
          </span>
        </div>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel}>OOB Provider</label>
          <input
            type="text"
            className="textInput"
            value={data.deserializationOobProvider ?? 'oast.fun'}
            onChange={(e) => updateField('deserializationOobProvider', e.target.value)}
            placeholder="oast.fun"
            disabled={!oobOn}
          />
          <span className={styles.fieldHint}>
            interactsh server. Use a self-hosted instance if oast.fun is blocked. Only used when the
            OOB callback workflow is enabled.
          </span>
        </div>
      </div>

      <div className={styles.fieldRow} style={ROW_STYLE}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel} style={CHECKBOX_LABEL_STYLE}>
            <input
              type="checkbox"
              checked={data.deserializationTimingEnabled ?? true}
              onChange={(e) => updateField('deserializationTimingEnabled', e.target.checked)}
            />
            Timing channel
          </label>
          <span className={styles.fieldHint}>
            Adds the timing sub-prompt: the agent compares response times to prove the server tried to
            connect while deserializing. It holds a request open on the target until a delay or timeout
            ends; disable on fragile targets. The error channel is always available.
          </span>
        </div>
      </div>

      <h3 style={GROUP_HEADER_STYLE}>Scope</h3>

      <div className={styles.fieldRow} style={ROW_STYLE}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel} style={CHECKBOX_LABEL_STYLE}>
            <input
              type="checkbox"
              checked={data.deserializationFindSinksEnabled ?? true}
              onChange={(e) => updateField('deserializationFindSinksEnabled', e.target.checked)}
            />
            Find sinks beyond recon candidates
          </label>
          <span className={styles.fieldHint}>
            Adds the sweep of every cookie, header, parameter and body for serialized blobs recon never
            flagged, and the format reference. When off, the agent only confirms recon&apos;s candidates.
          </span>
        </div>
      </div>

      <div className={styles.fieldRow} style={ROW_STYLE}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel}>Runtimes to cover</label>
          <div style={RUNTIME_GRID_STYLE}>
            {RUNTIMES.map(r => {
              const checked = runtimes.has(r.id)
              return (
                <label key={r.id} className={styles.fieldLabel} style={CHECKBOX_LABEL_STYLE}>
                  <input
                    type="checkbox"
                    checked={checked}
                    disabled={checked && runtimes.size === 1}
                    onChange={(e) => toggleRuntime(r.id, e.target.checked)}
                  />
                  {r.label}
                </label>
              )
            })}
          </div>
          <span className={styles.fieldHint}>
            Only the selected runtimes&apos; oracle blocks ship in the prompt. Narrow it only when you
            already know the target stack; a candidate in another runtime gets the error channel only.
          </span>
        </div>
      </div>

      <h3 style={GROUP_HEADER_STYLE}>Impact (off by default)</h3>

      <div className={styles.fieldRow} style={ROW_STYLE}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel} style={CHECKBOX_LABEL_STYLE}>
            <input
              type="checkbox"
              checked={data.deserializationExecGadgetsEnabled ?? false}
              onChange={(e) => updateField('deserializationExecGadgetsEnabled', e.target.checked)}
              disabled={!oobOn}
            />
            Exec gadget step (RCE proof)
          </label>
          <span className={styles.fieldHint}>
            After a sink is confirmed, the agent delivers ONE code-execution gadget that runs a command
            on the target and sends its output back over the OOB callback. Needs the OOB callback and the
            move to the exploitation phase. Enable only with explicit RoE permission.
            {!oobOn && ' Disabled while the OOB callback is off.'}
          </span>
        </div>
      </div>

      <div className={styles.fieldRow} style={ROW_STYLE}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel} style={CHECKBOX_LABEL_STYLE}>
            <input
              type="checkbox"
              checked={data.deserializationPharEnabled ?? false}
              onChange={(e) => updateField('deserializationPharEnabled', e.target.checked)}
              disabled={!phpOn}
            />
            PHAR polyglot upload
          </label>
          <span className={styles.fieldHint}>
            Adds the PHP PHAR polyglot sub-prompt. UPLOADS a file to the target; enable only with explicit
            RoE permission.
            {!phpOn && ' Disabled while PHP is not among the runtimes.'}
          </span>
        </div>
      </div>
    </div>
  )
}
