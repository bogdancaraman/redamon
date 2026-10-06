'use client'

import { useState } from 'react'
import Link from 'next/link'
import { ChevronDown, Binary, Play } from 'lucide-react'
import { Toggle } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface SerializedScanSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
}

/**
 * Serialized object scan: a passive, in-memory recon module (GROUP 5b, beside
 * JS Recon). It flags serialized-object signatures across every family as
 * info-severity :Vulnerability candidates; the agent's deserialization skill
 * confirms them out of band. TrafficMind (capture proxy) is a soft prerequisite
 * -- without captured traffic the agent has no request-side corpus to confirm
 * against, so we surface a warning rather than block (plan §4.1).
 */
export function SerializedScanSection({ data, updateField, onRun }: SerializedScanSectionProps) {
  const [isOpen, setIsOpen] = useState(true)

  const d = data as unknown as {
    serializedScanEnabled?: boolean
    captureProxyEnabled?: boolean
  }
  const enabled = !!d.serializedScanEnabled
  const captureOff = !d.captureProxyEnabled

  return (
    <div className={`${styles.section} ${styles.formSkin}`}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Binary size={16} />
          Serialized Object Scan
          <NodeInfoTooltip section="SerializedScan" />
          <span className={styles.badgePassive}>Passive</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && enabled && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onRun() }}
              className={styles.runPartialButton}
              title="Run Serialized Object Scan"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={enabled}
              onChange={(checked) => updateField('serializedScanEnabled' as keyof FormData, checked as never)}
              aria-label="Enable Serialized Object Scan"
            />
          </div>
          <ChevronDown size={16} className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`} />
        </div>
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Scans the response headers, Set-Cookie values and enumerated parameters the pipeline already holds
            for serialized-object signatures: native Java, polymorphic JSON (Jackson/FastJSON), XMLDecoder,
            XStream, SnakeYAML, PHP, Python pickle, .NET BinaryFormatter / ViewState, Ruby Marshal and Hessian.
            It is passive and in-memory, sends no extra traffic and never deserializes anything. Each hit becomes
            an info-severity candidate the agent&apos;s deserialization skill confirms with a non-destructive
            out-of-band oracle.
          </p>

          {enabled && captureOff && (
            <p className={`${styles.fieldHint} ${styles.fieldHintCaution}`}>
              Works best with TrafficMind (HTTP capture) enabled: the agent needs captured request traffic to
              confirm candidates. Enable it under Scan Modules &gt; Traffic capture, or on the{' '}
              <Link href="/traffic" style={{ color: 'var(--accent-primary)', fontWeight: 500 }}>
                TrafficMind
              </Link>{' '}
              page. Detection still runs without it, but with a thinner corpus.
            </p>
          )}
        </div>
      )}
    </div>
  )
}
