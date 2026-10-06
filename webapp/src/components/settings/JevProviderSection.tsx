'use client'

import type { ReactNode } from 'react'
import { ExternalLink, Loader2, Pencil, Plus, RefreshCw, Trash2 } from 'lucide-react'
import { PROVIDER_TYPES, JEV_MODEL } from '@/lib/llmProviderPresets'
import { LlmProviderForm } from './LlmProviderForm'
import type { ProviderData } from './LlmProviderForm'
import settingsStyles from './Settings.module.css'
import styles from './JevProviderSection.module.css'

const JEV_TYPE = PROVIDER_TYPES.find(p => p.id === 'jev')!

interface JevProviderSectionProps {
  userId: string
  /** The user's Jev row (masked), or null when none is saved. */
  provider: ProviderData | null
  loading: boolean
  /** The provider list could not be loaded: "no token" would be a guess. */
  error: boolean
  onRetry: () => void
  formOpen: boolean
  onOpenForm: () => void
  onFormDone: (saved: boolean) => void
  onDelete: (providerId: string) => void
  onDirtyChange?: (dirty: boolean) => void
  /** The Check API usage chip for the saved row. */
  usageChip?: ReactNode
}

/**
 * The TypeSafe AI (Jev) token, kept apart from the chat providers: Jev answers
 * typed questions for recon hooks and never appears in a model picker.
 */
export function JevProviderSection({
  userId, provider, loading, error, onRetry, formOpen, onOpenForm, onFormDone, onDelete,
  onDirtyChange, usageChip,
}: JevProviderSectionProps) {
  const Icon = JEV_TYPE.Icon

  let body: ReactNode
  if (loading) {
    body = <div className={settingsStyles.emptyState}><Loader2 size={16} className={settingsStyles.spin} /> Loading...</div>
  } else if (error) {
    body = (
      <div className={styles.error} role="alert">
        <span>Couldn&apos;t load your providers.</span>
        <button type="button" className="secondaryButton" onClick={onRetry}>
          <RefreshCw size={12} /> Retry
        </button>
      </div>
    )
  } else if (formOpen) {
    body = (
      <LlmProviderForm
        userId={userId}
        provider={provider}
        lockedType="jev"
        onDirtyChange={onDirtyChange}
        onSave={() => onFormDone(true)}
        onCancel={() => onFormDone(false)}
      />
    )
  } else if (!provider) {
    body = (
      <div className={styles.empty}>
        <div className={styles.emptyActions}>
          <button type="button" className="primaryButton" onClick={onOpenForm}>
            <Plus size={14} /> Add token
          </button>
          <a className={settingsStyles.apiKeyLink} href={JEV_TYPE.apiKeyUrl} target="_blank" rel="noopener noreferrer">
            Get an API key <ExternalLink size={12} />
          </a>
        </div>
      </div>
    )
  } else {
    body = (
      <div className={settingsStyles.providerCard}>
        <span className={settingsStyles.providerIcon} aria-label={JEV_TYPE.name}>
          <Icon size={28} />
        </span>
        <div className={settingsStyles.providerInfo}>
          <div className={settingsStyles.providerName}>{provider.name || JEV_TYPE.name}</div>
          <div className={settingsStyles.providerMeta}>
            <span data-testid="jev-masked-key">{provider.apiKey}</span> - {provider.modelIdentifier || JEV_MODEL}
          </div>
          {usageChip}
        </div>
        <div className={settingsStyles.providerActions}>
          <button className="iconButton" title="Edit" aria-label="Edit Jev token" onClick={onOpenForm}>
            <Pencil size={14} />
          </button>
          <button className="iconButton" title="Delete" aria-label="Delete Jev token"
            onClick={() => provider.id && onDelete(provider.id)}>
            <Trash2 size={14} />
          </button>
        </div>
      </div>
    )
  }

  return (
    <section className={styles.section} aria-labelledby="jev-provider-title">
      <h3 id="jev-provider-title" className={styles.title}>{JEV_TYPE.name}</h3>
      <p className={styles.intro}>
        Jev answers typed questions for recon hooks. Four can run on Jev instead of the LLM: FFuf
        extensions, Nuclei tags, WAF classification and takeover disambiguation. Five more run
        only on Jev: page-type labels, FFuf base-path ranking, Hakrawler seed order, the
        tool-health check and the serialized-object ranking. A project uses it only for the
        hooks it sets to Jev.
        It is not a chat model and never appears in a model picker.
      </p>
      {body}
    </section>
  )
}
