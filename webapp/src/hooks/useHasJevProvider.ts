'use client'

import { useCallback, useEffect, useState } from 'react'
import { useProject } from '@/providers/ProjectProvider'

export type JevProviderStatus = 'loading' | 'yes' | 'no' | 'error'

/** The masked Jev row, as the providers GET returns it to a browser. */
export interface JevProviderRow {
  id: string
  apiKey: string
  modelIdentifier: string
}

const CHANGED_EVENT = 'redamon:jev-provider-changed'

/**
 * Tell every mounted Jev lookup that the token was added, replaced or removed.
 *
 * One form holds several lookups (the Target AI panel and each tool section with a Jev hook);
 * without this, saving the token in one would leave the others reading "no token"
 * until the page reloads.
 */
export function notifyJevProviderChanged(): void {
  if (typeof window !== 'undefined') window.dispatchEvent(new Event(CHANGED_EVENT))
}

/**
 * The acting user's TypeSafe Jev token: whether there is one, the masked row, and a
 * way to look again.
 *
 * A failed fetch is 'error', never 'no': telling a user "you have no token" when
 * the lookup actually failed would push them to re-add a token they already have.
 * Don't copy ShodanSection's hook, which reports a failed fetch as "no key".
 *
 * This is a convenience signal for the form only; the server
 * (validateJevEngineChange) is the authority on whether a switch-on is allowed.
 */
export function useJevProvider(): {
  status: JevProviderStatus
  provider: JevProviderRow | null
  refresh: () => void
} {
  const { userId } = useProject()
  const [status, setStatus] = useState<JevProviderStatus>('loading')
  const [provider, setProvider] = useState<JevProviderRow | null>(null)
  const [nonce, setNonce] = useState(0)
  const refresh = useCallback(() => setNonce(n => n + 1), [])

  useEffect(() => {
    window.addEventListener(CHANGED_EVENT, refresh)
    return () => window.removeEventListener(CHANGED_EVENT, refresh)
  }, [refresh])

  useEffect(() => {
    if (!userId) {
      setStatus('loading')
      return
    }
    let cancelled = false
    setStatus('loading')
    ;(async () => {
      try {
        const resp = await fetch(`/api/users/${userId}/llm-providers`)
        if (!resp.ok) {
          if (!cancelled) setStatus('error')
          return
        }
        const rows = await resp.json()
        if (cancelled) return
        // A 200 that is not a list (an error payload, a proxy page) tells us
        // nothing about the account, so it is a failed lookup, not "no token".
        if (!Array.isArray(rows)) {
          setStatus('error')
          return
        }
        const jev = rows.find((r: { providerType?: string }) => r?.providerType === 'jev') ?? null
        setProvider(jev)
        setStatus(jev ? 'yes' : 'no')
      } catch {
        if (!cancelled) setStatus('error')
      }
    })()
    return () => { cancelled = true }
  }, [userId, nonce])

  return { status, provider, refresh }
}

/** Whether the acting user has a Jev token. See useJevProvider. */
export function useHasJevProvider(): JevProviderStatus {
  return useJevProvider().status
}
