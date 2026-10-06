/**
 * What the graph map shows when the project has no nodes at all.
 *
 * The card's button has to agree with the toolbar's Start Recon Pipeline button:
 * offering "Start" while a scan is already in flight, or on a read-only saved
 * version, would open a confirm modal for a start the backend then refuses. Kept
 * pure so the rule is testable without mounting the page.
 */
import type { ReconStatus } from '@/lib/recon-types'

export type EmptyGraphState = 'start' | 'paused' | 'running' | 'readOnly'

export interface EmptyGraphInput {
  /**
   * Node count of the UNFILTERED payload; undefined until it has arrived. A
   * graph whose nodes are all hidden by a filter is not an empty graph, so the
   * filtered or clustered count must never be passed here.
   */
  nodeCount: number | undefined
  isLoading: boolean
  hasError: boolean
  reconStatus: ReconStatus
  hasActivePartialRecons: boolean
  viewingPastVersion: boolean
  /** The live graph is being swapped for a saved version's snapshot. */
  isActivatingVersion: boolean
}

/** The empty-state variant to show, or null when the map should render as usual. */
export function resolveEmptyGraphState({
  nodeCount,
  isLoading,
  hasError,
  reconStatus,
  hasActivePartialRecons,
  viewingPastVersion,
  isActivatingVersion,
}: EmptyGraphInput): EmptyGraphState | null {
  if (isLoading || hasError || nodeCount !== 0) return null
  if (viewingPastVersion) return 'readOnly'
  // An activation clears the live graph, then restores the snapshot: the graph
  // is empty in between, and calling that "no graph yet" would be wrong.
  if (isActivatingVersion) return null
  if (hasActivePartialRecons) return 'running'
  if (reconStatus === 'paused') return 'paused'
  if (reconStatus === 'starting' || reconStatus === 'running' || reconStatus === 'pausing' || reconStatus === 'stopping') {
    return 'running'
  }
  return 'start'
}
