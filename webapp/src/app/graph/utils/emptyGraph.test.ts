/**
 * The empty-graph card must only claim "no graph yet" when that is true, and
 * must only offer a start the toolbar would also allow. The failure modes these
 * lock down: the card flashing before the payload has arrived, and a Start
 * button shown while a scan is already running or on a read-only saved version.
 */
import { describe, test, expect } from 'vitest'
import { resolveEmptyGraphState } from './emptyGraph'

const input = (over: Partial<Parameters<typeof resolveEmptyGraphState>[0]> = {}) => ({
  nodeCount: 0,
  isLoading: false,
  hasError: false,
  reconStatus: 'idle' as const,
  hasActivePartialRecons: false,
  viewingPastVersion: false,
  isActivatingVersion: false,
  ...over,
})

describe('resolveEmptyGraphState', () => {
  test('an idle project with no nodes offers to start a recon', () => {
    expect(resolveEmptyGraphState(input())).toBe('start')
  })

  test('a finished or failed recon that wrote nothing can be started again', () => {
    expect(resolveEmptyGraphState(input({ reconStatus: 'completed' }))).toBe('start')
    expect(resolveEmptyGraphState(input({ reconStatus: 'error' }))).toBe('start')
  })

  test('a graph with nodes never shows the card', () => {
    expect(resolveEmptyGraphState(input({ nodeCount: 1 }))).toBeNull()
  })

  test('nothing is shown until the payload has arrived', () => {
    expect(resolveEmptyGraphState(input({ nodeCount: undefined }))).toBeNull()
    expect(resolveEmptyGraphState(input({ isLoading: true }))).toBeNull()
  })

  test('a failed fetch is an error, not an empty graph', () => {
    expect(resolveEmptyGraphState(input({ hasError: true }))).toBeNull()
  })

  test('a scan in flight shows progress instead of a second start', () => {
    for (const reconStatus of ['starting', 'running', 'pausing', 'stopping'] as const) {
      expect(resolveEmptyGraphState(input({ reconStatus }))).toBe('running')
    }
    expect(resolveEmptyGraphState(input({ hasActivePartialRecons: true }))).toBe('running')
  })

  test('a paused recon offers to resume', () => {
    expect(resolveEmptyGraphState(input({ reconStatus: 'paused' }))).toBe('paused')
  })

  test('a partial recon blocks the resume, as it does on the toolbar', () => {
    expect(resolveEmptyGraphState(input({ reconStatus: 'paused', hasActivePartialRecons: true }))).toBe('running')
  })

  test('a saved version is read-only whatever the live scan is doing', () => {
    expect(resolveEmptyGraphState(input({ viewingPastVersion: true }))).toBe('readOnly')
    expect(resolveEmptyGraphState(input({ viewingPastVersion: true, reconStatus: 'running' }))).toBe('readOnly')
  })

  test('the gap in the middle of a version activation is not an empty graph', () => {
    expect(resolveEmptyGraphState(input({ isActivatingVersion: true }))).toBeNull()
  })
})
