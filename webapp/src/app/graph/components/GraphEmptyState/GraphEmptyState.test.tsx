/**
 * The card's one action has to be the right one for the scan's state: start when
 * idle, resume when paused, and no button at all when a scan is already running
 * or the graph on screen is a read-only saved version.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import { GraphEmptyState } from './GraphEmptyState'

const props = { onStartRecon: vi.fn(), onResumeRecon: vi.fn() }

beforeEach(() => vi.clearAllMocks())
// The suite has no `globals: true`, so RTL's auto-cleanup does not run.
afterEach(cleanup)

describe('GraphEmptyState', () => {
  test('start: explains the graph is empty and starts a recon', () => {
    render(<GraphEmptyState state="start" {...props} />)
    expect(screen.getByRole('heading', { name: 'No graph yet' })).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Start Recon Pipeline' }))
    expect(props.onStartRecon).toHaveBeenCalledTimes(1)
    expect(props.onResumeRecon).not.toHaveBeenCalled()
  })

  test('paused: the button resumes instead of starting a second recon', () => {
    render(<GraphEmptyState state="paused" {...props} />)
    fireEvent.click(screen.getByRole('button', { name: 'Resume Recon' }))
    expect(props.onResumeRecon).toHaveBeenCalledTimes(1)
    expect(props.onStartRecon).not.toHaveBeenCalled()
  })

  test('running: reports progress and offers no button', () => {
    render(<GraphEmptyState state="running" {...props} />)
    expect(screen.getByRole('heading', { name: 'Recon in progress' })).toBeTruthy()
    expect(screen.getByRole('status').textContent).toContain('Scan running')
    expect(screen.queryByRole('button')).toBeNull()
  })

  test('readOnly: a saved version offers no button', () => {
    render(<GraphEmptyState state="readOnly" {...props} />)
    expect(screen.getByRole('heading', { name: 'This version is empty' })).toBeTruthy()
    expect(screen.queryByRole('button')).toBeNull()
  })
})
