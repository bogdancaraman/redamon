/**
 * SerializedScanSection: the toggle writes serializedScanEnabled, and the
 * TrafficMind dependency warning appears only when the scan is on AND the
 * capture proxy is off (plan §4.1).
 *
 * Run: npx vitest run src/components/projects/ProjectForm/sections/SerializedScanSection.test.tsx
 */
import type { ReactNode } from 'react'
import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import { SerializedScanSection } from './SerializedScanSection'

vi.mock('../NodeInfoTooltip', () => ({ NodeInfoTooltip: () => null }))
// The Jev ranking control looks up the acting user's Jev token.
vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'u1' }) }))
vi.mock('next/link', () => ({ default: ({ children }: { children: ReactNode }) => <a>{children}</a> }))
vi.mock('@/components/ui', () => ({
  Toggle: ({ checked, onChange, ...rest }: { checked: boolean; onChange: (v: boolean) => void }) => (
    <button role="switch" aria-checked={checked} aria-label={(rest as Record<string, string>)['aria-label']}
            onClick={() => onChange(!checked)} />
  ),
}))

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, status: 200, json: async () => [] })))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

function renderSection(data: Record<string, unknown>) {
  const updateField = vi.fn()
  const view = render(<SerializedScanSection data={data as never} updateField={updateField as never} />)
  return { ...view, updateField }
}

describe('SerializedScanSection', () => {
  test('toggle flips serializedScanEnabled', () => {
    const { updateField } = renderSection({ serializedScanEnabled: false, captureProxyEnabled: true })
    fireEvent.click(screen.getByRole('switch', { name: /Enable Serialized Object Scan/i }))
    expect(updateField).toHaveBeenCalledWith('serializedScanEnabled', true)
  })

  const SKILL_ON = { builtIn: { deserialization: true } }

  test('warns when enabled and the capture proxy is off', () => {
    renderSection({ serializedScanEnabled: true, captureProxyEnabled: false, attackSkillConfig: SKILL_ON })
    expect(screen.getByText(/captured request traffic/)).toBeTruthy()
    expect(screen.getByText(/thinner corpus/)).toBeTruthy()
  })

  test('no capture warning when the capture proxy is on', () => {
    renderSection({ serializedScanEnabled: true, captureProxyEnabled: true, attackSkillConfig: SKILL_ON })
    expect(screen.queryByText(/captured request traffic/)).toBeNull()
  })

  test('the Jev ranking control shows only while the scan is on', () => {
    // As in the sibling sections: a hook whose scan is off never runs, so a switch
    // there would pass the token check for nothing.
    renderSection({ serializedScanEnabled: false, aiInPipeline: true })
    expect(screen.queryByRole('group', { name: 'Jev hook' })).toBeNull()
    cleanup()
    renderSection({ serializedScanEnabled: true, aiInPipeline: true, captureProxyEnabled: true })
    expect(screen.getByRole('group', { name: 'Jev hook' })).toBeTruthy()
  })

  test('no warnings when the scan is off', () => {
    renderSection({ serializedScanEnabled: false, captureProxyEnabled: false })
    expect(screen.queryByText(/captured request traffic/)).toBeNull()
    expect(screen.queryByText(/Half a cycle/)).toBeNull()
  })

  // The detect->confirm handshake: recon flags, the agent skill confirms.
  test('alerts to enable the agent skill when the scan is on but the skill is off (key absent)', () => {
    renderSection({ serializedScanEnabled: true, captureProxyEnabled: true })
    expect(screen.getByText(/Half a cycle/)).toBeTruthy()
    expect(screen.getByText(/Attack Skills/)).toBeTruthy()
  })

  test('alerts when the skill key is present but false', () => {
    renderSection({ serializedScanEnabled: true, captureProxyEnabled: true,
                    attackSkillConfig: { builtIn: { deserialization: false } } })
    expect(screen.getByText(/Half a cycle/)).toBeTruthy()
  })

  test('no agent-skill alert when the deserialization skill is enabled', () => {
    renderSection({ serializedScanEnabled: true, captureProxyEnabled: true, attackSkillConfig: SKILL_ON })
    expect(screen.queryByText(/Half a cycle/)).toBeNull()
  })

  test('no agent-skill alert when the scan is off even if the skill is off', () => {
    renderSection({ serializedScanEnabled: false, attackSkillConfig: { builtIn: { deserialization: false } } })
    expect(screen.queryByText(/Half a cycle/)).toBeNull()
  })
})
