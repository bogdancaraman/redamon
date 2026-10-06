/**
 * SerializedScanSection: the toggle writes serializedScanEnabled, and the
 * TrafficMind dependency warning appears only when the scan is on AND the
 * capture proxy is off (plan §4.1).
 *
 * Run: npx vitest run src/components/projects/ProjectForm/sections/SerializedScanSection.test.tsx
 */
import type { ReactNode } from 'react'
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import { SerializedScanSection } from './SerializedScanSection'

vi.mock('../NodeInfoTooltip', () => ({ NodeInfoTooltip: () => null }))
vi.mock('next/link', () => ({ default: ({ children }: { children: ReactNode }) => <a>{children}</a> }))
vi.mock('@/components/ui', () => ({
  Toggle: ({ checked, onChange, ...rest }: { checked: boolean; onChange: (v: boolean) => void }) => (
    <button role="switch" aria-checked={checked} aria-label={(rest as Record<string, string>)['aria-label']}
            onClick={() => onChange(!checked)} />
  ),
}))

afterEach(cleanup)

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

  test('warns when enabled and the capture proxy is off', () => {
    renderSection({ serializedScanEnabled: true, captureProxyEnabled: false })
    expect(screen.getByText(/captured request traffic/)).toBeTruthy()
    expect(screen.getByText(/thinner corpus/)).toBeTruthy()
  })

  test('no warning when the capture proxy is on', () => {
    renderSection({ serializedScanEnabled: true, captureProxyEnabled: true })
    expect(screen.queryByText(/captured request traffic/)).toBeNull()
  })

  test('no warning when the scan is off', () => {
    renderSection({ serializedScanEnabled: false, captureProxyEnabled: false })
    expect(screen.queryByText(/captured request traffic/)).toBeNull()
  })
})
