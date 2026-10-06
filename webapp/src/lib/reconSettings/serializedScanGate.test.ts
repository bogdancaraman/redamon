import { describe, test, expect } from 'vitest'
import {
  validateSerializedScanChange,
  serializedScanSwitchedOn,
  SERIALIZED_SCAN_CAPTURE_WARNING,
} from './serializedScanGate'

describe('serializedScanGate (warn, never block)', () => {
  test('warns on switch-on while capture is explicitly off', () => {
    const w = validateSerializedScanChange(
      { serializedScanEnabled: false, captureProxyEnabled: false },
      { serializedScanEnabled: true, captureProxyEnabled: false },
    )
    expect(w).toEqual([SERIALIZED_SCAN_CAPTURE_WARNING])
  })

  test('no warning when capture is on', () => {
    expect(validateSerializedScanChange(
      { serializedScanEnabled: false },
      { serializedScanEnabled: true, captureProxyEnabled: true },
    )).toEqual([])
  })

  test('no warning when already on (not a switch-on)', () => {
    expect(validateSerializedScanChange(
      { serializedScanEnabled: true, captureProxyEnabled: false },
      { serializedScanEnabled: true, captureProxyEnabled: false },
    )).toEqual([])
  })

  test('no warning when capture state is absent (never invents one)', () => {
    expect(validateSerializedScanChange(
      null,
      { serializedScanEnabled: true },
    )).toEqual([])
  })

  test('capture falls back to the existing row on a partial write', () => {
    // update that flips serialized on but omits captureProxyEnabled -> uses before
    expect(validateSerializedScanChange(
      { serializedScanEnabled: false, captureProxyEnabled: false },
      { serializedScanEnabled: true },
    )).toEqual([SERIALIZED_SCAN_CAPTURE_WARNING])
  })

  test('switch-on detection', () => {
    expect(serializedScanSwitchedOn({ serializedScanEnabled: false }, { serializedScanEnabled: true })).toBe(true)
    expect(serializedScanSwitchedOn({ serializedScanEnabled: true }, { serializedScanEnabled: true })).toBe(false)
    expect(serializedScanSwitchedOn(null, { serializedScanEnabled: false })).toBe(false)
  })

  test('it is a warning, not a refusal (returns an array, never throws)', () => {
    expect(Array.isArray(validateSerializedScanChange(null, null))).toBe(true)
    expect(validateSerializedScanChange(null, null)).toEqual([])
  })
})
