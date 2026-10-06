/**
 * Soft dependency gate for the serialized-object scan (plan §4.1).
 *
 * The scan is passive and in-memory, so it produces (thinner) value with no
 * capture proxy. But the agent's confirmation half needs captured request
 * traffic to confirm a candidate, so TrafficMind (`captureProxyEnabled`) is a
 * soft prerequisite. This WARNS on a switch-on while capture is off; it does NOT
 * refuse, mirroring the soft `jevImportWarnings` posture rather than the hard
 * `validateJevEngineChange` refusal -- a fail-closed block here would be a false
 * guarantee (the scan still runs and still writes candidates).
 *
 * Product decision flagged in the plan: if the corpus ever becomes a HARD
 * dependency, convert this to the `validateJevEngineChange` refusal shape.
 *
 * Pure and synchronous: it reads only the two booleans on the row being written
 * (merged with the existing row), never the database. Never throws.
 */

type Row = Record<string, unknown> | null | undefined

export const SERIALIZED_SCAN_CAPTURE_WARNING =
  'Serialized object scan is on, but TrafficMind (HTTP capture) is off. ' +
  'Detection still runs, but the agent needs captured request traffic to ' +
  'confirm candidates. Enable it under Scan Modules > Traffic capture, or on ' +
  'the TrafficMind page.'

/** True when the write turns serializedScanEnabled on (false/absent -> true). */
export function serializedScanSwitchedOn(before: Row, next: Row): boolean {
  return next?.serializedScanEnabled === true && before?.serializedScanEnabled !== true
}

/**
 * A warning (never a refusal) when a switch-on happens while capture is
 * EXPLICITLY off in the merged state. Absent capture state does not warn: we
 * only warn when we can see it is off, so a partial write never invents one.
 */
export function validateSerializedScanChange(before: Row, next: Row): string[] {
  if (!serializedScanSwitchedOn(before, next)) return []
  const capture = next?.captureProxyEnabled ?? before?.captureProxyEnabled
  if (capture !== false) return []
  return [SERIALIZED_SCAN_CAPTURE_WARNING]
}
