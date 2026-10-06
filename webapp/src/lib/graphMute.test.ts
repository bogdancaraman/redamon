import { describe, test, expect } from 'vitest'
import { notMuted, agentCandidateConfirmedOrNA } from './graphMute'

describe('agentCandidateConfirmedOrNA (serialized_scan pending exclusion, §12-D)', () => {
  test('is scoped to serialized_scan only', () => {
    const p = agentCandidateConfirmedOrNA('v')
    expect(p).toContain("v.source = 'serialized_scan'")
  })

  test('gates on needs_agent_confirmation and the CONFIRMS edge', () => {
    const p = agentCandidateConfirmedOrNA('v')
    expect(p).toContain('needs_agent_confirmation')
    expect(p).toContain('(:ChainFinding)-[:CONFIRMS]->(v)')
  })

  test('is an exclusion (NOT ...), so other sources and confirmed candidates pass', () => {
    const p = agentCandidateConfirmedOrNA('v')
    expect(p.trimStart().startsWith('NOT (')).toBe(true)
  })

  test('binds the given variable', () => {
    expect(agentCandidateConfirmedOrNA('x')).toContain('x.source')
    expect(notMuted('x')).toContain('x.stale_since IS NULL')
  })
})
