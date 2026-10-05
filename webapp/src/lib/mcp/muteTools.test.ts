/**
 * mute_findings, unmute_findings and search_muted_findings: hiding a finding
 * over MCP, bringing one back, and finding the ids to do it with.
 *
 * The surface used to guarantee "only a person mutes". What replaces that
 * guarantee is enforced HERE and in the agent, so each control is pinned:
 *
 *  - the opt-in permission, the mute bucket, and ownership before anything;
 *  - the per-call cap, and that nothing caps a token's total;
 *  - busy checks that fail closed, before the write and (for activation) after;
 *  - the exact body the agent receives: the MCP source, the owner as muted_by,
 *    the token prefix, and the exemptions that protect a person's unmute;
 *  - a lost answer is `<op>_outcome_unknown`, never "unavailable";
 *  - the unmute writes its exemptions FIRST and removes exactly the ones it
 *    created when the unmute does not happen.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const h = vi.hoisted(() => ({
  findProject: vi.fn(),
  exemptionFind: vi.fn(),
  exemptionCreate: vi.fn(),
  exemptionDelete: vi.fn(),
  nodeFilter: vi.fn(),
  writeAudit: vi.fn(),
  activationBusy: vi.fn(),
  nodeFilterWriter: vi.fn(),
  scanWriters: vi.fn(),
  invalidateCache: vi.fn(),
  fetch: vi.fn(),
  /** Every agent op and exemption write, in call order. */
  order: [] as string[],
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => h.findProject(...a) },
    nodeFilterExemption: {
      findMany: (...a: unknown[]) => h.exemptionFind(...a),
      createManyAndReturn: (...a: unknown[]) => { h.order.push('exemptions.create'); return h.exemptionCreate(...a) },
      deleteMany: (...a: unknown[]) => { h.order.push('exemptions.delete'); return h.exemptionDelete(...a) },
    },
    projectNodeFilter: { findUnique: (...a: unknown[]) => h.nodeFilter(...a) },
    mcpAccessToken: { update: () => Promise.resolve() },
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.writeAudit(...a) }))
vi.mock('@/lib/activationLock', () => ({
  activationBusy: (...a: unknown[]) => { h.order.push('activation'); return h.activationBusy(...a) },
}))
vi.mock('@/lib/nodeFilterRun', () => ({
  describeNodeFilterWriter: (...a: unknown[]) => { h.order.push('applyCheck'); return h.nodeFilterWriter(...a) },
}))
vi.mock('@/lib/graphWriters', () => ({
  describeScanWriters: (...a: unknown[]) => { h.order.push('scanCheck'); return h.scanWriters(...a) },
}))
vi.mock('@/app/api/graph/cache', () => ({ invalidateCache: (...a: unknown[]) => h.invalidateCache(...a) }))

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { McpAccessDenied, McpScopeError, __resetRateLimiter, bucketSpec } from '@/lib/mcpAuth'
import { McpToolError } from './errors'
import {
  MUTED_VIA_FILTERS,
  MUTE_MAX_REFS,
  UNMUTE_MAX_REFS,
  muteFindings,
  searchMutedFindings,
  unmuteFindings,
} from './muteTools'
import { buildMcpServer } from './server'
import type { McpContext } from './tools'

const TOKEN_PREFIX = 'rdmn_mcp_ab12cd34'

/** The agent's request and answer per op, shared with tests/test_triage_mixin.py. */
const CONTRACT = JSON.parse(readFileSync(join(__dirname, 'contracts/triage_mute.json'), 'utf-8')) as Record<
  'mute_many' | 'resolve_muted' | 'unmute_many',
  { request: Record<string, unknown>; response: Record<string, unknown> }
>

const ctx = (scopes: string[] = ['triage:mute', 'triage:read'], tokenId = 't1'): McpContext => ({
  token: { tokenId, userId: 'owner', tokenPrefix: TOKEN_PREFIX, name: 'agent', scopes: scopes as never },
})

type AgentAnswer = unknown | { __status: number; body?: unknown } | { __throw: unknown }

/** What the agent answers per op. A missing op is a test bug, so it throws. */
let agent: Record<string, AgentAnswer>

function sent(op?: string): Record<string, unknown>[] {
  return h.fetch.mock.calls
    .map(c => JSON.parse((c[1] as RequestInit).body as string) as Record<string, unknown>)
    .filter(b => !op || b.op === op)
}

const muteItem = (over: Record<string, unknown> = {}) => ({
  ref: 'v1', key: 'v1', label: 'Vulnerability', node_id: '812', name: 'Banner', severity: 'info',
  outcome: 'muted', was_via: null, ...over,
})

const refused = (code: string) =>
  Object.assign(new TypeError('fetch failed'), { cause: Object.assign(new Error(code), { code }) })

const timeout = () => Object.assign(new Error('The operation was aborted due to timeout'), { name: 'TimeoutError' })

beforeEach(() => {
  vi.clearAllMocks()
  h.order.length = 0
  __resetRateLimiter()
  vi.unstubAllEnvs()
  vi.spyOn(console, 'error').mockImplementation(() => undefined)
  h.findProject.mockResolvedValue({ id: 'p1', userId: 'owner' })
  h.exemptionFind.mockResolvedValue([{ label: 'Secret', nodeKey: 's9' }])
  h.exemptionCreate.mockImplementation(({ data }: { data: { label: string; nodeKey: string }[] }) =>
    Promise.resolve(data.map(d => ({ label: d.label, nodeKey: d.nodeKey }))))
  h.exemptionDelete.mockResolvedValue({ count: 0 })
  h.nodeFilter.mockResolvedValue({ rules: { version: 1, kinds: { 'vuln.nuclei': {
    enabled: true, action: 'mute', rules: [{ id: 'k3f9a2', name: 'Informational templates', enabled: true, all: [] }],
  } } } })
  h.activationBusy.mockResolvedValue(false)
  h.nodeFilterWriter.mockResolvedValue(null)
  h.scanWriters.mockResolvedValue(null)

  agent = {
    mute_many: { items: [muteItem()], not_found: [], mcp_gated: true },
    resolve_muted: {
      to_unmute: [{ ref: 'v1', key: 'v1', label: 'Vulnerability', node_id: '812', muted_by: 'owner', was_via: 'mcp' }],
      skipped_rule_mute: [], not_found: [], mcp_gated: true,
    },
    unmute_many: {
      unmuted: 1, items: [{ key: 'v1', label: 'Vulnerability', muted_by: 'owner', was_via: 'mcp' }],
      skipped: [], mcp_gated: true,
    },
    list_muted: { findings: [], total: 0, mcp_gated: true },
    muted_facets: { total: 0, by_person: 0, by_mcp: 0, labels: {}, rules: [], tokens: [], mcp_gated: true },
  }
  h.fetch.mockImplementation(async (_url: string, init: RequestInit) => {
    const op = JSON.parse(init.body as string).op as string
    h.order.push(op)
    if (!(op in agent)) throw new Error(`test agent has no answer for ${op}`)
    const a = agent[op] as Record<string, unknown>
    if (a && typeof a === 'object' && '__throw' in a) throw a.__throw
    if (a && typeof a === 'object' && '__status' in a) {
      return { ok: false, status: a.__status, json: async () => a.body ?? {} }
    }
    return { ok: true, status: 200, json: async () => a }
  })
  vi.stubGlobal('fetch', h.fetch)
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.unstubAllEnvs()
})

const mute = (over: Partial<{ findingIds: string[]; nodeIds: string[]; reason: string }> = {}, c = ctx()) =>
  muteFindings(c, 'p1', { findingIds: ['v1'], reason: 'dev-only banner, per the owner', ...over })

const unmute = (over: Partial<{ findingIds: string[]; nodeIds: string[]; includeRuleMutes: boolean }> = {}, c = ctx()) =>
  unmuteFindings(c, 'p1', { findingIds: ['v1'], ...over })

const errorOf = (p: Promise<unknown>) => p.then(() => null, (e: unknown) => e as McpToolError)

// --- permissions ---------------------------------------------------------------

describe('permissions, ownership and rate', () => {
  test('mute and unmute need triage:mute; triage:write or triage:read alone is refused', async () => {
    for (const scopes of [['triage:write'], ['triage:read'], ['triage:write', 'triage:read']]) {
      await expect(mute({}, ctx(scopes))).rejects.toBeInstanceOf(McpScopeError)
      await expect(unmute({}, ctx(scopes))).rejects.toBeInstanceOf(McpScopeError)
    }
    expect(h.fetch).not.toHaveBeenCalled()
  })

  test('the search needs only triage:read', async () => {
    await expect(searchMutedFindings(ctx(['triage:read']), 'p1')).resolves.toMatchObject({ projectId: 'p1' })
    await expect(searchMutedFindings(ctx(['triage:mute']), 'p1')).rejects.toBeInstanceOf(McpScopeError)
  })

  test('another user\'s project is refused before anything is reserved or sent', async () => {
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'someone-else' })
    await expect(mute()).rejects.toBeInstanceOf(McpAccessDenied)
    await expect(unmute()).rejects.toBeInstanceOf(McpAccessDenied)
    await expect(searchMutedFindings(ctx(), 'p1')).rejects.toBeInstanceOf(McpAccessDenied)
    expect(h.fetch).not.toHaveBeenCalled()
  })

  test('mute and unmute share the mute bucket, apart from the write and read buckets', async () => {
    vi.stubEnv('MCP_RATE_MUTE_PER_MIN', '10')
    // Were they still counted as writes, the second call would be refused.
    vi.stubEnv('MCP_RATE_WRITE_PER_MIN', '1')
    for (let i = 0; i < 5; i++) await mute()
    for (let i = 0; i < 5; i++) await unmute()
    expect(await errorOf(mute())).toMatchObject({ code: 'rate_limited' })
    expect(await errorOf(unmute())).toMatchObject({ code: 'rate_limited' })
    await expect(searchMutedFindings(ctx(), 'p1')).resolves.toBeDefined()
  })

  test('the mute bucket is 200 calls a minute per token, and one token does not spend another\'s', async () => {
    expect(bucketSpec('mute')).toEqual({ limit: 200, windowMs: 60_000 })
    expect(bucketSpec('write').limit).toBe(10)
    vi.stubEnv('MCP_RATE_MUTE_PER_MIN', '1')
    await mute()
    expect(await errorOf(mute())).toMatchObject({ code: 'rate_limited' })
    await expect(mute({}, ctx(undefined, 't2'))).resolves.toBeDefined()
  })
})

describe('arguments', () => {
  test('no finding at all is refused', async () => {
    expect(await errorOf(muteFindings(ctx(), 'p1', { reason: 'noise noise' }))).toMatchObject({ code: 'bad_args' })
    expect(await errorOf(unmuteFindings(ctx(), 'p1', {}))).toMatchObject({ code: 'bad_args' })
  })

  test('one call names up to 5000 findings, to mute or to unmute', () => {
    expect([MUTE_MAX_REFS, UNMUTE_MAX_REFS]).toEqual([5000, 5000])
  })

  test('the cap is on distinct findings, across both lists', async () => {
    const ids = Array.from({ length: MUTE_MAX_REFS - 5 }, (_, i) => `v${i}`)
    await expect(mute({ findingIds: [...ids, ...ids], nodeIds: ['1', '2', '3', '4', '5'] })).resolves.toBeDefined()
    expect(sent('mute_many')[0].keys).toHaveLength(MUTE_MAX_REFS - 5)
    expect(await errorOf(mute({ findingIds: ids, nodeIds: ['1', '2', '3', '4', '5', '6'] })))
      .toMatchObject({ code: 'bad_args' })
    const many = Array.from({ length: UNMUTE_MAX_REFS + 1 }, (_, i) => `v${i}`)
    expect(await errorOf(unmute({ findingIds: many }))).toMatchObject({ code: 'bad_args' })
    await expect(unmute({ findingIds: many.slice(1) })).resolves.toBeDefined()
  })

  test('ids are checked, whatever reaches the tool body', async () => {
    expect(await errorOf(mute({ findingIds: ["v1' OR 1=1"] }))).toMatchObject({ code: 'bad_args' })
    expect(await errorOf(mute({ findingIds: [], nodeIds: ['12a'] }))).toMatchObject({ code: 'bad_args' })
    expect(h.fetch).not.toHaveBeenCalled()
  })

  test('a reason of 3-500 characters is required, counted after trimming', async () => {
    for (const reason of ['', '  a  ', 'x'.repeat(501)]) {
      expect(await errorOf(mute({ reason })), reason.slice(0, 5)).toMatchObject({ code: 'bad_args' })
    }
    expect(h.fetch).not.toHaveBeenCalled()
  })
})

// --- mute --------------------------------------------------------------------------

describe('mute_findings: what the agent is sent', () => {
  test('the MCP source, the owner as muted_by, the token prefix and the exemptions', async () => {
    await mute({ findingIds: ['v1', 'v1', 'v2'], nodeIds: ['812'], reason: '  dev-only banner  ' })
    expect(sent('mute_many')).toEqual([{
      op: 'mute_many', user_id: 'owner', project_id: 'p1', source: 'mcp',
      keys: ['v1', 'v2'], graph_ids: ['812'],
      exempt_pairs: [['Secret', 's9']],
      reason: 'dev-only banner',
      token_prefix: TOKEN_PREFIX,
      muted_by: 'owner',
    }])
    expect(h.exemptionFind).toHaveBeenCalledWith({ where: { projectId: 'p1' }, select: { label: true, nodeKey: true } })
  })
})

describe('mute_findings: outcomes', () => {
  test('every outcome is passed through to its own list', async () => {
    agent.mute_many = {
      items: [
        muteItem(),
        muteItem({ ref: 'v1', key: 'v1', label: 'Secret', node_id: '813' }),
        muteItem({ ref: 'v2', key: 'v2', outcome: 'already_muted', was_via: 'rule' }),
        muteItem({ ref: 'v3', key: 'v3', outcome: 'proven' }),
        muteItem({ ref: 'v4', key: 'v4', outcome: 'kept_visible' }),
        muteItem({ ref: '900', key: null, label: 'IP', outcome: 'not_a_finding' }),
      ],
      not_found: ['gone', '901'],
      mcp_gated: true,
    }
    const r = await mute({ findingIds: ['v1', 'v2', 'v3', 'v4', 'gone'], nodeIds: ['900', '901'] })
    // One key can match two nodes: both are reported.
    expect(r.muted).toEqual([
      { findingId: 'v1', nodeId: '812', label: 'Vulnerability', name: 'Banner', severity: 'info' },
      { findingId: 'v1', nodeId: '813', label: 'Secret', name: 'Banner', severity: 'info' },
    ])
    expect(r.alreadyMuted).toEqual([{ findingId: 'v2', nodeId: '812', label: 'Vulnerability', mutedVia: 'rule' }])
    expect(r.refused).toEqual([
      { ref: 'v3', reason: 'proven', label: 'Vulnerability' },
      { ref: 'v4', reason: 'kept_visible', label: 'Vulnerability' },
      { ref: '900', reason: 'not_a_finding', label: 'IP' },
    ])
    expect(r.notFound).toEqual(['gone', '901'])
  })

  test('the cache is dropped only when something was muted', async () => {
    agent.mute_many = { items: [muteItem({ outcome: 'proven' })], not_found: [], mcp_gated: true }
    await mute()
    expect(h.invalidateCache).not.toHaveBeenCalled()
    agent.mute_many = { items: [muteItem()], not_found: [], mcp_gated: true }
    await mute()
    expect(h.invalidateCache).toHaveBeenCalledWith('p1')
  })

  test('the audit row names the token, the reason and every item', async () => {
    await mute()
    const rows = h.writeAudit.mock.calls.map(c => c[0])
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({
      action: 'muted_nodes.muted', actorId: 'owner', targetType: 'project', targetId: 'p1', source: 'mcp',
      after: {
        tokenId: 't1', tokenPrefix: TOKEN_PREFIX, reason: 'dev-only banner, per the owner', count: 1,
        items: [{ key: 'v1', label: 'Vulnerability', outcome: 'muted' }],
      },
    })
  })
})

describe('the agent contract (contracts/triage_mute.json)', () => {
  // The Python side pins that the mixin answers exactly these keys. Here: the
  // body sent has exactly the request keys, and every answer key is read.
  const keysOf = (o: Record<string, unknown>) => Object.keys(o).sort()

  test('mute_many: the body sent and the answer read', async () => {
    const { request, response } = CONTRACT.mute_many
    agent.mute_many = response
    h.exemptionFind.mockResolvedValue((request.exempt_pairs as string[][]).map(([label, nodeKey]) => ({ label, nodeKey })))
    const r = await muteFindings(ctx(), 'p1', {
      findingIds: request.keys as string[], nodeIds: request.graph_ids as string[], reason: request.reason as string,
    })
    const body = sent('mute_many')[0]
    expect(keysOf(body)).toEqual(keysOf(request))
    expect(body).toEqual(request)
    expect(r.muted).toEqual([{ findingId: 'v1', nodeId: '812', label: 'Vulnerability', name: 'Banner', severity: 'info' }])
    expect(r.notFound).toEqual(['813'])
  })

  test('resolve_muted and unmute_many: the bodies sent and the answers read', async () => {
    agent.resolve_muted = CONTRACT.resolve_muted.response
    agent.unmute_many = CONTRACT.unmute_many.response
    const req = CONTRACT.resolve_muted.request
    const r = await unmuteFindings(ctx(), 'p1', {
      findingIds: req.keys as string[], nodeIds: req.graph_ids as string[],
    })
    expect(sent('resolve_muted')[0]).toEqual(req)
    expect(keysOf(sent('unmute_many')[0])).toEqual(keysOf(CONTRACT.unmute_many.request))
    expect(r.unmuted).toEqual([{ findingId: 'v1', nodeId: '812', label: 'Vulnerability', wasMutedVia: 'mcp' }])
    expect(r.skippedRuleMutes).toMatchObject([{ findingId: 'v2', nodeId: '813', label: 'Vulnerability' }])
    expect(r.notFound).toEqual([])
    expect(r.exempted).toBe(1)
  })

  test('a skipped row in the unmute answer drops the exemption made for it', async () => {
    // `skipped` is what keeps a rule mute from carrying a stray exemption.
    agent.resolve_muted = {
      ...CONTRACT.resolve_muted.response,
      to_unmute: [...(CONTRACT.resolve_muted.response.to_unmute as object[]),
        { ref: 'v2', key: 'v2', label: 'Vulnerability', node_id: '813', muted_by: 'owner', was_via: 'mcp' }],
      skipped_rule_mute: [],
    }
    agent.unmute_many = CONTRACT.unmute_many.response
    await unmute({ findingIds: ['v1', 'v2'] })
    expect(h.exemptionDelete).toHaveBeenCalledWith({
      where: { projectId: 'p1', OR: [{ label: 'Vulnerability', nodeKey: 'v2' }] },
    })
  })
})

describe('mute_findings: a person who unmutes during the call wins', () => {
  // The write checks a snapshot of the exemptions read before it. A person
  // who unmutes a finding while the call waits at the agent writes one the
  // write never sees, so without a second look the agent re-hides it.
  const personUnmutesMidCall = () => {
    h.exemptionFind
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([{ label: 'Vulnerability', nodeKey: 'v1' }])
  }

  test('a finding a person brought back during the call is unmuted again, not left re-hidden', async () => {
    personUnmutesMidCall()
    const r = await mute()
    expect(sent('unmute_many')).toEqual([expect.objectContaining({ keys: ['v1'], include_rule_mutes: false })])
    expect(r.muted).toEqual([])
    expect(r.refused).toEqual([{ ref: 'v1', reason: 'kept_visible', label: 'Vulnerability' }])
    expect(h.order).toEqual(['activation', 'mute_many', 'unmute_many', 'activation'])
  })

  test('the re-read asks only about what this call muted', async () => {
    agent.mute_many = {
      items: [muteItem(), muteItem({ ref: 'v2', key: 'v2', outcome: 'proven' })], not_found: [], mcp_gated: true,
    }
    await mute({ findingIds: ['v1', 'v2'] })
    expect(h.exemptionFind.mock.calls[1][0]).toMatchObject({
      where: { projectId: 'p1', OR: [{ label: 'Vulnerability', nodeKey: 'v1' }] },
    })
    expect(sent('unmute_many')).toEqual([])
  })

  test('a release that fails is named in a warning, never reported as done', async () => {
    personUnmutesMidCall()
    agent.unmute_many = { __status: 400, body: { error: 'refused' } }
    const r = await mute()
    expect(r.muted).toMatchObject([{ findingId: 'v1' }])
    expect(r.warning).toMatch(/brought back v1 during this call/)
  })

  test('a re-read that fails is a warning, not a silent all-clear', async () => {
    h.exemptionFind.mockResolvedValueOnce([]).mockRejectedValueOnce(new Error('db down'))
    const r = await mute()
    expect(r.muted).toMatchObject([{ findingId: 'v1' }])
    expect(r.warning).toMatch(/could not be checked/)
    expect(sent('unmute_many')).toEqual([])
  })
})

describe('mute_findings: no daily cap', () => {
  test('a token mutes a full call again and again, and the answer carries no budget', async () => {
    // A value left in an old .env is inert: nothing reads it.
    vi.stubEnv('MCP_MUTE_DAILY_BUDGET', '1')
    const ids = Array.from({ length: MUTE_MAX_REFS }, (_, i) => `v${i}`)
    for (let i = 0; i < 3; i++) {
      expect(await mute({ findingIds: ids })).not.toHaveProperty('budget')
    }
    expect(sent('mute_many').map(b => (b.keys as string[]).length)).toEqual([MUTE_MAX_REFS, MUTE_MAX_REFS, MUTE_MAX_REFS])
  })
})

describe('mute_findings: a definite failure and an uncertain one', () => {
  test('busy, unreachable and a coded refusal each say nothing was changed', async () => {
    h.activationBusy.mockResolvedValueOnce(true)
    expect(await errorOf(mute())).toMatchObject({ code: 'busy' })

    agent.mute_many = { __throw: refused('ECONNREFUSED') }
    expect(await errorOf(mute())).toMatchObject({ code: 'agent_unreachable' })

    agent.mute_many = { __status: 400, body: { error: 'reason must be 3-500 characters' } }
    expect(await errorOf(mute())).toMatchObject({ code: 'agent_failed' })

    agent.mute_many = { __status: 503, body: { error: 'locked; nothing was changed', code: 'busy' } }
    expect(await errorOf(mute())).toMatchObject({ code: 'agent_failed' })
  })

  test('a 5xx after sending may follow a commit, so it is unknown, never a refusal', async () => {
    // A lost commit acknowledgement reaches the agent as an exception after
    // the write: its 500 does not mean "nothing was changed".
    for (const answer of [
      { __status: 500, body: { error: 'IncompleteCommit' } },
      { __status: 502, body: {} },
      { __status: 504, body: {} },
      { __status: 503, body: { error: 'uncoded' } },
    ]) {
      agent.mute_many = answer
      expect(await errorOf(mute()), String(answer.__status)).toMatchObject({ code: 'mute_outcome_unknown' })
    }
  })
})

describe('mute_findings: busy checks fail closed', () => {
  test('an activation in progress (or unreadable) refuses before anything is read or sent', async () => {
    h.activationBusy.mockResolvedValue(true)
    expect(await errorOf(mute())).toMatchObject({ code: 'busy' })
    expect(h.exemptionFind).not.toHaveBeenCalled()
    expect(h.fetch).not.toHaveBeenCalled()
  })

  test('exemptions that cannot be read are busy, never "no exemptions"', async () => {
    // An empty list would let the mute re-hide everything a person unmuted.
    h.exemptionFind.mockRejectedValue(new Error('db down'))
    expect(await errorOf(mute())).toMatchObject({ code: 'busy' })
    expect(h.fetch).not.toHaveBeenCalled()
  })

  test('an activation that starts during the call is reported as a warning', async () => {
    h.activationBusy.mockResolvedValueOnce(false).mockResolvedValueOnce(true)
    const r = await mute()
    expect(r.warning).toMatch(/activation started during this call/)
    expect(h.order).toEqual(['activation', 'mute_many', 'activation'])
  })
})

describe('mute_findings: a lost answer is an unknown outcome', () => {
  test('a timeout is mute_outcome_unknown, the cache is dropped and the audit says unknown', async () => {
    agent.mute_many = { __throw: timeout() }
    const err = await errorOf(mute({ findingIds: ['v1'], nodeIds: ['812'] }))
    expect(err).toMatchObject({ code: 'mute_outcome_unknown' })
    expect(err?.message).toMatch(/may or may not have been applied/)
    expect(err?.message).toMatch(/search_muted_findings/)
    expect(h.invalidateCache).toHaveBeenCalledWith('p1')
    expect(h.writeAudit.mock.calls[0][0]).toMatchObject({
      action: 'muted_nodes.muted',
      after: { outcome: 'unknown', requested: { findingIds: ['v1'], nodeIds: ['812'] }, tokenPrefix: TOKEN_PREFIX },
    })
  })

  test('the unknown-outcome audit of a large call names 100 ids and counts them all', async () => {
    agent.mute_many = { __throw: timeout() }
    await errorOf(mute({ findingIds: Array.from({ length: 250 }, (_, i) => `v${i}`), nodeIds: ['812'] }))
    const { requested } = h.writeAudit.mock.calls[0][0].after
    expect(requested.findingIds).toHaveLength(100)
    expect(requested).toMatchObject({ nodeIds: ['812'], count: 251 })
  })

  test('a reset after sending is unknown too; only a refusal before sending is unreachable', async () => {
    agent.mute_many = { __throw: refused('ECONNRESET') }
    expect(await errorOf(mute())).toMatchObject({ code: 'mute_outcome_unknown' })
    agent.mute_many = { __throw: refused('ENOTFOUND') }
    expect(await errorOf(mute())).toMatchObject({ code: 'agent_unreachable' })
  })

  test('an answer without the MCP acknowledgement is not trusted', async () => {
    agent.mute_many = { items: [muteItem()], not_found: [] }
    expect(await errorOf(mute())).toMatchObject({ code: 'mute_outcome_unknown' })
  })

  test('an agent older than this build says to rebuild it', async () => {
    agent.mute_many = { __status: 400, body: { error: "unknown op 'mute_many'" } }
    const err = await errorOf(mute())
    expect(err).toMatchObject({ code: 'agent_outdated' })
    expect(err?.message).toMatch(/rebuild the agent image/)
  })
})

// --- unmute ------------------------------------------------------------------------

describe('unmute_findings: the order of writes', () => {
  test('resolve, then the exemptions, then the re-check, then the unmute', async () => {
    const r = await unmute()
    expect(h.order).toEqual([
      'activation', 'applyCheck', 'resolve_muted',
      'exemptions.create', 'activation', 'applyCheck', 'unmute_many',
    ])
    expect(r.unmuted).toEqual([{ findingId: 'v1', nodeId: '812', label: 'Vulnerability', wasMutedVia: 'mcp' }])
    expect(r.exempted).toBe(1)
    expect(sent('unmute_many')[0]).toMatchObject({ keys: ['v1'], include_rule_mutes: false, source: 'mcp' })
    expect(h.exemptionCreate.mock.calls[0][0]).toMatchObject({
      skipDuplicates: true,
      data: [{ projectId: 'p1', label: 'Vulnerability', nodeKey: 'v1', createdBy: 'owner', realActorUserId: null }],
    })
    expect(h.invalidateCache).toHaveBeenCalledWith('p1')
  })

  test('the unmute is audited with the token, the items and the exemptions', async () => {
    await unmute()
    expect(h.writeAudit.mock.calls[0][0]).toMatchObject({
      action: 'muted_nodes.unmuted', source: 'mcp', targetId: 'p1',
      after: { tokenId: 't1', tokenPrefix: TOKEN_PREFIX, count: 1, exempted: 1, outcome: 'ok',
        items: [{ key: 'v1', label: 'Vulnerability', wasMutedVia: 'mcp' }] },
    })
  })

  test('an exemption that cannot be saved means nothing is unmuted', async () => {
    h.exemptionCreate.mockRejectedValue(new Error('db down'))
    const err = await errorOf(unmute())
    expect(err).toMatchObject({ code: 'exemptions_failed' })
    expect(sent('unmute_many')).toEqual([])
  })

  test('busy at the re-check removes exactly the exemptions this call created', async () => {
    agent.resolve_muted = {
      to_unmute: [
        { ref: 'v1', key: 'v1', label: 'Vulnerability', node_id: '1', muted_by: 'owner', was_via: 'person' },
        { ref: 'v2', key: 'v2', label: 'Vulnerability', node_id: '2', muted_by: 'owner', was_via: 'person' },
      ],
      skipped_rule_mute: [], not_found: [], mcp_gated: true,
    }
    // v2 was already exempt, so Postgres reports only v1 as created.
    h.exemptionCreate.mockResolvedValue([{ label: 'Vulnerability', nodeKey: 'v1' }])
    h.nodeFilterWriter.mockResolvedValueOnce(null).mockResolvedValueOnce('mute rules are being applied to the graph')
    expect(await errorOf(unmute({ findingIds: ['v1', 'v2'] }))).toMatchObject({ code: 'busy' })
    expect(h.exemptionDelete).toHaveBeenCalledWith({
      where: { projectId: 'p1', OR: [{ label: 'Vulnerability', nodeKey: 'v1' }] },
    })
    expect(sent('unmute_many')).toEqual([])
  })

  test('a definite unmute failure removes the exemptions it created', async () => {
    for (const answer of [
      { __status: 400, body: { error: 'at most 100 findings per unmute' } },
      { __status: 503, body: { error: 'The graph was busy; nothing was changed.', code: 'retry' } },
    ]) {
      h.exemptionDelete.mockClear()
      agent.unmute_many = answer
      expect(await errorOf(unmute()), String(answer.__status)).toMatchObject({ code: 'agent_failed' })
      expect(h.exemptionDelete).toHaveBeenCalledOnce()
    }
  })

  test('a 500 after the unmute may have committed is unknown, and KEEPS the exemptions', async () => {
    // Removing them would leave a finding the agent really unmuted with no
    // exemption, and the next rule sweep would hide it again.
    agent.unmute_many = { __status: 500, body: { error: 'IncompleteCommit' } }
    expect(await errorOf(unmute())).toMatchObject({ code: 'unmute_outcome_unknown' })
    expect(h.exemptionDelete).not.toHaveBeenCalled()
    expect(h.writeAudit.mock.calls[0][0]).toMatchObject({ after: { outcome: 'unknown' } })
  })

  test('an unknown unmute outcome KEEPS them, so a lost answer converges', async () => {
    agent.unmute_many = { __throw: timeout() }
    expect(await errorOf(unmute())).toMatchObject({ code: 'unmute_outcome_unknown' })
    expect(h.exemptionDelete).not.toHaveBeenCalled()
    expect(h.invalidateCache).toHaveBeenCalledWith('p1')
    expect(h.writeAudit.mock.calls[0][0]).toMatchObject({ after: { outcome: 'unknown' } })
  })

  test('nothing to unmute writes nothing', async () => {
    agent.resolve_muted = { to_unmute: [], skipped_rule_mute: [], not_found: ['v1'], mcp_gated: true }
    const r = await unmute()
    expect(r).toMatchObject({ unmuted: [], notFound: ['v1'], exempted: 0 })
    expect(h.exemptionCreate).not.toHaveBeenCalled()
    expect(sent('unmute_many')).toEqual([])
  })
})

describe('unmute_findings: rule mutes', () => {
  test('without the flag a rule mute is skipped and named by its rule', async () => {
    agent.resolve_muted = {
      to_unmute: [],
      skipped_rule_mute: [{ ref: 'r1', key: 'r1', label: 'Vulnerability', node_id: '9',
        muted_by: 'rule:vuln.nuclei/k3f9a2', was_via: 'rule' }],
      not_found: [], mcp_gated: true,
    }
    const r = await unmute({ findingIds: ['r1'] })
    expect(r.skippedRuleMutes).toEqual([
      { findingId: 'r1', nodeId: '9', label: 'Vulnerability', ruleName: 'Informational templates' },
    ])
    expect(sent('resolve_muted')[0]).toMatchObject({ include_rule_mutes: false })
    expect(r.notes.join(' ')).toMatch(/includeRuleMutes/)
  })

  test('the flag checks for a running scan, before AND after the exemptions', async () => {
    await unmute({ includeRuleMutes: true })
    expect(h.order.filter(o => o === 'scanCheck')).toHaveLength(2)
    expect(h.order).not.toContain('applyCheck')
    expect(sent('unmute_many')[0]).toMatchObject({ include_rule_mutes: true })
  })

  test('with the flag, a running scan refuses before anything is written', async () => {
    h.scanWriters.mockResolvedValue('a partial recon run is active')
    const err = await errorOf(unmute({ includeRuleMutes: true }))
    expect(err).toMatchObject({ code: 'busy' })
    expect(err?.message).toMatch(/partial recon run is active/)
    expect(h.exemptionCreate).not.toHaveBeenCalled()
  })

  test('a finding the agent left muted loses the exemption this call created for it', async () => {
    agent.unmute_many = {
      unmuted: 0, items: [], skipped: [{ key: 'v1', label: 'Vulnerability', muted_by: 'rule:x/abc123' }],
      mcp_gated: true,
    }
    const r = await unmute()
    expect(r.unmuted).toEqual([])
    expect(r.exempted).toBe(0)
    expect(h.exemptionDelete).toHaveBeenCalledWith({
      where: { projectId: 'p1', OR: [{ label: 'Vulnerability', nodeKey: 'v1' }] },
    })
  })

  test('node ids are resolved by the agent and passed as graph ids', async () => {
    await unmute({ findingIds: [], nodeIds: ['812'] })
    expect(sent('resolve_muted')[0]).toMatchObject({ keys: [], graph_ids: ['812'] })
  })
})

// --- search ------------------------------------------------------------------------

describe('search_muted_findings', () => {
  const row = (over: Record<string, unknown> = {}) => ({
    id: 'v1', node_id: '812', label: 'Vulnerability', name: 'Banner', severity: 'info', source: 'nuclei',
    host: 'app.example.com', muted_at: '2026-09-29T10:00:00Z', muted_by: 'owner', muted_via: 'mcp',
    muted_channel: 'mcp', muted_token: TOKEN_PREFIX, muted_reason: 'noise', stale_since: null,
    triage_status: 'unreviewed', triage_ai_quote: 'TARGET TEXT', raw_response: '<html>',
    ...over,
  })

  test('the filters reach the agent, with the token as `token`', async () => {
    await searchMutedFindings(ctx(), 'p1', {
      limit: 20, offset: 40, label: 'Secret', mutedVia: 'mcp', mutedByToken: TOKEN_PREFIX,
      search: 'banner', order: 'person_first',
    })
    expect(sent('list_muted')[0]).toMatchObject({
      limit: 20, offset: 40, label: 'Secret', muted_via: 'mcp', token: TOKEN_PREFIX,
      search: 'banner', order: 'person_first', source: 'mcp',
    })
  })

  test('a deleted-rule filter names the rules that still exist', async () => {
    await searchMutedFindings(ctx(), 'p1', { mutedVia: 'deleted_rule' })
    expect(sent('list_muted')[0].live_rules).toEqual(['rule:vuln.nuclei/allowlist', 'rule:vuln.nuclei/k3f9a2'])
  })

  test('a token that is not a prefix is refused', async () => {
    expect(await errorOf(searchMutedFindings(ctx(), 'p1', { mutedByToken: 'rdmn_mcp_ab12cd34ef' })))
      .toMatchObject({ code: 'bad_args' })
  })

  test("rows are an allowlist: no raw evidence, and the agent's token is shown", async () => {
    agent.list_muted = { findings: [row(), row({ id: 'r1', muted_by: 'rule:vuln.nuclei/k3f9a2', muted_via: 'rule',
      muted_channel: '', muted_token: '' })], total: 2, mcp_gated: true }
    const r = await searchMutedFindings(ctx(), 'p1')
    expect(r.findings[0]).toEqual({
      id: 'v1', nodeId: '812', label: 'Vulnerability', name: 'Banner', severity: 'info', source: 'nuclei',
      host: 'app.example.com', mutedAt: '2026-09-29T10:00:00Z', mutedVia: 'mcp', mutedBy: 'owner',
      mutedByToken: TOKEN_PREFIX, ruleName: null, mutedReason: 'noise', staleSince: null,
      triageStatus: 'unreviewed',
    })
    expect(r.findings[1]).toMatchObject({ mutedVia: 'rule', ruleName: 'Informational templates' })
    expect(r.findings[1]).not.toHaveProperty('mutedByToken')
    expect(JSON.stringify(r)).not.toContain('TARGET TEXT')
    expect(JSON.stringify(r)).not.toContain('<html>')
  })

  test('the envelope is exact: total, offset, returned, truncated', async () => {
    agent.list_muted = { findings: [row(), row({ id: 'v2' })], total: 30, mcp_gated: true }
    const r = await searchMutedFindings(ctx(), 'p1', { offset: 10, limit: 2 })
    expect(r).toMatchObject({ total: 30, offset: 10, returned: 2, truncated: true })
    agent.list_muted = { findings: [row()], total: 1, mcp_gated: true }
    expect(await searchMutedFindings(ctx(), 'p1')).not.toHaveProperty('truncated')
  })

  test('facets only on request, with rules named and tokens counted', async () => {
    await searchMutedFindings(ctx(), 'p1')
    expect(sent('muted_facets')).toEqual([])
    agent.muted_facets = {
      total: 6, by_person: 1, by_mcp: 3, labels: { Vulnerability: 6 },
      rules: [{ muted_by: 'rule:vuln.nuclei/k3f9a2', count: 2, reason: 'Filter rule: Informational templates' }],
      tokens: [{ token: TOKEN_PREFIX, count: 3 }], mcp_gated: true,
    }
    const r = await searchMutedFindings(ctx(), 'p1', { facets: true })
    expect(r.facets).toEqual({
      total: 6, byPerson: 1, byMcp: 3, labels: { Vulnerability: 6 },
      rules: [{ mutedBy: 'rule:vuln.nuclei/k3f9a2', count: 2, ruleName: 'Informational templates' }],
      tokens: [{ token: TOKEN_PREFIX, count: 3 }],
    })
  })
})

// --- through a real MCP client ---------------------------------------------------------

describe('the advertised schema is enforced', () => {
  async function call(name: string, args: Record<string, unknown>) {
    const server = buildMcpServer(ctx())
    const client = new Client({ name: 'mute-test', version: '1.0.0' }, { capabilities: {} })
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
    try {
      const result = await client.callTool({ name, arguments: args })
      const content = result.content as { text?: string }[]
      return { isError: Boolean(result.isError), text: content.map(c => c.text ?? '').join('\n') }
    } finally {
      await client.close()
      await server.close()
    }
  }

  test('an offset past 10,000 is refused before the tool runs', async () => {
    const r = await call('search_muted_findings', { projectId: 'p1', offset: 10_001 })
    expect(r.isError).toBe(true)
    expect(sent()).toEqual([])
  })

  test('a Node ID copied from query_graph (a JSON number) is accepted, and sent as digits', async () => {
    const r = await call('mute_findings', { projectId: 'p1', nodeIds: [812, '813'], reason: 'noise, per owner' })
    expect(r.isError).toBe(false)
    expect(sent('mute_many')[0]).toMatchObject({ keys: [], graph_ids: ['812', '813'] })
  })

  test('a negative or fractional Node ID is refused before the tool runs', async () => {
    for (const bad of [-1, 1.5, '12a']) {
      h.fetch.mockClear()
      const r = await call('unmute_findings', { projectId: 'p1', nodeIds: [bad] })
      expect(r.isError, String(bad)).toBe(true)
      expect(sent()).toEqual([])
    }
  })

  test('a mute with no reason is refused before the tool runs', async () => {
    const r = await call('mute_findings', { projectId: 'p1', findingIds: ['v1'] })
    expect(r.isError).toBe(true)
    expect(sent()).toEqual([])
  })

  test('a failure reaches the caller as its own message, and the handler audits the code', async () => {
    h.activationBusy.mockResolvedValue(true)
    const r = await call('mute_findings', { projectId: 'p1', findingIds: ['v1'], reason: 'noise, per owner' })
    expect(r.isError).toBe(true)
    expect(r.text).toMatch(/^Refused \(busy\): nothing was changed: a version activation is in progress/)
    const handlerRow = h.writeAudit.mock.calls.map(c => c[0]).find(a => a.action === 'mcp.mute_findings')
    expect(handlerRow.after).toMatchObject({ outcome: 'busy', tokenPrefix: TOKEN_PREFIX })
  })

  test('the error codes the tool descriptions promise reach the client in the text', async () => {
    // The handler sends only the message, never err.code, so a code an agent
    // is told to branch on has to be in the message.
    agent.mute_many = { __throw: timeout() }
    let r = await call('mute_findings', { projectId: 'p1', findingIds: ['v1'], reason: 'noise, per owner' })
    expect(r.text).toMatch(/\(mute_outcome_unknown\)/)

    agent.unmute_many = { __throw: timeout() }
    r = await call('unmute_findings', { projectId: 'p1', findingIds: ['v1'] })
    expect(r.text).toMatch(/\(unmute_outcome_unknown\)/)
  })

  test('5000 ids pass the advertised schema, and one more is refused before the tool runs', async () => {
    const ids = Array.from({ length: MUTE_MAX_REFS + 1 }, (_, i) => `v${i}`)
    let r = await call('mute_findings', { projectId: 'p1', findingIds: ids.slice(1), reason: 'noise, per owner' })
    expect(r.isError).toBe(false)
    h.fetch.mockClear()
    r = await call('mute_findings', { projectId: 'p1', findingIds: ids, reason: 'noise, per owner' })
    expect(r.isError).toBe(true)
    expect(sent()).toEqual([])
  })
})

// Review finding, proposed (adjacent gap, not built): MCP reports a Multi mute
// as `muted_via: multi` but cannot filter to one, and its `person` filter
// leaves Multi mutes out. Adding it changes the MCP tool schema, which needs
// the MCP API reference regenerated, so it is proposed rather than written.
describe('the muted_via filter', () => {
  test.fails('reaches Multi mutes', () => {
    expect(MUTED_VIA_FILTERS).toContain('multi')
  })
})
