/**
 * The four engagement tools, exercised through their real handlers.
 *
 * What they are for, stated once so the assertions read as consequences rather
 * than as a list: an agent holding an MCP token must be able to take a scope
 * document and stand up a project that PROVABLY cannot violate it. Every test
 * below is one way that could fail quietly.
 *
 * T24 lives here too. Each of these is a new state-changing tool, and a tool
 * that skips a guard the others keep is a hole in a control that holds
 * everywhere else on the surface: the scope check, a rate-limit bucket, the busy
 * check, and an audit row.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  createProject: vi.fn(),
  findProject: vi.fn(),
  updateProject: vi.fn(),
  updateManyProject: vi.fn(),
  createAuthorization: vi.fn(),
  findFirstAuthorization: vi.fn(),
  findUniqueAuthorization: vi.fn(),
  findManyAuthorization: vi.fn(),
  countAuthorization: vi.fn(),
  tokenCount: vi.fn(),
  findFirstScanJob: vi.fn(),
  transaction: vi.fn(),
  busy: vi.fn(),
  audit: vi.fn(),
}))

vi.mock('@/lib/prisma', () => {
  const client = {
    project: {
      create: (...a: unknown[]) => h.createProject(...a),
      findUnique: (...a: unknown[]) => h.findProject(...a),
      update: (...a: unknown[]) => h.updateProject(...a),
      updateMany: (...a: unknown[]) => h.updateManyProject(...a),
    },
    engagementAuthorization: {
      create: (...a: unknown[]) => h.createAuthorization(...a),
      findFirst: (...a: unknown[]) => h.findFirstAuthorization(...a),
      findUnique: (...a: unknown[]) => h.findUniqueAuthorization(...a),
      findMany: (...a: unknown[]) => h.findManyAuthorization(...a),
      count: (...a: unknown[]) => h.countAuthorization(...a),
    },
    scanJob: { findFirst: (...a: unknown[]) => h.findFirstScanJob(...a) },
    userLlmProvider: { count: (...a: unknown[]) => h.tokenCount(...a) },
    $transaction: (fn: (tx: unknown) => unknown) => h.transaction(fn, client),
  }
  return { default: client }
})
vi.mock('@/lib/graphWriters', () => ({ describeScanWriters: (...a: unknown[]) => h.busy(...a) }))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))

import { McpScopeError, __resetRateLimiter } from '@/lib/mcpAuth'
import {
  attachEngagementAuthorization,
  createProject,
  listEngagementAuthorizations,
  preflightScopeCheck,
} from './engagementTools'
import { updateReconSettings } from './writeTools'
import type { McpContext } from './tools'

const ALL_SCOPES = [
  'recon:read', 'project:create', 'engagement:authorize', 'recon:settings',
] as const

const ctx = (scopes: readonly string[] = ALL_SCOPES): McpContext => ({
  token: {
    tokenId: 't1', userId: 'owner', tokenPrefix: 'rdmn_mcp_aaaaaaaa',
    name: 'agent', scopes: scopes as never,
  },
})

describe('preflight_scope_check: the effective engine of each AI hook', () => {
  const byHook = (r: Awaited<ReturnType<typeof preflightScopeCheck>>) =>
    Object.fromEntries(r.aiHooks.map(x => [x.hook, x]))

  test('reports every hook with its kind and the engine each row asks for', async () => {
    h.findProject.mockResolvedValue(projectRow({ aiInPipeline: true, ffufAiUseJev: false }))
    const r = await preflightScopeCheck(ctx(), 'p1')
    expect(r.aiHooks.map(x => x.hook)).toEqual([
      'ffuf_extensions', 'nuclei_tags', 'waf_classification', 'takeover_disambiguation',
      'ffuf_base_paths', 'page_type', 'tool_health', 'crawl_seed_order', 'serialized_assess',
    ])
    expect(byHook(r).ffuf_extensions).toEqual(
      { hook: 'ffuf_extensions', kind: 'engine', engine: 'llm', effective: 'llm' })
  })

  test('a Jev-only hook switched off is off, never "llm"', async () => {
    // It has no LLM engine: false means the step runs with no AI at all.
    h.findProject.mockResolvedValue(projectRow({ aiInPipeline: true }))
    const r = await preflightScopeCheck(ctx(), 'p1')
    for (const hook of ['ffuf_base_paths', 'page_type', 'tool_health', 'crawl_seed_order',
      'serialized_assess']) {
      expect(byHook(r)[hook]).toEqual({ hook, kind: 'enable', engine: 'off', effective: 'off' })
    }
  })

  test('the serialized-scan ranking reports Jev with a token and its fallback without one', async () => {
    h.findProject.mockResolvedValue(projectRow({ aiInPipeline: true, serializedScanJevRank: true }))
    h.tokenCount.mockResolvedValue(1)
    expect(byHook(await preflightScopeCheck(ctx(), 'p1')).serialized_assess)
      .toEqual({ hook: 'serialized_assess', kind: 'enable', engine: 'jev', effective: 'jev' })
    h.tokenCount.mockResolvedValue(0)
    expect(byHook(await preflightScopeCheck(ctx(), 'p1')).serialized_assess.effective)
      .toBe('jev → static fallback (no Jev token on the owner\'s account)')
  })

  test('a Jev-only hook switched on runs on Jev with a token, or its fallback without one', async () => {
    h.tokenCount.mockResolvedValue(1)
    h.findProject.mockResolvedValue(projectRow({ aiInPipeline: true, httpxJevPageType: true }))
    let r = await preflightScopeCheck(ctx(), 'p1')
    expect(byHook(r).page_type).toMatchObject({ kind: 'enable', engine: 'jev', effective: 'jev' })
    h.tokenCount.mockResolvedValue(0)
    h.findProject.mockResolvedValue(projectRow({ aiInPipeline: true, hakrawlerJevSeedOrder: true }))
    r = await preflightScopeCheck(ctx(), 'p1')
    expect(byHook(r).crawl_seed_order.effective).toBe(
      "jev → static fallback (no Jev token on the owner's account)")
  })

  test('a Jev-only hook is off when aiInPipeline is off, whatever its flag says', async () => {
    h.findProject.mockResolvedValue(projectRow({ aiInPipeline: false, resourceEnumJevToolHealth: true }))
    const r = await preflightScopeCheck(ctx(), 'p1')
    expect(byHook(r).tool_health).toMatchObject({ engine: 'jev', effective: 'off' })
  })

  test('aiInPipeline off means every hook is off, whatever the engine field says', async () => {
    h.findProject.mockResolvedValue(projectRow({ aiInPipeline: false, ffufAiUseJev: true }))
    const r = await preflightScopeCheck(ctx(), 'p1')
    expect(byHook(r).ffuf_extensions).toMatchObject({ engine: 'jev', effective: 'off' })
    expect(r.aiHooks.every(x => x.effective === 'off')).toBe(true)
    expect(h.tokenCount).not.toHaveBeenCalled()
  })

  test('a hook on Jev with a token on the owner\'s account runs on Jev', async () => {
    h.tokenCount.mockResolvedValue(1)
    h.findProject.mockResolvedValue(projectRow({ aiInPipeline: true, wafAiUseJev: true }))
    const r = await preflightScopeCheck(ctx(), 'p1')
    expect(byHook(r).waf_classification).toMatchObject({ engine: 'jev', effective: 'jev' })
    expect(h.tokenCount).toHaveBeenCalledWith({ where: { userId: 'owner', providerType: 'jev' } })
  })

  test('a hook on Jev with no token is reported as its static fallback', async () => {
    h.findProject.mockResolvedValue(projectRow({ aiInPipeline: true, nucleiTagsAiUseJev: true }))
    const r = await preflightScopeCheck(ctx(), 'p1')
    expect(byHook(r).nuclei_tags.effective).toBe("jev → static fallback (no Jev token on the owner's account)")
    expect(byHook(r).ffuf_extensions.effective).toBe('llm')
  })

  test('a failed token count is reported as unverified, never as a guess', async () => {
    h.tokenCount.mockRejectedValue(new Error('db down'))
    h.findProject.mockResolvedValue(projectRow({ aiInPipeline: true, takeoverAiUseJev: true }))
    const r = await preflightScopeCheck(ctx(), 'p1')
    expect(byHook(r).takeover_disambiguation.effective).toContain('could not check')
  })

  test('all hooks on the LLM never touch the token table', async () => {
    h.findProject.mockResolvedValue(projectRow({ aiInPipeline: true }))
    await preflightScopeCheck(ctx(), 'p1')
    expect(h.tokenCount).not.toHaveBeenCalled()
  })

  test('the response carries counts and engines only: never a token, key or provider row', async () => {
    h.tokenCount.mockResolvedValue(1)
    h.findProject.mockResolvedValue(projectRow({ aiInPipeline: true, ffufAiUseJev: true }))
    const r = await preflightScopeCheck(ctx(), 'p1')
    expect(JSON.stringify(r.aiHooks)).not.toMatch(/apikey|api_key|apiKey|token":/i)
  })
})

const AUTH = {
  documentSha256: 'a'.repeat(64),
  documentKind: 'hackerone_program',
  programHandle: 'nba-public',
  issuedAt: '2026-01-01T00:00:00.000Z',
  summary: '428 in-scope, 28 excluded, 3 rps ceiling',
}

const projectRow = (over: Record<string, unknown> = {}) => ({
  id: 'p1',
  userId: 'owner',
  updatedAt: new Date('2026-01-01T00:00:00.000Z'),
  engagementKind: 'internal',
  engagementIdentityHeader: '',
  roeGlobalMaxRps: 0,
  targetDomain: 'example.com',
  targetIps: [],
  ipMode: false,
  domainBatchMode: false,
  domainBatchHosts: [],
  targetGuardrailEnabled: true,
  roeExcludedHosts: [],
  roeForbiddenTools: [],
  roeForbiddenCategories: [],
  roeAllowDos: false,
  roeAllowDataExfiltration: false,
  scanModules: ['domain_discovery', 'port_scan'],
  naabuRateLimit: 1000,
  nucleiRateLimit: 150,
  takeoverRateLimit: 50,
  ffufRate: 0,
  nucleiDockerImage: 'projectdiscovery/nuclei:latest',
  naabuEnabled: true,
  ffufEnabled: true,
  ffufWordlist: '/usr/share/seclists/Discovery/Web-Content/common.txt',
  ...over,
})

beforeEach(() => {
  vi.clearAllMocks()
  __resetRateLimiter()
  h.busy.mockResolvedValue(null)
  h.findProject.mockResolvedValue(projectRow())
  h.createProject.mockResolvedValue({ id: 'p1', name: 'test' })
  h.createAuthorization.mockResolvedValue({ id: 'auth1', recordedAt: new Date() })
  h.findFirstAuthorization.mockResolvedValue(null)
  h.findUniqueAuthorization.mockResolvedValue(null)
  h.findManyAuthorization.mockResolvedValue([])
  h.countAuthorization.mockResolvedValue(0)
  h.tokenCount.mockResolvedValue(0)
  h.findFirstScanJob.mockResolvedValue(null)
  h.updateProject.mockResolvedValue({})
  h.updateManyProject.mockResolvedValue({ count: 1 })
  h.transaction.mockImplementation((fn, client) => fn(client))
  h.audit.mockResolvedValue(undefined)
})

// --- create_project -----------------------------------------------------------------

describe('create_project fixes scope, and only here', () => {
  test('it needs project:create', async () => {
    await expect(createProject(ctx(['recon:read']), { name: 'x', engagementKind: 'internal', targetDomain: 'a.tld' }))
      .rejects.toBeInstanceOf(McpScopeError)
  })

  test('a single domain creates a project', async () => {
    const r = await createProject(ctx(), {
      name: 'test', engagementKind: 'internal', targetDomain: 'example.com',
    })
    expect(r.created).toBe(true)
    expect(h.createProject.mock.calls[0][0].data.targetDomain).toBe('example.com')
  })

  test('no targeting mode is refused, naming all three', async () => {
    await expect(createProject(ctx(), { name: 'test', engagementKind: 'internal' }))
      .rejects.toThrow(/targetDomain.*targetIps.*domainBatchHosts/s)
  })

  test('two targeting modes are refused rather than resolved', async () => {
    // Picking one for the caller would scan something it did not ask for.
    await expect(createProject(ctx(), {
      name: 'test', engagementKind: 'internal',
      targetDomain: 'example.com', targetIps: ['10.0.0.1'],
    })).rejects.toThrow(/mutually exclusive/)
  })

  test('the domain-batch grouping is derived server-side', async () => {
    // The grouping decides the run order, so a client-supplied one is a control
    // the server would be taking from the caller's word.
    await createProject(ctx(), {
      name: 'test', engagementKind: 'internal',
      domainBatchHosts: ['a.example.com', 'b.example.com'],
    })
    const data = h.createProject.mock.calls[0][0].data
    expect(data.domainBatchMode).toBe(true)
    expect(Array.isArray(data.domainBatchGroups)).toBe(true)
    expect(data.domainBatchGroups).not.toHaveLength(0)
  })

  test('the owner is the TOKEN owner, never a body-supplied one', async () => {
    await createProject(ctx(), {
      name: 'test', engagementKind: 'internal', targetDomain: 'example.com',
      settings: { userId: 'someone-else' } as never,
    }).catch(() => {})
    if (h.createProject.mock.calls.length > 0) {
      expect(h.createProject.mock.calls[0][0].data.userId).toBe('owner')
    }
  })
})

describe('B-3: create_project runs the hard guardrail the form runs', () => {
  // Scan start refuses these anyway, but a project nobody may ever scan should
  // not be created either, least of all with an authorization record attached.
  test('a permanently blocked single domain is refused and nothing is written', async () => {
    await expect(createProject(ctx(), {
      name: 'test', engagementKind: 'internal', targetDomain: 'portal.example.gov',
    })).rejects.toThrow(/permanently blocked: portal\.example\.gov/)
    expect(h.createProject).not.toHaveBeenCalled()
  })

  test('a wildcard is stripped before the check, not used to slip past it', async () => {
    await expect(createProject(ctx(), {
      name: 'test', engagementKind: 'internal', targetDomain: '*.example.gov',
    })).rejects.toThrow(/permanently blocked/)
  })

  test('one blocked root refuses the whole batch', async () => {
    await expect(createProject(ctx(), {
      name: 'test', engagementKind: 'internal',
      domainBatchHosts: ['a.example.com', 'portal.example.gov'],
    })).rejects.toThrow(/permanently blocked: example\.gov/)
    expect(h.createProject).not.toHaveBeenCalled()
  })
})

describe('create_project enforces the third-party rule before writing anything', () => {
  test('third_party with no ceiling is refused', async () => {
    await expect(createProject(ctx(), {
      name: 'test', engagementKind: 'third_party', targetDomain: 'example.com',
      authorization: AUTH,
    })).rejects.toThrow(/rate ceiling/)
    expect(h.createProject).not.toHaveBeenCalled()
  })

  test('third_party with a 0 ceiling is refused, saying what 0 means', async () => {
    await expect(createProject(ctx(), {
      name: 'test', engagementKind: 'third_party', targetDomain: 'example.com',
      settings: { roeGlobalMaxRps: 0 },
      authorization: AUTH,
    })).rejects.toThrow(/NO ceiling/)
  })

  test('third_party with no authorization is refused', async () => {
    await expect(createProject(ctx(), {
      name: 'test', engagementKind: 'third_party', targetDomain: 'example.com',
      settings: { roeGlobalMaxRps: 3 },
    })).rejects.toThrow(/authorized it/)
    expect(h.createProject).not.toHaveBeenCalled()
  })

  test('third_party with both is created, and the authorization with it', async () => {
    const r = await createProject(ctx(), {
      name: 'test', engagementKind: 'third_party', targetDomain: 'example.com',
      settings: { roeGlobalMaxRps: 3 },
      authorization: AUTH,
    })
    expect(r.created).toBe(true)
    expect(h.createAuthorization).toHaveBeenCalled()
    expect(h.createAuthorization.mock.calls[0][0].data.documentSha256).toBe(AUTH.documentSha256)
  })

  test('the project and its authorization are written in ONE transaction', async () => {
    // A project that exists without the record that authorized it is exactly
    // the state the third-party rule is meant to make impossible.
    await createProject(ctx(), {
      name: 'test', engagementKind: 'third_party', targetDomain: 'example.com',
      settings: { roeGlobalMaxRps: 3 },
      authorization: AUTH,
    })
    expect(h.transaction).toHaveBeenCalledTimes(1)
  })
})

describe('create_project takes a digest, never the document', () => {
  test('documentText is digested here and not stored', async () => {
    await createProject(ctx(), {
      name: 'test', engagementKind: 'third_party', targetDomain: 'example.com',
      settings: { roeGlobalMaxRps: 3 },
      authorization: { ...AUTH, documentSha256: undefined, documentText: 'in scope: *.example.com' },
    })
    const data = h.createAuthorization.mock.calls[0][0].data
    expect(data.documentSha256).toMatch(/^[0-9a-f]{64}$/)
    expect(JSON.stringify(data)).not.toContain('in scope')
  })

  test('a malformed digest is refused', async () => {
    await expect(createProject(ctx(), {
      name: 'test', engagementKind: 'third_party', targetDomain: 'example.com',
      settings: { roeGlobalMaxRps: 3 },
      authorization: { ...AUTH, documentSha256: 'not-a-digest' },
    })).rejects.toThrow(/64 lower-case hex/)
  })

  test('a future issuedAt is refused', async () => {
    await expect(createProject(ctx(), {
      name: 'test', engagementKind: 'third_party', targetDomain: 'example.com',
      settings: { roeGlobalMaxRps: 3 },
      authorization: { ...AUTH, issuedAt: new Date(Date.now() + 86_400_000).toISOString() },
    })).rejects.toThrow(/future/)
  })

  test('recordedAt is the server clock, never the caller s', async () => {
    // A timestamp a caller can choose proves nothing.
    await createProject(ctx(), {
      name: 'test', engagementKind: 'third_party', targetDomain: 'example.com',
      settings: { roeGlobalMaxRps: 3 },
      authorization: { ...AUTH, recordedAt: '1999-01-01T00:00:00.000Z' } as never,
    })
    expect(h.createAuthorization.mock.calls[0][0].data).not.toHaveProperty('recordedAt')
  })

  test('the writing token is recorded, so a revoked one stays attributable', async () => {
    await createProject(ctx(), {
      name: 'test', engagementKind: 'third_party', targetDomain: 'example.com',
      settings: { roeGlobalMaxRps: 3 },
      authorization: AUTH,
    })
    expect(h.createAuthorization.mock.calls[0][0].data.recordedByTokenId).toBe('t1')
  })
})

describe('create_project is safe to retry', () => {
  test('the same idempotency key returns the FIRST project', async () => {
    // A retry is the normal failure path for an unattended loop, and a retry
    // that creates a second project is two engagements where the operator
    // authorized one.
    h.findUniqueAuthorization.mockResolvedValue({
      projectId: 'p1', project: { userId: 'owner', name: 'first' },
    })
    const r = await createProject(ctx(), {
      name: 'second', engagementKind: 'internal', targetDomain: 'example.com',
      idempotencyKey: 'nba-public-abc12345',
    })
    expect(r.created).toBe(false)
    expect(r.projectId).toBe('p1')
    expect(h.createProject).not.toHaveBeenCalled()
  })

  test('another account s idempotency key is refused, not returned', async () => {
    h.findUniqueAuthorization.mockResolvedValue({
      projectId: 'p1', project: { userId: 'someone-else', name: 'theirs' },
    })
    await expect(createProject(ctx(), {
      name: 'x', engagementKind: 'internal', targetDomain: 'example.com',
      idempotencyKey: 'nba-public-abc12345',
    })).rejects.toThrow(/another account/)
  })

  test('the key is checked BEFORE anything is written', async () => {
    h.findUniqueAuthorization.mockResolvedValue({
      projectId: 'p1', project: { userId: 'owner', name: 'first' },
    })
    await createProject(ctx(), {
      name: 'x', engagementKind: 'internal', targetDomain: 'example.com',
      idempotencyKey: 'k'.repeat(12),
    })
    expect(h.transaction).not.toHaveBeenCalled()
  })
})

describe('create_project validates what it writes', () => {
  test('the engagement limits go in `settings`, like any other field', async () => {
    // There is no `roe` argument any more. A limit is an ordinary setting, so a
    // caller does not have to know which block a field belongs to before it can
    // open an engagement.
    await createProject(ctx(), {
      name: 'test', engagementKind: 'internal', targetDomain: 'example.com',
      settings: { roeGlobalMaxRps: 3, roeExcludedHosts: ['pay.example.com'] },
    })
    const data = h.createProject.mock.calls[0][0].data
    expect(data.roeGlobalMaxRps).toBe(3)
    expect(data.roeExcludedHosts).toEqual(['pay.example.com'])
  })

  test('an engagement RECORD field is refused by name, even at creation', async () => {
    // The contract is a person's to write. It carries third-party personal data
    // and nothing in the pipeline enforces it.
    await expect(createProject(ctx(), {
      name: 'test', engagementKind: 'internal', targetDomain: 'example.com',
      settings: { roeClientContactEmail: 'someone@client.test' },
    })).rejects.toThrow(/roeClientContactEmail/)
  })

  test('the derived engagement flag is refused at creation too', async () => {
    await expect(createProject(ctx(), {
      name: 'test', engagementKind: 'internal', targetDomain: 'example.com',
      settings: { roeEnabled: true },
    })).rejects.toThrow(/roeEnabled/)
  })

  test('an out-of-bounds tuning value is refused', async () => {
    await expect(createProject(ctx(), {
      name: 'test', engagementKind: 'internal', targetDomain: 'example.com',
      settings: { naabuThreads: 999_999 },
    })).rejects.toThrow(/between/)
  })

  test('an identity header that would re-point the request is refused', async () => {
    await expect(createProject(ctx(), {
      name: 'test', engagementKind: 'internal', targetDomain: 'example.com',
      engagementIdentityHeader: 'Host: victim.com',
    })).rejects.toThrow(/host/)
  })

  test('an ordinary identity header is accepted', async () => {
    await createProject(ctx(), {
      name: 'test', engagementKind: 'internal', targetDomain: 'example.com',
      engagementIdentityHeader: 'X-Bug-Bounty: my-handle',
    })
    expect(h.createProject.mock.calls[0][0].data.engagementIdentityHeader)
      .toBe('X-Bug-Bounty: my-handle')
  })
})

// --- the engagement limits, through the ordinary settings path -------------------------

describe('an engagement limit is changed with update_recon_settings', () => {
  test('lowering the ceiling is accepted', async () => {
    h.findProject.mockResolvedValue(projectRow({ roeGlobalMaxRps: 3 }))
    await updateReconSettings(ctx(['recon:settings']), 'p1', { roeGlobalMaxRps: 1 })
    expect(h.updateManyProject).toHaveBeenCalled()
    expect(h.updateManyProject.mock.calls[0][0].data).toEqual({ roeGlobalMaxRps: 1 })
  })

  test('raising the ceiling is ALSO accepted, and audited', async () => {
    // The direction rule is gone. What replaced it is not permissiveness: the
    // ceiling is applied at scan start whatever it says, so raising it changes
    // what runs rather than what is checked, and preflight_scope_check reports
    // the resolved rates. The audit row is what records the move.
    h.findProject.mockResolvedValue(projectRow({ roeGlobalMaxRps: 3 }))
    await updateReconSettings(ctx(['recon:settings']), 'p1', { roeGlobalMaxRps: 10 })
    expect(h.updateManyProject.mock.calls[0][0].data).toEqual({ roeGlobalMaxRps: 10 })
    const row = h.audit.mock.calls[0][0]
    expect(row.before).toEqual({ roeGlobalMaxRps: 3 })
  })

  test('recon:settings is enough; project:create is not required', async () => {
    // B4: project:create governs create_project alone now.
    h.findProject.mockResolvedValue(projectRow({ roeGlobalMaxRps: 3 }))
    await expect(
      updateReconSettings(ctx(['recon:settings']), 'p1', { roeExcludedHosts: ['a.tld'] })
    ).resolves.toBeTruthy()
  })

  test('an engagement RECORD field is still refused by name', async () => {
    h.findProject.mockResolvedValue(projectRow({}))
    await expect(
      updateReconSettings(ctx(['recon:settings']), 'p1', { roeClientName: 'Acme' })
    ).rejects.toThrow(/roeClientName/)
  })

  test('it is refused while a scan is writing the graph', async () => {
    // The running scan read its settings at start, so a change accepted
    // mid-scan is one that silently did not apply.
    h.busy.mockResolvedValue('a full recon is running')
    await expect(
      updateReconSettings(ctx(['recon:settings']), 'p1', { roeGlobalMaxRps: 1 })
    ).rejects.toThrow(/will not see/)
  })
})

// --- attach_engagement_authorization -------------------------------------------------------

describe('attach_engagement_authorization is append-only', () => {
  test('it needs engagement:authorize, which project:create does not imply', async () => {
    await expect(attachEngagementAuthorization(ctx(['project:create']), 'p1', AUTH))
      .rejects.toBeInstanceOf(McpScopeError)
  })

  test('it creates rather than updating', async () => {
    await attachEngagementAuthorization(ctx(), 'p1', AUTH)
    expect(h.createAuthorization).toHaveBeenCalled()
  })

  test('it reports what it supersedes without removing it', async () => {
    h.findFirstAuthorization.mockResolvedValue({ id: 'auth0', programHandle: 'nba-public' })
    const r = await attachEngagementAuthorization(ctx(), 'p1', AUTH)
    expect(r.supersedes).toBe('auth0')
    expect(r.note).toMatch(/Append-only/)
  })

  test('a DIFFERENT program is flagged, and does not re-point the project', async () => {
    // A project quietly re-authorized against another program's scope is the
    // failure this note exists for.
    h.findFirstAuthorization.mockResolvedValue({ id: 'auth0', programHandle: 'other-program' })
    const r = await attachEngagementAuthorization(ctx(), 'p1', AUTH)
    expect(r.note).toMatch(/DIFFERENT program/)
    expect(r.note).toMatch(/still the one it was created with/)
  })

  test('it writes an audit row carrying the digest', async () => {
    await attachEngagementAuthorization(ctx(), 'p1', AUTH)
    const row = h.audit.mock.calls[0][0]
    expect(row.action).toBe('mcp.attach_authorization')
    expect((row.after as Record<string, unknown>).documentSha256).toBe(AUTH.documentSha256)
  })

  test('there is no update or delete path on this module', async () => {
    const mod = await import('./engagementTools')
    const names = Object.keys(mod).join(' ')
    expect(names).not.toMatch(/updateAuthorization|deleteAuthorization|revokeAuthorization/)
  })
})

// --- preflight_scope_check -------------------------------------------------------------

describe('preflight_scope_check reports RESOLVED values', () => {
  test('it needs only recon:read', async () => {
    await expect(preflightScopeCheck(ctx([]), 'p1')).rejects.toBeInstanceOf(McpScopeError)
    await expect(preflightScopeCheck(ctx(['recon:read']), 'p1')).resolves.toBeTruthy()
  })

  test('a rate above the ceiling is reported at the ceiling, not as written', async () => {
    h.findProject.mockResolvedValue(projectRow({
      roeEnabled: true, roeGlobalMaxRps: 3, naabuRateLimit: 1000,
    }))
    const r = await preflightScopeCheck(ctx(), 'p1')
    const naabu = r.resolvedRates.find(x => x.field === 'naabuRateLimit')!
    expect(naabu.written).toBe(1000)
    expect(naabu.resolved).toBe(3)
    expect(naabu.capped).toBe(true)
  })

  test('a zero that means unlimited is reported at the ceiling too', async () => {
    // The failure a `value > ceiling` check cannot see.
    h.findProject.mockResolvedValue(projectRow({
      roeEnabled: true, roeGlobalMaxRps: 3, ffufRate: 0,
    }))
    const r = await preflightScopeCheck(ctx(), 'p1')
    const ffuf = r.resolvedRates.find(x => x.field === 'ffufRate')!
    expect(ffuf.resolved).toBe(3)
    expect(ffuf.wasUnlimited).toBe(true)
  })

  test('with no ceiling, a zero rate is reported as unlimited rather than as zero', async () => {
    const r = await preflightScopeCheck(ctx(), 'p1')
    const ffuf = r.resolvedRates.find(x => x.field === 'ffufRate')!
    expect(ffuf.resolved).toBe(0)
    expect(ffuf.wasUnlimited).toBe(true)
  })

  test('no rate ever resolves above the ceiling', async () => {
    h.findProject.mockResolvedValue(projectRow({
      roeEnabled: true, roeGlobalMaxRps: 3,
      naabuRateLimit: 5000, nucleiRateLimit: 500, takeoverRateLimit: 500,
    }))
    const r = await preflightScopeCheck(ctx(), 'p1')
    expect(r.ratesExceedingCeiling).toEqual([])
    for (const rate of r.resolvedRates) expect(rate.resolved, rate.field).toBeLessThanOrEqual(3)
  })

  test('a non-allowlisted image is reported as pinned', async () => {
    // get_recon_settings will echo what was written. This is the only place a
    // caller learns which image actually runs.
    h.findProject.mockResolvedValue(projectRow({ nucleiDockerImage: 'attacker/evil:latest' }))
    const r = await preflightScopeCheck(ctx(), 'p1')
    const rewrite = r.rewrittenAtScanStart.find(x => x.field === 'nucleiDockerImage')!
    expect(rewrite.written).toBe('attacker/evil:latest')
    expect(rewrite.willRun).toBe('projectdiscovery/nuclei:latest')
  })

  test('a shipped image is NOT reported as rewritten', async () => {
    const r = await preflightScopeCheck(ctx(), 'p1')
    expect(r.rewrittenAtScanStart.some(x => x.field === 'nucleiDockerImage')).toBe(false)
  })

  test('an escaping wordlist path is reported as dropped', async () => {
    h.findProject.mockResolvedValue(projectRow({ ffufWordlist: '/etc/shadow' }))
    const r = await preflightScopeCheck(ctx(), 'p1')
    expect(r.rewrittenAtScanStart.some(x => x.field === 'ffufWordlist')).toBe(true)
  })

  test('a tool enabled in a phase that is not running is named as a silent no-op', async () => {
    // The two-level model biting: the scan succeeds, that tool never runs, and
    // no result field says why.
    h.findProject.mockResolvedValue(projectRow({
      scanModules: ['domain_discovery'], ffufEnabled: true,
    }))
    const r = await preflightScopeCheck(ctx(), 'p1')
    expect(r.silentNoOps.some(x => x.field === 'ffufEnabled')).toBe(true)
  })

  test('a tool enabled in a phase that IS running is not a no-op', async () => {
    h.findProject.mockResolvedValue(projectRow({
      scanModules: ['domain_discovery', 'port_scan'], naabuEnabled: true,
    }))
    const r = await preflightScopeCheck(ctx(), 'p1')
    expect(r.silentNoOps.some(x => x.field === 'naabuEnabled')).toBe(false)
  })

  test('startable is false exactly when start_recon would refuse', async () => {
    h.findProject.mockResolvedValue(projectRow({
      engagementKind: 'third_party', roeEnabled: true, roeGlobalMaxRps: 3,
    }))
    h.countAuthorization.mockResolvedValue(0)
    expect((await preflightScopeCheck(ctx(), 'p1')).startable).toBe(false)

    h.countAuthorization.mockResolvedValue(1)
    expect((await preflightScopeCheck(ctx(), 'p1')).startable).toBe(true)
  })

  test('it returns no credential and no client identity', async () => {
    h.findProject.mockResolvedValue(projectRow({
      cypherfixGithubToken: 'ghp_secret',
      roeClientContactEmail: 'someone@client.example',
      graphqlAuthValue: 'Bearer secret',
    }))
    const serialised = JSON.stringify(await preflightScopeCheck(ctx(), 'p1'))
    expect(serialised).not.toContain('ghp_secret')
    expect(serialised).not.toContain('client.example')
    expect(serialised).not.toContain('Bearer secret')
  })

  test('it reports the provenance of the last run', async () => {
    // The middle of the chain an incident review walks: a graph node, the scan
    // job that wrote it, the settings it ran with, the document that permitted
    // looking. JobQueue.settingsHash is the only other settings fingerprint and
    // it is deleted with the queue row at dispatch.
    h.findFirstScanJob.mockResolvedValue({
      id: 'job1', kind: 'full_recon', status: 'completed',
      startedAt: new Date('2026-01-01T00:00:00.000Z'), versionId: 'v3',
      settingsHash: 'f'.repeat(64), authorizationId: 'auth1',
    })
    const r = await preflightScopeCheck(ctx(), 'p1')
    expect(r.lastRun?.scanJobId).toBe('job1')
    expect(r.lastRun?.authorizationId).toBe('auth1')
    expect(r.lastRun?.scanVersionId).toBe('v3')
  })

  test('it says when the settings changed since the last run', async () => {
    // The graph you are looking at was produced by a DIFFERENT configuration
    // than the one being reported.
    h.findFirstScanJob.mockResolvedValue({
      id: 'job1', kind: 'full_recon', status: 'completed', startedAt: new Date(),
      versionId: null, settingsHash: 'f'.repeat(64), authorizationId: null,
    })
    expect((await preflightScopeCheck(ctx(), 'p1')).lastRun?.settingsChangedSince).toBe(true)
  })

  test('a run that predates provenance reports null, not false', async () => {
    // "We do not know" is not "nothing changed".
    h.findFirstScanJob.mockResolvedValue({
      id: 'job0', kind: 'full_recon', status: 'completed', startedAt: new Date(),
      versionId: null, settingsHash: null, authorizationId: null,
    })
    expect((await preflightScopeCheck(ctx(), 'p1')).lastRun?.settingsChangedSince).toBeNull()
  })

  test('a project that has never been scanned reports no last run', async () => {
    expect((await preflightScopeCheck(ctx(), 'p1')).lastRun).toBeNull()
  })

  test('a missing project is refused, not reported as an empty one', async () => {
    // assertMcpProjectAccess gets there first and refuses with the same message
    // it uses for another account's project. That is deliberate: distinguishing
    // "does not exist" from "not yours" is a project enumeration oracle.
    h.findProject.mockResolvedValue(null)
    await expect(preflightScopeCheck(ctx(), 'p1')).rejects.toThrow(/not found/)
  })
})

describe('list_engagement_authorizations', () => {
  test('it returns the history newest first and says it is append-only', async () => {
    h.findManyAuthorization.mockResolvedValue([{ id: 'auth2' }, { id: 'auth1' }])
    const r = await listEngagementAuthorizations(ctx(), 'p1')
    expect(r.authorizations).toHaveLength(2)
    expect(h.findManyAuthorization.mock.calls[0][0].orderBy).toEqual({ recordedAt: 'desc' })
    expect(r.note).toMatch(/Append-only/)
  })

  test('an empty list is a real answer for an internal engagement', async () => {
    const r = await listEngagementAuthorizations(ctx(), 'p1')
    expect(r.authorizations).toEqual([])
  })
})

// --- T24: the guards every state-changing tool keeps ----------------------------------------

describe('T24 every new tool joins the guards the others keep', () => {
  test('each state-changing tool writes an audit row', async () => {
    await createProject(ctx(), { name: 'a', engagementKind: 'internal', targetDomain: 'a.tld' })
    expect(h.audit).toHaveBeenCalledTimes(1)

    h.audit.mockClear()
    h.findProject.mockResolvedValue(projectRow())
    await updateReconSettings(ctx(), 'p1', { roeExcludedHosts: ['a.tld'] })
    expect(h.audit).toHaveBeenCalledTimes(1)

    h.audit.mockClear()
    await attachEngagementAuthorization(ctx(), 'p1', AUTH)
    expect(h.audit).toHaveBeenCalledTimes(1)
  })

  test('each read-only tool writes none', async () => {
    await preflightScopeCheck(ctx(), 'p1')
    await listEngagementAuthorizations(ctx(), 'p1')
    expect(h.audit).not.toHaveBeenCalled()
  })

  test('every tool taking a projectId asserts access to it', async () => {
    // assertMcpProjectAccess loads the project and compares its owner. A tool
    // that skipped it would read another account's engagement.
    h.findProject.mockResolvedValue({ ...projectRow(), userId: 'someone-else' })
    for (const call of [
      () => updateReconSettings(ctx(), 'p1', { roeExcludedHosts: ['a'] }),
      () => attachEngagementAuthorization(ctx(), 'p1', AUTH),
      () => preflightScopeCheck(ctx(), 'p1'),
      () => listEngagementAuthorizations(ctx(), 'p1'),
    ]) {
      await expect(call()).rejects.toThrow()
    }
  })
})
