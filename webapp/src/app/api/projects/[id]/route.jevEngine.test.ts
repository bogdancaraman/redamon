/**
 * PUT /api/projects/[id] and the Jev engine flags.
 *
 * A switch onto Jev needs a Jev token on the project OWNER's account. Only a
 * switch-on is judged: the form sends every field on every save, so a stored
 * `true` must never block a save of a project whose owner later lost the token.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const mockFindUnique = vi.fn()
const mockUpdate = vi.fn()
const mockUpdateMany = vi.fn()
const mockTokenCount = vi.fn()
const mockActor = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    project: {
      findUnique: (...a: unknown[]) => mockFindUnique(...a),
      update: (...a: unknown[]) => mockUpdate(...a),
      updateMany: (...a: unknown[]) => mockUpdateMany(...a),
    },
    userLlmProvider: { count: (...a: unknown[]) => mockTokenCount(...a) },
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ run: vi.fn(), close: vi.fn() }) }))
vi.mock('@/lib/graphWriters', () => ({ describeScanWriters: async () => null }))
vi.mock('@/lib/graphRestore', () => ({ clearProjectGraph: vi.fn() }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))
vi.mock('@/lib/session', () => ({ isInternalRequest: () => false, isScannerRequest: () => false }))
vi.mock('@/lib/access', async () => {
  const actual = await vi.importActual<typeof import('@/lib/access')>('@/lib/access')
  return {
    ...actual,
    requireEffectiveUser: async () => mockActor(),
    requireProjectAccess: async () => ({ project: { id: 'proj-1', userId: 'owner' } }),
  }
})

import { PUT } from './route'

const JEV_ONLY = ['ffufJevBasePaths', 'httpxJevPageType', 'resourceEnumJevToolHealth',
  'hakrawlerJevSeedOrder', 'serializedScanJevRank'] as const

const STORED = {
  id: 'proj-1', userId: 'owner', name: 'p', targetDomain: 'example.test',
  ipMode: false, domainBatchMode: false, katanaDepth: 2,
  ffufAiUseJev: false, nucleiTagsAiUseJev: false, wafAiUseJev: false, takeoverAiUseJev: false,
  ...Object.fromEntries(JEV_ONLY.map(k => [k, false])),
  updatedAt: new Date('2026-09-29T10:00:00.000Z'),
}

function put(body: Record<string, unknown>) {
  return PUT(
    new NextRequest('http://localhost/api/projects/proj-1', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
    { params: Promise.resolve({ id: 'proj-1' }) },
  )
}

let stored: Record<string, unknown>

beforeEach(() => {
  vi.clearAllMocks()
  stored = { ...STORED }
  mockActor.mockResolvedValue({ userId: 'owner', isAdmin: false })
  // Honour `select` the way Prisma does. Returning the whole row hid a route that
  // read only four engine fields: every Jev-only true read back as a switch-on.
  mockFindUnique.mockImplementation(async (args?: { select?: Record<string, unknown> }) => {
    if (!args?.select) return { ...stored }
    return Object.fromEntries(Object.keys(args.select).filter(k => args.select![k]).map(k => [k, stored[k]]))
  })
  mockUpdate.mockImplementation(async ({ data }: { data: Record<string, unknown> }) => ({ ...stored, ...data }))
  mockUpdateMany.mockResolvedValue({ count: 1 })
  mockTokenCount.mockResolvedValue(0)
})

describe('PUT: a switch onto Jev', () => {
  test('with a token on the owner\'s account it is written', async () => {
    mockTokenCount.mockResolvedValue(1)
    const res = await put({ name: 'p', ffufAiUseJev: true })
    expect(res.status).toBe(200)
    expect(mockUpdate.mock.calls[0][0].data.ffufAiUseJev).toBe(true)
  })

  test('without a token it is refused with 400 and nothing is written', async () => {
    const res = await put({ name: 'p', ffufAiUseJev: true, wafAiUseJev: true })
    expect(res.status).toBe(400)
    const { error } = await res.json()
    expect(error).toContain('ffufAiUseJev')
    expect(error).toContain('wafAiUseJev')
    expect(error).toContain('Settings')
    expect(mockUpdate).not.toHaveBeenCalled()
    expect(mockUpdateMany).not.toHaveBeenCalled()
  })

  test('the token is looked up for the project OWNER, not the admin acting on it', async () => {
    mockActor.mockResolvedValue({ userId: 'admin-1', isAdmin: true })
    mockTokenCount.mockResolvedValue(0)
    const res = await put({ name: 'p', ffufAiUseJev: true })
    expect(res.status).toBe(400)
    expect(mockTokenCount).toHaveBeenCalledWith({ where: { userId: 'owner', providerType: 'jev' } })
  })

  test('it fails closed when the token lookup throws', async () => {
    mockTokenCount.mockRejectedValue(new Error('db down'))
    const res = await put({ name: 'p', takeoverAiUseJev: true })
    expect(res.status).toBe(400)
    expect((await res.json()).error).toBe("Couldn't verify your Jev token, try again.")
    expect(mockUpdate).not.toHaveBeenCalled()
  })
})

describe('PUT: a stored Jev choice is never a reason to refuse a save', () => {
  test('an unchanged true with no token still saves an unrelated field', async () => {
    stored.ffufAiUseJev = true
    stored.wafAiUseJev = true
    const res = await put({ name: 'p', katanaDepth: 4, ffufAiUseJev: true, wafAiUseJev: true })
    expect(res.status).toBe(200)
    expect(mockTokenCount).not.toHaveBeenCalled()
    expect(mockUpdate.mock.calls[0][0].data.katanaDepth).toBe(4)
  })

  test.each(JEV_ONLY)('an unchanged Jev-only %s=true with no token still saves an unrelated field', async (field) => {
    stored[field] = true
    const res = await put({ name: 'p', katanaDepth: 4, [field]: true })
    expect(res.status).toBe(200)
    expect(mockTokenCount).not.toHaveBeenCalled()
    expect(mockUpdate.mock.calls[0][0].data.katanaDepth).toBe(4)
  })

  test('switching a hook back to the LLM never needs a token', async () => {
    stored.ffufAiUseJev = true
    const res = await put({ name: 'p', ffufAiUseJev: false })
    expect(res.status).toBe(200)
    expect(mockTokenCount).not.toHaveBeenCalled()
  })

  test('a save that names no engine field never touches the token table', async () => {
    const res = await put({ name: 'p', katanaDepth: 3 })
    expect(res.status).toBe(200)
    expect(mockTokenCount).not.toHaveBeenCalled()
  })
})

describe('PUT: turning on a Jev-only hook', () => {
  test('without a token it is refused with 400 and nothing is written', async () => {
    const res = await put({ name: 'p', httpxJevPageType: true })
    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain('httpxJevPageType (page-type labels)')
    expect(mockUpdate).not.toHaveBeenCalled()
  })

  test('with a token on the owner\'s account it is written', async () => {
    mockTokenCount.mockResolvedValue(1)
    const res = await put({ name: 'p', resourceEnumJevToolHealth: true })
    expect(res.status).toBe(200)
    expect(mockUpdate.mock.calls[0][0].data.resourceEnumJevToolHealth).toBe(true)
  })
})
