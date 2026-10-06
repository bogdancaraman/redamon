/**
 * POST /api/projects and the Jev engine flags.
 *
 * A new project starts with every engine on the LLM, so any engine flag in the
 * body is a switch-on and needs a Jev token on the CREATING user's account. The
 * flags must also survive into the create call: the route passes a column
 * through only if the generated Prisma client lists it.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const mockUserFindUnique = vi.fn()
const mockProjectCreate = vi.fn()
const mockProjectUpdate = vi.fn()
const mockTokenCount = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    user: { findUnique: (...a: unknown[]) => mockUserFindUnique(...a) },
    project: {
      create: (...a: unknown[]) => mockProjectCreate(...a),
      update: (...a: unknown[]) => mockProjectUpdate(...a),
    },
    userLlmProvider: { count: (...a: unknown[]) => mockTokenCount(...a) },
  },
}))
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({ run: vi.fn().mockResolvedValue({ records: [] }), close: vi.fn() }),
}))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn().mockResolvedValue({ userId: 'user-1' }),
  ownerScope: (eff: { userId: string }) => ({ userId: eff.userId }),
}))

import { Prisma } from '@prisma/client'
import { NextRequest } from 'next/server'
import { POST } from './route'

const postReq = (body: Record<string, unknown>) =>
  new NextRequest('http://localhost:3000/api/projects', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })

const base = { name: 'test', targetDomain: 'example.invalid' }

beforeEach(() => {
  vi.clearAllMocks()
  mockUserFindUnique.mockResolvedValue({ id: 'user-1' })
  mockProjectCreate.mockResolvedValue({ id: 'p1', name: 'test' })
  mockProjectUpdate.mockResolvedValue({})
  mockTokenCount.mockResolvedValue(0)
})

describe('the generated client knows every Jev column', () => {
  test.each(['ffufAiUseJev', 'nucleiTagsAiUseJev', 'wafAiUseJev', 'takeoverAiUseJev',
    'ffufJevBasePaths', 'httpxJevPageType', 'resourceEnumJevToolHealth', 'hakrawlerJevSeedOrder',
    'serializedScanJevRank'])(
    '%s is a Project scalar', name => {
      expect(Object.values(Prisma.ProjectScalarFieldEnum)).toContain(name)
    })
})

describe('POST: a new project asking for the Jev engine', () => {
  test('with a token on the creating account the flag reaches the create call', async () => {
    mockTokenCount.mockResolvedValue(1)
    const res = await POST(postReq({ ...base, ffufAiUseJev: true }))
    expect(res.status).toBeLessThan(400)
    expect(mockProjectCreate.mock.calls[0][0].data.ffufAiUseJev).toBe(true)
    expect(mockTokenCount).toHaveBeenCalledWith({ where: { userId: 'user-1', providerType: 'jev' } })
  })

  test('without a token it is refused and no project is created', async () => {
    const res = await POST(postReq({ ...base, wafAiUseJev: true }))
    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain('wafAiUseJev')
    expect(mockProjectCreate).not.toHaveBeenCalled()
  })

  test('it fails closed when the lookup throws', async () => {
    mockTokenCount.mockRejectedValue(new Error('db down'))
    const res = await POST(postReq({ ...base, takeoverAiUseJev: true }))
    expect(res.status).toBe(400)
    expect(mockProjectCreate).not.toHaveBeenCalled()
  })

  test('the form sends every engine flag as false: that is not a switch-on and needs no token', async () => {
    const res = await POST(postReq({
      ...base, ffufAiUseJev: false, nucleiTagsAiUseJev: false, wafAiUseJev: false, takeoverAiUseJev: false,
    }))
    expect(res.status).toBeLessThan(400)
    expect(mockTokenCount).not.toHaveBeenCalled()
  })
})

describe('POST: a new project turning on a Jev-only hook', () => {
  test.each(['ffufJevBasePaths', 'httpxJevPageType', 'resourceEnumJevToolHealth', 'hakrawlerJevSeedOrder',
    'serializedScanJevRank'])(
    '%s without a token is refused and no project is created', async (field) => {
      const res = await POST(postReq({ ...base, [field]: true }))
      expect(res.status).toBe(400)
      expect((await res.json()).error).toContain(field)
      expect(mockProjectCreate).not.toHaveBeenCalled()
    })

  test.each(['true', 'TRUE'])('the string "%s" is a switch-on too', async (value) => {
    // The body is coerced to booleans after it is read; judging the raw body let a
    // string through to a project created with the flag on and no token.
    const res = await POST(postReq({ ...base, serializedScanJevRank: value }))
    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain('serializedScanJevRank')
    expect(mockProjectCreate).not.toHaveBeenCalled()
  })

  test('the form sends every Jev-only flag as false: no switch-on, no lookup', async () => {
    const res = await POST(postReq({
      ...base, ffufJevBasePaths: false, httpxJevPageType: false, resourceEnumJevToolHealth: false,
      hakrawlerJevSeedOrder: false, serializedScanJevRank: false,
    }))
    expect(res.status).toBeLessThan(400)
    expect(mockTokenCount).not.toHaveBeenCalled()
  })
})
