/**
 * create_project and the Jev engine flags.
 *
 * A new project starts with every engine on the LLM, so an engine flag in
 * `settings` is a switch-on and needs a Jev token on the creating account. The
 * check runs before anything is written, so a refusal leaves no project behind.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  createProject: vi.fn(),
  tokenCount: vi.fn(),
  audit: vi.fn(),
}))

vi.mock('@/lib/prisma', () => {
  const client = {
    project: {
      create: (...a: unknown[]) => h.createProject(...a),
      findUnique: vi.fn(),
      update: vi.fn(),
      updateMany: vi.fn(),
    },
    userLlmProvider: { count: (...a: unknown[]) => h.tokenCount(...a) },
    engagementAuthorization: {
      create: vi.fn(), findFirst: vi.fn(), findUnique: vi.fn(), findMany: vi.fn(), count: vi.fn(),
    },
    scanJob: { findFirst: vi.fn() },
    $transaction: (fn: (tx: unknown) => unknown) => fn(client),
  }
  return { default: client }
})
vi.mock('@/lib/graphWriters', () => ({ describeScanWriters: vi.fn(async () => null) }))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))

import { __resetRateLimiter } from '@/lib/mcpAuth'
import { createProject } from './engagementTools'
import type { McpContext } from './tools'

const ctx = (): McpContext => ({
  token: {
    tokenId: 't1', userId: 'creator', tokenPrefix: 'rdmn_mcp_aaaaaaaa',
    name: 'agent', scopes: ['recon:read', 'project:create'] as never,
  },
})

const args = (settings: Record<string, unknown>) => ({
  name: 'test', engagementKind: 'internal' as const, targetDomain: 'example.com', settings,
})

beforeEach(() => {
  vi.clearAllMocks()
  __resetRateLimiter()
  h.createProject.mockResolvedValue({ id: 'p1', name: 'test' })
  h.tokenCount.mockResolvedValue(0)
  h.audit.mockResolvedValue(undefined)
})

describe('create_project: a Jev engine flag in settings', () => {
  test('with a token on the creating account it reaches the create call', async () => {
    h.tokenCount.mockResolvedValue(1)
    const r = await createProject(ctx(), args({ ffufAiUseJev: true }))
    expect(r.created).toBe(true)
    expect(h.createProject.mock.calls[0][0].data.ffufAiUseJev).toBe(true)
    expect(h.tokenCount).toHaveBeenCalledWith({ where: { userId: 'creator', providerType: 'jev' } })
  })

  test('without a token it is refused and no project is created', async () => {
    await expect(createProject(ctx(), args({ wafAiUseJev: true })))
      .rejects.toThrow(/wafAiUseJev.*no TypeSafe AI \(Jev\) token/s)
    expect(h.createProject).not.toHaveBeenCalled()
  })

  test('it fails closed when the lookup throws', async () => {
    h.tokenCount.mockRejectedValue(new Error('db down'))
    await expect(createProject(ctx(), args({ takeoverAiUseJev: true })))
      .rejects.toThrow("Couldn't verify your Jev token, try again.")
    expect(h.createProject).not.toHaveBeenCalled()
  })

  test('settings with no engine flag never touch the token table', async () => {
    await createProject(ctx(), args({ naabuThreads: 25 }))
    expect(h.tokenCount).not.toHaveBeenCalled()
  })
})

describe('create_project: a Jev-only hook flag in settings', () => {
  test.each(['ffufJevBasePaths', 'httpxJevPageType', 'resourceEnumJevToolHealth', 'hakrawlerJevSeedOrder',
    'serializedScanJevRank'])(
    '%s without a token is refused and no project is created', async (field) => {
      await expect(createProject(ctx(), args({ [field]: true })))
        .rejects.toThrow(new RegExp(`${field}.*no TypeSafe AI \\(Jev\\) token`, 's'))
      expect(h.createProject).not.toHaveBeenCalled()
    })

  test('with a token it reaches the create call', async () => {
    h.tokenCount.mockResolvedValue(1)
    const r = await createProject(ctx(), args({ httpxJevPageType: true }))
    expect(r.created).toBe(true)
    expect(h.createProject.mock.calls[0][0].data.httpxJevPageType).toBe(true)
  })
})
