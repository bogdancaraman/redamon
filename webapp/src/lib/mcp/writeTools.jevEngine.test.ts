/**
 * update_recon_settings and the Jev engine flags.
 *
 * The project form checks the owner's Jev token in the browser, but the MCP
 * writer is the other door onto the same column, so it enforces the same rule on
 * the server: a switch-on needs a token on the project owner's account, a stored
 * `true` never blocks an unrelated write, and a failed lookup refuses.
 *
 * Over MCP the token's user must be the project's owner (a mismatch is always a
 * hard deny), so the acting account and the owner are the same here; the check
 * reads the stored row's owner regardless.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  findProject: vi.fn(),
  updateManyProjects: vi.fn(),
  tokenCount: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: {
      findUnique: (...a: unknown[]) => h.findProject(...a),
      updateMany: (...a: unknown[]) => h.updateManyProjects(...a),
    },
    userLlmProvider: { count: (...a: unknown[]) => h.tokenCount(...a) },
    jobQueue: { findMany: async () => [] },
    projectAuthProfile: { findUnique: async () => null },
    fireteamSettingsAudit: { createMany: async () => ({}) },
    scanSchedule: { findMany: async () => [] },
  },
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))
vi.mock('@/lib/graphWriters', () => ({
  describeLiveGraphWriters: async () => null,
  describeScanWriters: async () => null,
}))
vi.mock('@/lib/startFullScan', () => ({ startFullScan: vi.fn() }))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn(async () => undefined) }))

import { __resetRateLimiter } from '@/lib/mcpAuth'
import { updateReconSettings } from './writeTools'
import type { McpContext } from './tools'

const READ_AT = new Date('2026-09-29T08:00:00.000Z')

const ctx = (): McpContext => ({
  token: {
    tokenId: 't1', userId: 'owner', tokenPrefix: 'rdmn_mcp_aaaaaaaa',
    name: 'agent', scopes: ['recon:read', 'recon:settings'] as never,
  },
})

let stored: Record<string, unknown>

beforeEach(() => {
  vi.clearAllMocks()
  __resetRateLimiter()
  stored = {
    id: 'p1', userId: 'owner', updatedAt: READ_AT,
    ffufAiUseJev: false, nucleiTagsAiUseJev: false, wafAiUseJev: false, takeoverAiUseJev: false,
  }
  h.findProject.mockImplementation(async () => ({ ...stored }))
  h.updateManyProjects.mockResolvedValue({ count: 1 })
  h.tokenCount.mockResolvedValue(0)
})

describe('update_recon_settings: a switch onto Jev', () => {
  test('with a token on the owner\'s account it is written', async () => {
    h.tokenCount.mockResolvedValue(1)
    const r = await updateReconSettings(ctx(), 'p1', { ffufAiUseJev: true })
    expect(r.projectId).toBe('p1')
    expect(h.updateManyProjects.mock.calls[0][0].data).toEqual({ ffufAiUseJev: true })
  })

  test('the lookup is for the stored owner and the jev provider type', async () => {
    h.tokenCount.mockResolvedValue(1)
    await updateReconSettings(ctx(), 'p1', { wafAiUseJev: true })
    expect(h.tokenCount).toHaveBeenCalledWith({ where: { userId: 'owner', providerType: 'jev' } })
  })

  test('without a token it is refused, naming the field, and nothing is written', async () => {
    await expect(updateReconSettings(ctx(), 'p1', { nucleiTagsAiUseJev: true }))
      .rejects.toThrow(/nucleiTagsAiUseJev.*no TypeSafe AI \(Jev\) token/s)
    expect(h.updateManyProjects).not.toHaveBeenCalled()
  })

  test('it fails closed when the lookup throws', async () => {
    h.tokenCount.mockRejectedValue(new Error('db down'))
    await expect(updateReconSettings(ctx(), 'p1', { ffufAiUseJev: true }))
      .rejects.toThrow("Couldn't verify your Jev token, try again.")
    expect(h.updateManyProjects).not.toHaveBeenCalled()
  })
})

describe('update_recon_settings: a stored Jev choice is not a reason to refuse', () => {
  test('an unchanged true with no token still allows an unrelated write', async () => {
    stored.ffufAiUseJev = true
    const r = await updateReconSettings(ctx(), 'p1', { ffufAiUseJev: true, naabuThreads: 25 })
    expect(r.projectId).toBe('p1')
    expect(h.tokenCount).not.toHaveBeenCalled()
  })

  test('switching back to the LLM needs no token', async () => {
    stored.wafAiUseJev = true
    await updateReconSettings(ctx(), 'p1', { wafAiUseJev: false })
    expect(h.tokenCount).not.toHaveBeenCalled()
    expect(h.updateManyProjects.mock.calls[0][0].data).toEqual({ wafAiUseJev: false })
  })
})

describe('update_recon_settings: turning on a Jev-only hook', () => {
  test.each(['ffufJevBasePaths', 'httpxJevPageType', 'resourceEnumJevToolHealth', 'hakrawlerJevSeedOrder',
    'serializedScanJevRank'])(
    '%s without a token is refused and nothing is written', async (field) => {
      await expect(updateReconSettings(ctx(), 'p1', { [field]: true }))
        .rejects.toThrow(new RegExp(`${field}.*no TypeSafe AI \\(Jev\\) token`, 's'))
      expect(h.updateManyProjects).not.toHaveBeenCalled()
    })

  test('with a token it is written', async () => {
    h.tokenCount.mockResolvedValue(1)
    await updateReconSettings(ctx(), 'p1', { ffufJevBasePaths: true })
    expect(h.updateManyProjects.mock.calls[0][0].data).toEqual({ ffufJevBasePaths: true })
  })
})
