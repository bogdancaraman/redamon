/**
 * The server-side check behind the LLM | Jev engine switch.
 *
 * The form's own token lookup is a convenience; this is the authority. It
 * refuses a SWITCH-ON to Jev when the project owner has no Jev token, and
 * nothing else: a stored `true` must never block an unrelated save.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const mockCount = vi.fn()
vi.mock('@/lib/prisma', () => ({
  default: { userLlmProvider: { count: (...a: unknown[]) => mockCount(...a) } },
}))

import {
  JEV_ENGINE_FIELDS, JEV_HOOK_LABEL, JEV_VERIFY_FAILED, jevImportWarnings, jevSwitchedOn,
  validateJevEngineChange,
} from './jevEngine'

beforeEach(() => {
  mockCount.mockReset().mockResolvedValue(0)
})

describe('jevSwitchedOn', () => {
  test('a field turned on is a switch-on', () => {
    expect(jevSwitchedOn({ ffufAiUseJev: false }, { ffufAiUseJev: true })).toEqual(['ffufAiUseJev'])
  })

  test('a field already true stays true: not a switch-on', () => {
    expect(jevSwitchedOn({ ffufAiUseJev: true }, { ffufAiUseJev: true })).toEqual([])
  })

  test('a field absent from the write is not a switch-on, even when stored true', () => {
    expect(jevSwitchedOn({ wafAiUseJev: true }, { name: 'x' })).toEqual([])
  })

  test('turning one off is never a switch-on', () => {
    expect(jevSwitchedOn({ ffufAiUseJev: true }, { ffufAiUseJev: false })).toEqual([])
  })

  test('no stored row means every true is new', () => {
    expect(jevSwitchedOn(null, { wafAiUseJev: true, takeoverAiUseJev: true }))
      .toEqual(['wafAiUseJev', 'takeoverAiUseJev'])
  })

  test('only the per-hook Jev fields count', () => {
    expect(jevSwitchedOn(null, { nucleiAiResponseFilter: true, ffufAiExtensions: true })).toEqual([])
    expect(JEV_ENGINE_FIELDS).toHaveLength(9)
  })

  test('a Jev-only hook turned on is a switch-on, like an engine switch', () => {
    expect(jevSwitchedOn(null, {
      ffufJevBasePaths: true, httpxJevPageType: true, resourceEnumJevToolHealth: true,
      hakrawlerJevSeedOrder: true, serializedScanJevRank: true,
    })).toEqual(['ffufJevBasePaths', 'httpxJevPageType', 'resourceEnumJevToolHealth', 'hakrawlerJevSeedOrder',
      'serializedScanJevRank'])
  })

  test('every Jev field has a label for the refusal message', () => {
    for (const field of JEV_ENGINE_FIELDS) {
      expect(JEV_HOOK_LABEL[field], field).toBeTruthy()
    }
  })

  test('a truthy non-boolean is not a switch-on', () => {
    expect(jevSwitchedOn(null, { ffufAiUseJev: 'true', wafAiUseJev: 1 })).toEqual([])
  })
})

describe('validateJevEngineChange', () => {
  test('no switch-on: allowed, and the database is not touched', async () => {
    expect(await validateJevEngineChange({ ffufAiUseJev: true }, { ffufAiUseJev: true, name: 'x' }, 'owner')).toBeNull()
    expect(mockCount).not.toHaveBeenCalled()
  })

  test('a stored true does not block a save when the owner lost the token (the form sends every field)', async () => {
    mockCount.mockResolvedValue(0)
    const stored = { ffufAiUseJev: true, wafAiUseJev: true }
    expect(await validateJevEngineChange(stored, { ...stored, katanaDepth: 3 }, 'owner')).toBeNull()
  })

  test('a switch-on with a token is allowed, and the lookup is for the OWNER and the jev type', async () => {
    mockCount.mockResolvedValue(1)
    expect(await validateJevEngineChange({ ffufAiUseJev: false }, { ffufAiUseJev: true }, 'owner-1')).toBeNull()
    expect(mockCount).toHaveBeenCalledWith({ where: { userId: 'owner-1', providerType: 'jev' } })
  })

  test('a switch-on without a token is refused, naming each field and where to add one', async () => {
    const error = await validateJevEngineChange(
      { ffufAiUseJev: false, wafAiUseJev: false }, { ffufAiUseJev: true, wafAiUseJev: true }, 'owner')
    expect(error).toContain('ffufAiUseJev')
    expect(error).toContain('wafAiUseJev')
    expect(error).toContain('FFuf extensions')
    expect(error).toContain('Settings → LLM Providers')
  })

  test('turning a Jev-only hook on without a token is refused the same way', async () => {
    const error = await validateJevEngineChange(
      { httpxJevPageType: false }, { httpxJevPageType: true }, 'owner')
    expect(error).toContain('httpxJevPageType (page-type labels)')
    expect(error).toContain('Settings → LLM Providers')
  })

  test('only the fields actually switched on are named', async () => {
    const error = await validateJevEngineChange(
      { ffufAiUseJev: true, wafAiUseJev: false }, { ffufAiUseJev: true, wafAiUseJev: true }, 'owner')
    expect(error).toContain('wafAiUseJev')
    expect(error).not.toContain('ffufAiUseJev')
  })

  test('FAILS CLOSED when the lookup throws', async () => {
    mockCount.mockRejectedValue(new Error('db down'))
    expect(await validateJevEngineChange(null, { ffufAiUseJev: true }, 'owner')).toBe(JEV_VERIFY_FAILED)
  })

  test('FAILS CLOSED with no owner: Prisma ignores userId:undefined and would count anyone\'s token', async () => {
    mockCount.mockResolvedValue(5)
    for (const owner of [undefined, null, '']) {
      expect(await validateJevEngineChange(null, { ffufAiUseJev: true }, owner)).toBe(JEV_VERIFY_FAILED)
    }
    expect(mockCount).not.toHaveBeenCalled()
  })
})

describe('jevImportWarnings', () => {
  test('no Jev hook, no warning, no lookup', async () => {
    expect(await jevImportWarnings({ ffufAiUseJev: false }, 'u')).toEqual([])
    expect(mockCount).not.toHaveBeenCalled()
  })

  test('hooks on Jev and no token: one warning per hook, values untouched', async () => {
    const row = { ffufAiUseJev: true, takeoverAiUseJev: true }
    const warnings = await jevImportWarnings(row, 'importer')
    expect(warnings).toHaveLength(2)
    expect(warnings[0]).toContain('ffufAiUseJev')
    expect(warnings[1]).toContain('takeoverAiUseJev')
    expect(warnings.join(' ')).toContain('static fallback')
    expect(row).toEqual({ ffufAiUseJev: true, takeoverAiUseJev: true })
  })

  test('hooks on Jev and a token: nothing to warn about', async () => {
    mockCount.mockResolvedValue(1)
    expect(await jevImportWarnings({ wafAiUseJev: true }, 'importer')).toEqual([])
  })

  test('never throws: a failed lookup becomes one warning', async () => {
    mockCount.mockRejectedValue(new Error('db down'))
    const warnings = await jevImportWarnings({ wafAiUseJev: true }, 'importer')
    expect(warnings).toHaveLength(1)
    expect(warnings[0]).toContain('could not be')
  })
})
