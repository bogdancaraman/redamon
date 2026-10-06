/**
 * The server-side preset library: what a stored preset may hold, how a stored
 * blob is read, and applying a preset exactly as the project form does.
 *
 * The property the whole module rests on is PARITY: MCP apply must write what
 * the form's "Load preset" writes, or a preset means two different things
 * depending on which door applied it.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

const mockPresetFind = vi.fn()
const mockUserSettings = vi.fn()
const mockOrchestratorFetch = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    userProjectPreset: { findFirst: (...a: unknown[]) => mockPresetFind(...a) },
    userSettings: { findUnique: (...a: unknown[]) => mockUserSettings(...a) },
  },
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => mockOrchestratorFetch(...a) }))

import { RECON_PRESETS } from '@/lib/recon-presets'
import { MINIMAL_DEFAULTS } from '@/components/projects/ProjectForm/formDefaults'
import {
  PRESET_FIELD_KEYS,
  appliedPresetName,
  applyPresetSettings,
  extractPresetSettings,
  pickPresetFields,
  presetFingerprint,
} from '@/lib/project-preset-utils'
import { field, fieldsWhere, prismaDefaults } from '@/lib/reconSettings/registry'
import { validateValue } from '@/lib/reconSettings/validators'
import {
  DefaultsUnavailable,
  PRESET_MAX_BYTES,
  computePresetApplication,
  fetchBackendDefaults,
  presetSettingsForStorage,
  projectPresetForRead,
  resolvePreset,
  sanitizePresetText,
  validateApplication,
  validatePresetSettings,
} from './server'

/** A full project row at its defaults, as a freshly created project holds it. */
const baseRow = (): Record<string, unknown> => ({
  ...extractPresetSettings({}),
  mcpKaliExecEnabled: false,
  updateGraphDb: true,
  targetDomain: 'lab.example.com',
})

const DEFAULTS = { katanaDepth: 2, fireteamTimeoutSec: 3600 }

beforeEach(() => {
  vi.clearAllMocks()
  mockUserSettings.mockResolvedValue(null)
})

afterEach(() => {
  vi.unstubAllGlobals()
})

// --- validatePresetSettings -------------------------------------------------------------

describe('validatePresetSettings refuses what a preset may not hold', () => {
  const refused = (settings: Record<string, unknown>) => {
    const r = validatePresetSettings(settings)
    expect(r.ok).toBe(false)
    return r as { ok: false; key: string; error: string }
  }

  test('each excluded class is refused by name, with the tool that owns it', () => {
    expect(refused({ targetDomain: 'x.example.com' }).error).toMatch(/engagement scope.*create_project/)
    expect(refused({ roeGlobalMaxRps: 3 }).error).toMatch(/one engagement.*update_recon_settings/)
    expect(refused({ roeClientName: 'Acme' }).error).toMatch(/not configuration/)
    expect(refused({ graphqlAuthValue: 'token' }).error).toMatch(/credential/)
    expect(refused({ jsReconUploadedFiles: [] }).error).toMatch(/uploaded file/)
    expect(refused({ mcpKaliExecEnabled: true }).error).toMatch(/not configuration/)
    expect(refused({ updateGraphDb: false }).error).toMatch(/not configuration/)
    expect(refused({ id: 'p1' }).error).toMatch(/not configuration/)
    expect(refused({ vhostSniCustomWordlist: 'admin' }).error).toMatch(/tied to one project/)
  })

  test('an unknown key is refused, naming the key', () => {
    const r = refused({ notASetting: 1 })
    expect(r.key).toBe('notASetting')
    expect(r.error).toMatch(/not a recon setting/)
  })

  test('a value outside its bound is refused, naming the bound', () => {
    expect(refused({ katanaDepth: 999 }).error).toMatch(/between/)
    expect(refused({ naabuEnabled: 'yes' }).error).toMatch(/true or false/)
  })

  test('reconPresetId may only be null or a built-in preset', () => {
    expect(validatePresetSettings({ reconPresetId: 'stealth-recon' }).ok).toBe(true)
    expect(validatePresetSettings({ reconPresetId: null }).ok).toBe(true)
    expect(refused({ reconPresetId: 'made-up' }).error).toMatch(/built-in/)
  })

  test('a project_file path is refused without a project: a preset outlives the project', () => {
    // Inside a project's own upload directory is valid on that project only.
    const r = validatePresetSettings({ ffufWordlist: '/app/recon/wordlists/proj-a/mine.txt' })
    expect(r.ok).toBe(false)
    // A shipped list is valid anywhere.
    expect(validatePresetSettings({ ffufWordlist: '/usr/share/seclists/Discovery/Web-Content/common.txt' }).ok).toBe(true)
  })

  test('null is a value on a nullable column, not a type error', () => {
    expect(validatePresetSettings({ agentLport: null }).ok).toBe(true)
  })

  test('the key and byte caps bound one preset', () => {
    expect(refused({}).error).toMatch(/at least one/)
    const tooMany = Object.fromEntries(Array.from({ length: PRESET_FIELD_KEYS.length + 1 }, (_, i) => [`k${i}`, 1]))
    expect(refused(tooMany).error).toMatch(/at most/)
    expect(refused({ nucleiCustomTemplates: 'x'.repeat(PRESET_MAX_BYTES + 1) } as never).error).toMatch(/KiB/)
  })

  test('every built-in preset passes, so copying one never fails', () => {
    const problems = RECON_PRESETS
      .map(p => [p.id, validatePresetSettings({ ...p.parameters, reconPresetId: p.id })] as const)
      .filter(([, r]) => !r.ok)
      .map(([id, r]) => `${id}: ${(r as { error: string }).error}`)
    expect(problems).toEqual([])
  })
})

describe('sanitizePresetText', () => {
  test('a name loses its control characters and is capped', () => {
    expect(sanitizePresetText('  evil\n[audit] x\u0007  ', 120)).toBe('evil[audit] x')
    expect(sanitizePresetText('a'.repeat(200), 120)).toHaveLength(120)
    expect(sanitizePresetText(42, 120)).toBe('')
  })

  test('a description keeps its line breaks', () => {
    expect(sanitizePresetText('line one\nline two\u0000', 2000, { multiline: true })).toBe('line one\nline two')
  })
})

// --- reading stored presets ---------------------------------------------------------------

describe('projectPresetForRead never returns a stored blob verbatim', () => {
  test('a crafted blob yields only preset fields', () => {
    const { settings, ignoredKeys } = projectPresetForRead({
      katanaDepth: 3,
      graphqlAuthValue: 'Bearer leaked',
      targetDomain: 'victim.example.com',
      roeClientName: 'Acme',
      junk: { nested: true },
    })
    expect(settings).toEqual({ katanaDepth: 3 })
    expect(ignoredKeys.sort()).toEqual(['graphqlAuthValue', 'junk', 'roeClientName', 'targetDomain'])
  })

  test('a non-object reads as empty', () => {
    expect(projectPresetForRead('x')).toEqual({ settings: {}, ignoredKeys: [] })
    expect(projectPresetForRead(null)).toEqual({ settings: {}, ignoredKeys: [] })
    expect(projectPresetForRead([1])).toEqual({ settings: {}, ignoredKeys: [] })
  })

  test('storage from the UI and an import keeps only preset fields, and bounds the size', () => {
    const r = presetSettingsForStorage({ katanaDepth: 3, targetDomain: 'x', cypherfixGithubToken: 'ghp_x' })
    expect(r).toEqual({ ok: true, settings: { katanaDepth: 3 }, dropped: 2 })
    expect(presetSettingsForStorage({ nucleiCustomTemplates: 'x'.repeat(PRESET_MAX_BYTES + 1) } as never).ok)
      .toBe(false)
    expect(presetSettingsForStorage('x').ok).toBe(false)
  })
})

describe('resolvePreset', () => {
  test('a built-in resolves to its parameters plus the badge id, without the database', async () => {
    const r = await resolvePreset('u1', 'stealth-recon')
    expect(r?.source).toBe('builtin')
    expect(r?.settings.reconPresetId).toBe('stealth-recon')
    expect(mockPresetFind).not.toHaveBeenCalled()
  })

  test('a user preset is looked up by id AND owner, so another user\'s reads as missing', async () => {
    mockPresetFind.mockResolvedValue(null)
    expect(await resolvePreset('u1', 'someone-elses')).toBeNull()
    expect(mockPresetFind.mock.calls[0][0].where).toEqual({ id: 'someone-elses', userId: 'u1' })
  })

  test('a stored preset is projected on the way out', async () => {
    mockPresetFind.mockResolvedValue({
      id: 'p1', name: 'mine', description: '', updatedAt: new Date(), createdVia: 'ui', updatedVia: 'ui',
      lastWriterTokenPrefix: null, settings: { katanaDepth: 3, targetDomain: 'x.example.com' },
    })
    const r = await resolvePreset('u1', 'p1')
    expect(r?.settings).toEqual({ katanaDepth: 3 })
  })

  test('a database error throws: "could not look" is never "not there"', async () => {
    mockPresetFind.mockRejectedValue(new Error('db down'))
    await expect(resolvePreset('u1', 'p1')).rejects.toThrow('db down')
  })
})

// --- applying ---------------------------------------------------------------------------------

const X = { name: 'x', id: 'up-x', source: 'user' } as const

describe('computePresetApplication is the form\'s preset load', () => {
  test('parity: for every built-in, the data equals the form\'s save body', () => {
    for (const p of RECON_PRESETS) {
      const settings = { ...p.parameters, reconPresetId: p.id } as Record<string, unknown>
      const row = baseRow()
      const app = computePresetApplication(row, settings, DEFAULTS, { name: p.name, id: p.id, source: 'builtin' })
      expect(app.data, p.id).toEqual(pickPresetFields(applyPresetSettings(row, settings, DEFAULTS)))
      expect(app.loadedPreset.fingerprint, p.id)
        .toBe(presetFingerprint(applyPresetSettings(row, settings, DEFAULTS)))
    }
  })

  test('the badge an apply writes shows in the settings form that loads the row', () => {
    // The server fingerprints the row it writes; the form fingerprints the state
    // it builds from that row after the API's JSON round trip. Any gap between
    // the two hides the badge on every MCP apply.
    const settings = {
      katanaDepth: 5, naabuEnabled: false, arjunMethods: ['POST'],
      agentToolPhaseMap: { b: ['x'], a: ['y'] },
    }
    const row = baseRow()
    const app = computePresetApplication(row, settings, DEFAULTS, { name: 'Mine', id: 'up1', source: 'user' })
    const served = JSON.parse(JSON.stringify({ ...row, ...app.data, loadedPreset: app.loadedPreset }))
    expect(appliedPresetName({ ...MINIMAL_DEFAULTS, ...served })).toBe('Mine')
  })

  test('C-10: the badge names the preset by id and source, so a rename or delete can find it', () => {
    const app = computePresetApplication(baseRow(), { naabuEnabled: true }, DEFAULTS, { name: 'Mine', id: 'up1', source: 'user' })
    expect(app.loadedPreset).toMatchObject({ name: 'Mine', presetId: 'up1', source: 'user' })
  })

  test('it reports what changes, what only resets, and what a replace keeps', () => {
    const row = { ...baseRow(), katanaDepth: 9, naabuEnabled: false, agentOpenaiModel: 'mine' }
    const app = computePresetApplication(row, { naabuEnabled: true }, DEFAULTS, X)
    expect(app.changed).toContain('naabuEnabled')
    expect(app.changed).toContain('katanaDepth')
    expect(app.resetToDefault).toContain('katanaDepth')
    expect(app.resetToDefault).not.toContain('naabuEnabled')
    expect(app.keptAsIs).toEqual([
      'agentOpenaiModel', 'aiPipelineModel',
      'ffufAiUseJev', 'ffufJevBasePaths', 'hakrawlerJevSeedOrder', 'httpxJevPageType',
      'nucleiTagsAiUseJev', 'resourceEnumJevToolHealth', 'serializedScanJevRank', 'takeoverAiUseJev',
      'wafAiUseJev',
    ])
    expect(app.data.agentOpenaiModel).toBe('mine')
    expect(app.unchangedCount).toBe(PRESET_FIELD_KEYS.length - app.changed.length)
  })

  test('C-1: the MCP sandbox switch and graph writes are never part of it', () => {
    const app = computePresetApplication(baseRow(), { naabuEnabled: true }, { mcpKaliExecEnabled: true }, X)
    expect(app.data).not.toHaveProperty('mcpKaliExecEnabled')
    expect(app.data).not.toHaveProperty('updateGraphDb')
  })
})

describe('validateApplication', () => {
  test('only CHANGED values are judged', async () => {
    // The row already holds a value a later bound refuses. Re-judging it would
    // lock the project out of every preset.
    const row = { ...baseRow(), katanaDepth: 999 }
    const ok = await validateApplication({ data: { ...row }, changed: ['naabuEnabled'] }, row, 'p1', 'u1')
    expect(ok).toBeNull()
  })

  test('a default that breaks its bound refuses the whole apply, naming the key', async () => {
    const row = baseRow()
    const app = computePresetApplication(row, {}, { katanaDepth: 999 }, X)
    const problem = await validateApplication(app, row, 'p1', 'u1')
    expect(problem?.key).toBe('katanaDepth')
  })

  test('a project_file path into THIS project\'s upload directory is valid here', async () => {
    const row = baseRow()
    const data = { ...row, ffufWordlist: '/app/recon/wordlists/p1/mine.txt' }
    expect(await validateApplication({ data, changed: ['ffufWordlist'] }, row, 'p1', 'u1')).toBeNull()
    expect(await validateApplication({ data, changed: ['ffufWordlist'] }, row, 'p2', 'u1')).not.toBeNull()
  })

  test('the fireteam cross-field rule fires on the merged row', async () => {
    const row = { ...baseRow(), fireteamMaxMembers: 3 }
    const data = { ...row, fireteamMaxConcurrent: 6 }
    const problem = await validateApplication({ data, changed: ['fireteamMaxConcurrent'] }, row, 'p1', 'u1')
    expect(problem?.error).toMatch(/cannot exceed fireteamMaxMembers/)
  })

  test('the supply-chain rule fires, reading the host allowlist from the actor', async () => {
    // A value the registry accepts (free text) and only the cross-field rule
    // refuses: a repository on a host nobody registered.
    const row = baseRow()
    const data = { ...row, supplyChainRepoUrl: 'https://git.example.com/acme/app' }
    const problem = await validateApplication({ data, changed: ['supplyChainRepoUrl'] }, row, 'p1', 'u1')
    expect(problem?.error).toMatch(/Repository must be a repo on github\.com/)
    expect(mockUserSettings.mock.calls[0][0].where).toEqual({ userId: 'u1' })
  })
})

describe('fetchBackendDefaults fails closed', () => {
  test('both halves, merged, the agent winning', async () => {
    mockOrchestratorFetch.mockResolvedValue({ ok: true, json: async () => ({ katanaDepth: 2, shared: 'recon' }) })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => ({ shared: 'agent' }) }))
    expect(await fetchBackendDefaults()).toEqual({ katanaDepth: 2, shared: 'agent' })
  })

  test('either half failing throws DefaultsUnavailable', async () => {
    mockOrchestratorFetch.mockResolvedValue({ ok: true, json: async () => ({}) })
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('timeout')))
    await expect(fetchBackendDefaults()).rejects.toBeInstanceOf(DefaultsUnavailable)

    mockOrchestratorFetch.mockResolvedValue({ ok: false, status: 503, json: async () => ({}) })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) }))
    await expect(fetchBackendDefaults()).rejects.toBeInstanceOf(DefaultsUnavailable)
  })

  test('each request carries a timeout, so a hung backend cannot hold a call forever', async () => {
    mockOrchestratorFetch.mockResolvedValue({ ok: true, json: async () => ({}) })
    const agentFetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) })
    vi.stubGlobal('fetch', agentFetch)
    await fetchBackendDefaults()
    expect(mockOrchestratorFetch.mock.calls[0][1].signal).toBeInstanceOf(AbortSignal)
    expect(agentFetch.mock.calls[0][1].signal).toBeInstanceOf(AbortSignal)
  })
})

// --- the defaults every apply resets to -----------------------------------------------------

describe('every Prisma default passes its own registry validator', () => {
  // A preset resets every unnamed field to its default, and apply judges what
  // it writes. One default outside its own bound would refuse EVERY apply.
  test('for every preset field', () => {
    const defaults = prismaDefaults()
    const problems: string[] = []
    for (const key of PRESET_FIELD_KEYS) {
      if (!Object.prototype.hasOwnProperty.call(defaults, key)) continue
      const spec = field(key)!
      let value = defaults[key]
      if (spec.type === 'json' && typeof value === 'string') value = JSON.parse(value)
      if (key === 'reconPresetId' || (value === null && spec.optional)) continue
      const problem = validateValue(key, spec, value)
      if (problem) problems.push(`${key}=${JSON.stringify(value)}: ${problem}`)
    }
    expect(problems).toEqual([])
  })

  test('and every settable field, which an MCP write judges the same way', () => {
    const defaults = prismaDefaults()
    const problems: string[] = []
    for (const f of fieldsWhere(s => s.mcp === 'settable')) {
      if (!Object.prototype.hasOwnProperty.call(defaults, f.key)) continue
      let value = defaults[f.key]
      if (f.type === 'json' && typeof value === 'string') value = JSON.parse(value)
      if (value === null && f.optional) continue
      const problem = validateValue(f.key, f, value)
      if (problem) problems.push(`${f.key}=${JSON.stringify(value)}: ${problem}`)
    }
    expect(problems).toEqual([])
  })
})
