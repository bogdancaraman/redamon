import prisma from '@/lib/prisma'

/**
 * Every per-hook Jev field. The first four are engine switches on an LLM hook
 * (`true` answers it with Jev instead of the LLM); the rest switch on a Jev-only
 * hook that has no LLM twin. Either way `true` needs the owner's Jev token.
 */
export const JEV_ENGINE_FIELDS = [
  'ffufAiUseJev',
  'nucleiTagsAiUseJev',
  'wafAiUseJev',
  'takeoverAiUseJev',
  'ffufJevBasePaths',
  'httpxJevPageType',
  'resourceEnumJevToolHealth',
  'hakrawlerJevSeedOrder',
  'serializedScanJevRank',
] as const

export type JevEngineField = typeof JEV_ENGINE_FIELDS[number]

export const JEV_HOOK_LABEL: Record<JevEngineField, string> = {
  ffufAiUseJev: 'FFuf extensions',
  nucleiTagsAiUseJev: 'Nuclei tag selection',
  wafAiUseJev: 'WAF classification',
  takeoverAiUseJev: 'takeover disambiguation',
  ffufJevBasePaths: 'FFuf base-path ranking',
  httpxJevPageType: 'page-type labels',
  resourceEnumJevToolHealth: 'silent tool-failure check',
  hakrawlerJevSeedOrder: 'Hakrawler seed order',
  serializedScanJevRank: 'serialized-scan ranking',
}

export const JEV_VERIFY_FAILED = "Couldn't verify your Jev token, try again."

type Row = Record<string, unknown> | null | undefined

/** The engine fields a write turns ON: true in `next`, not already true in `before`. */
export function jevSwitchedOn(before: Row, next: Row): JevEngineField[] {
  return JEV_ENGINE_FIELDS.filter(k => next?.[k] === true && before?.[k] !== true)
}

/**
 * Refuses a write that switches a hook onto Jev (an engine switch to Jev, or a
 * Jev-only hook turned on) when the project owner has no Jev token. Returns the error message, or null when the write may proceed.
 *
 * It refuses only a SWITCH-ON, never "any true value": the project form sends
 * every field on every save, so a rule over "any true" would block every save of
 * a project whose owner later deleted the token, including saves that touch
 * nothing to do with Jev. A stored true is left alone; at scan time the hook
 * falls back to its static list.
 *
 * `ownerUserId` is the project's owner, not the acting user: recon resolves
 * credentials from the owner.
 *
 * Fails closed. A lookup that throws, or a missing owner, is a refusal; the
 * missing-owner case matters because Prisma ignores `userId: undefined` in a
 * `where`, which would count every user's Jev row and wrongly allow the write.
 */
export async function validateJevEngineChange(
  before: Row,
  next: Row,
  ownerUserId: string | null | undefined,
): Promise<string | null> {
  const on = jevSwitchedOn(before, next)
  if (on.length === 0) return null
  if (!ownerUserId) return JEV_VERIFY_FAILED

  let tokens: number
  try {
    tokens = await prisma.userLlmProvider.count({
      where: { userId: ownerUserId, providerType: 'jev' },
    })
  } catch {
    return JEV_VERIFY_FAILED
  }
  if (tokens > 0) return null

  const named = on.map(k => `${k} (${JEV_HOOK_LABEL[k]})`).join(', ')
  return `Can't use Jev for ${named}: the project owner has no TypeSafe AI (Jev) token. Add one in Settings → LLM Providers.`
}

/**
 * Warnings for an imported project that arrives with hooks set to Jev. Import
 * keeps the bundle's values, because refusing would make a bundle exported from
 * an account with a token unimportable anywhere else; the warning names each
 * hook that will use its static fallback until the importer adds a token.
 *
 * Never throws: a warning must not fail an import that already succeeded.
 */
export async function jevImportWarnings(row: Row, importerUserId: string | null | undefined): Promise<string[]> {
  const on = JEV_ENGINE_FIELDS.filter(k => row?.[k] === true)
  if (on.length === 0 || !importerUserId) return []

  let tokens: number
  try {
    tokens = await prisma.userLlmProvider.count({ where: { userId: importerUserId, providerType: 'jev' } })
  } catch {
    return [
      `${on.map(k => JEV_HOOK_LABEL[k]).join(', ')}: set to use Jev, and your Jev token could not be ` +
      'checked. A hook with no token uses its static fallback.',
    ]
  }
  if (tokens > 0) return []
  return on.map(k =>
    `${k} (${JEV_HOOK_LABEL[k]}) is set to use Jev, but your account has no TypeSafe AI (Jev) token: ` +
    'this hook uses its static fallback until you add one in Settings → LLM Providers.')
}
