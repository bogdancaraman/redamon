/**
 * The Mute Rules exemptions an unmute records, shared by the Muted Nodes route
 * and MCP `unmute_findings`.
 *
 * An exemption is what makes an unmute stick: no rule mutes that finding again
 * until a person clears it on the Mute Rules page. It is a Postgres row keyed on
 * (project, label, natural key), because the prune, the recon asset clear,
 * version activation and import would each delete a graph property.
 *
 * The two callers use these in opposite orders, on purpose. The UI unmutes the
 * graph first and reports an exemption that failed (the person can see the
 * finding and act). MCP writes the exemptions FIRST, so a lost response cannot
 * leave a rule-muted finding unmuted with nothing stopping the next sweep from
 * hiding it again; that is why `ensureExemptions` reports exactly the rows IT
 * created, so a rolled-back unmute removes those and never someone else's.
 */
import prisma from '@/lib/prisma'
import { writeAudit } from '@/lib/audit'

export interface ExemptionPair {
  label: string
  key: string
}

function uniquePairs(pairs: ExemptionPair[]): ExemptionPair[] {
  const seen = new Set<string>()
  const out: ExemptionPair[] = []
  for (const p of pairs) {
    if (!p?.label || !p?.key) continue
    const id = `${p.label}\u0000${p.key}`
    if (seen.has(id)) continue
    seen.add(id)
    out.push({ label: p.label, key: p.key })
  }
  return out
}

/**
 * Exempt every pair, creating only the missing rows.
 *
 * `created` is exactly what this call inserted (Postgres reports it, so a row a
 * concurrent unmute created is never claimed); `total` is how many of the pairs
 * are now exempt. Throws on a database error: the caller decides what that means.
 */
export async function ensureExemptions(
  projectId: string,
  pairs: ExemptionPair[],
  actor: { createdBy: string; realActorUserId: string | null }
): Promise<{ created: ExemptionPair[]; total: number }> {
  const wanted = uniquePairs(pairs)
  if (wanted.length === 0) return { created: [], total: 0 }
  const rows = await prisma.nodeFilterExemption.createManyAndReturn({
    data: wanted.map(p => ({
      projectId,
      label: p.label,
      nodeKey: p.key,
      createdBy: actor.createdBy,
      realActorUserId: actor.realActorUserId,
    })),
    skipDuplicates: true,
    select: { label: true, nodeKey: true },
  })
  return { created: rows.map(r => ({ label: r.label, key: r.nodeKey })), total: wanted.length }
}

/**
 * Remove exemptions this caller created, when the unmute they were for did not
 * happen. Never throws: a leftover exemption on a still-muted finding means the
 * next sweep releases a rule's mute on it, which is logged loudly here.
 */
export async function removeExemptions(projectId: string, created: ExemptionPair[]): Promise<boolean> {
  const pairs = uniquePairs(created)
  if (pairs.length === 0) return true
  try {
    await prisma.nodeFilterExemption.deleteMany({
      where: { projectId, OR: pairs.map(p => ({ label: p.label, nodeKey: p.key })) },
    })
    return true
  } catch (err) {
    console.error(
      `[unmute] could not remove ${pairs.length} exemption(s) for an unmute that did not happen; ` +
        'the next Mute Rules sweep will release any rule mute on those findings:', err)
    return false
  }
}

export interface UnmuteAuditItem {
  key: string
  label: string
  mutedBy?: string
  wasMutedVia?: string | null
}

/**
 * The `muted_nodes.unmuted` audit row. Keys and what had muted each (rule ids
 * and user ids), never finding text. `outcome: 'unknown'` records an MCP unmute
 * whose answer was lost.
 */
export async function auditUnmute(entry: {
  actorId: string
  projectId: string
  source: 'ui' | 'mcp' | 'multi_undo'
  realActorUserId: string | null
  items: UnmuteAuditItem[]
  exempted: number
  /** A Multi mute Undo: the batch it reverted. */
  batchId?: string
  tokenId?: string
  tokenPrefix?: string
  outcome?: 'ok' | 'unknown'
  requested?: { findingIds: string[]; nodeIds: string[]; count?: number }
}): Promise<void> {
  await writeAudit({
    actorId: entry.actorId,
    action: 'muted_nodes.unmuted',
    targetType: 'project',
    targetId: entry.projectId,
    after: {
      realActorUserId: entry.realActorUserId,
      count: entry.items.length,
      exempted: entry.exempted,
      items: entry.items.slice(0, 100),
      ...(entry.tokenId ? { tokenId: entry.tokenId, tokenPrefix: entry.tokenPrefix } : {}),
      ...(entry.outcome ? { outcome: entry.outcome } : {}),
      ...(entry.requested ? { requested: entry.requested } : {}),
      ...(entry.batchId ? { batchId: entry.batchId } : {}),
    },
    source: entry.source,
  })
}
