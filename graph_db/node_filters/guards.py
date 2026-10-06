"""What stops a rule muting a finding, projected once and re-checked on write.

Guards only ever BLOCK muting. A guarded node's target state is "not
rule-muted", so a finding that became guarded while a rule had it muted (a
person judged it, the agent proved it) is released at the next sweep instead
of staying hidden for good. `set_human_verdict` and the agent's CONFIRMS
writer both match muted nodes, so that can happen.

A person releases `g_human` with Reset: `set_human_verdict(..., 'unreviewed')`
removes `triage_source`, so a reset finding may be rule-muted like any other.

An operator's own mute is a separate case: it is neither muted nor unmuted by a
rule, ever. That is decided from `muted` / `muted_by`, not here.
"""
from __future__ import annotations

#: Projected with every row. Kept as columns rather than one boolean so the
#: preview can say WHY a node was kept.
GUARD_COLUMNS = """coalesce(n.triage_source, '') = 'human' AS g_human,
       (coalesce(n.triage_status, '') = 'confirmed' OR n.triage_proof IS NOT NULL) AS g_confirmed,
       EXISTS { MATCH (:ChainFinding)-[:CONFIRMS]->(n) } AS g_chain"""

#: The same guards, re-checked inside the mute write: a verdict set between the
#: read and the write must never be hidden by it.
GUARD_WRITE_CHECK = """coalesce(n.triage_source, '') <> 'human'
  AND coalesce(n.triage_status, '') <> 'confirmed'
  AND n.triage_proof IS NULL
  AND NOT EXISTS { MATCH (:ChainFinding)-[:CONFIRMS]->(n) }"""

#: The positive form of GUARD_WRITE_CHECK: a finding the stale-prune must KEEP
#: (stamp stale_since, never DELETE) because a person judged it or the agent
#: proved it. The same reasons a rule may not mute it apply here: deleting an
#: agent-confirmed finding because a later run stopped reporting it would destroy
#: proof. Used by base_mixin.prune_unseen_findings.
GUARD_KEEP_CHECK = """coalesce(n.triage_source, '') = 'human'
  OR coalesce(n.triage_status, '') = 'confirmed'
  OR n.triage_proof IS NOT NULL
  OR EXISTS { MATCH (:ChainFinding)-[:CONFIRMS]->(n) }"""

GUARD_KEYS = ("g_human", "g_confirmed", "g_chain")


def guard_reasons(row) -> list:
    """Which guards hold for a projected row: human, confirmed, chain."""
    return [key[2:] for key in GUARD_KEYS if row.get(key)]


def is_guarded(row) -> bool:
    return any(row.get(key) for key in GUARD_KEYS)
