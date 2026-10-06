"""Regression guard for the shared stale-prune keep-clause (plan §5.6-A, §12-A).

prune_unseen_findings is shared by every recon source. Before this change it
spared only an operator mute and a human verdict; an agent-confirmed candidate
(proof-typed CONFIRMS edge) that a later run stopped reporting was DELETED,
destroying proof. The keep-clause now also spares the mute guards' terms
(triage_status='confirmed', triage_proof IS NOT NULL, a CONFIRMS edge), sourced
from node_filters/guards.py so the prune and the mute guards never drift.

Hermetic: a fake session captures the generated Cypher (the gate has no Neo4j).
It asserts the clause keeps proof AND still keeps the pre-existing mute/human
terms -- and, by rendering the query, that GUARD_KEEP_CHECK injects cleanly.
"""

import os
import sys
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from graph_db.mixins.base_mixin import BaseMixin
from graph_db.node_filters.guards import GUARD_KEEP_CHECK, GUARD_WRITE_CHECK


class _Result:
    def single(self):
        return {"pruned": 0, "stale": 0, "revived": 0}


class _FakeSession:
    def __init__(self, calls):
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        return _Result()


class _FakeDriver:
    def __init__(self):
        self.calls = []

    def session(self):
        return _FakeSession(self.calls)


class _Harness(BaseMixin):
    def __init__(self):
        self.driver = _FakeDriver()


class TestPruneKeepClause(unittest.TestCase):
    def setUp(self):
        self.h = _Harness()
        self.h.prune_unseen_findings(
            "u1", "p1", ["serialized_scan"], "2026-01-01T00:00:00+00:00")
        # the prune query is the one containing DETACH DELETE
        self.prune_q = next(q for q, _ in self.h.driver.calls if "DETACH DELETE" in q)

    def test_renders_without_error(self):
        self.assertIn("MATCH (n)", self.prune_q)

    def test_keeps_agent_proof(self):
        self.assertIn("coalesce(n.triage_status, '') = 'confirmed'", self.prune_q)
        self.assertIn("n.triage_proof IS NOT NULL", self.prune_q)
        self.assertIn("EXISTS { MATCH (:ChainFinding)-[:CONFIRMS]->(n) }", self.prune_q)

    def test_still_keeps_mute_and_human(self):
        self.assertIn("n:Muted", self.prune_q)
        self.assertIn("STARTS WITH 'rule:'", self.prune_q)
        self.assertIn("coalesce(n.triage_source, '') = 'human'", self.prune_q)

    def test_proof_kept_is_stamped_not_deleted(self):
        # kept rows are stamped stale_since; only the non-kept become `doomed`
        self.assertIn("SET n.stale_since = coalesce(n.stale_since, datetime())", self.prune_q)
        self.assertIn("FOREACH (d IN doomed | DETACH DELETE d)", self.prune_q)


class TestGuardsStayInSync(unittest.TestCase):
    """The keep terms are the positive form of the mute write-check: the same
    reasons a rule may not mute a finding are the reasons the prune must keep it."""

    def test_keep_and_write_check_cover_the_same_guards(self):
        for needle in ("triage_source", "triage_status", "triage_proof", "CONFIRMS"):
            self.assertIn(needle, GUARD_KEEP_CHECK)
            self.assertIn(needle, GUARD_WRITE_CHECK)


if __name__ == "__main__":
    unittest.main()
