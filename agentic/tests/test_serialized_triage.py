"""Serialized-object candidate triage behaviour (plan §10, §14, G2).

Two layers guard the Detect->Confirm lifecycle:

  score layer   an info candidate sits at the T4 floor until it is proven, and a
                proof-typed CONFIRMS edge (reflected as proven_finding_ids)
                promotes it straight to T1.
  G2 fact layer only a ChainFinding whose finding_type is in the proof set makes
                a candidate proven. A finding_type='custom' CONFIRMS edge (the
                fire_record_finding default) lands and makes the node un-hideable
                but NEVER promotes; 'vulnerability_confirmed' does. This is the
                single most load-bearing fix in the integration.
"""

import unittest

import agentic.cypherfix_triage.score_model as sm
from agentic.cypherfix_triage import fact_queries


def _candidate(**over):
    base = {
        "id": "ser1", "label": "Vulnerability", "source": "serialized_scan",
        "severity": "info", "host": "h1", "needs_agent_confirmation": True,
        "type": "insecure_deserialization",
    }
    base.update(over)
    return base


class TestSerializedCandidateTiering(unittest.TestCase):
    def test_confidence_row_is_low(self):
        self.assertEqual(sm.CONFIDENCE_BY_SOURCE["serialized_scan"], 0.4)

    def test_unproven_info_candidate_lands_in_track(self):
        result = sm.score(_candidate(), sm.ProjectFacts(live_hosts={"h1"}))
        self.assertEqual(result.tier, "T4")

    def test_proof_typed_confirms_promotes_to_act_now(self):
        # proven_finding_ids is populated ONLY by the proof fact query (below),
        # i.e. a proof-typed CONFIRMS edge. Simulating it here proves the scoring
        # half short-circuits to T1 before the info gate.
        facts = sm.ProjectFacts(proven_finding_ids={"ser1"})
        result = sm.score(_candidate(), facts)
        self.assertEqual(result.tier, "T1")

    def test_a_bare_info_candidate_is_not_proven_without_the_edge(self):
        self.assertFalse(sm.is_proven(_candidate(), sm.ProjectFacts()))


class TestProofTypeGate(unittest.TestCase):
    """G2: the proof fact query gates promotion on finding_type, not the edge."""

    def _proof_query(self):
        rows = [q for q in fact_queries.PROJECT_FACT_QUERIES if q["name"] == "proof"]
        self.assertEqual(len(rows), 1)
        return rows[0]["query"]

    def test_vulnerability_confirmed_counts_as_proof(self):
        self.assertIn("vulnerability_confirmed", self._proof_query())

    def test_custom_finding_type_does_not_count_as_proof(self):
        q = self._proof_query()
        # the finding_type filter is a closed list; 'custom' (the
        # fire_record_finding default) must not appear in it
        self.assertNotIn("'custom'", q)
        self.assertIn("cf.finding_type IN", q)


if __name__ == "__main__":
    unittest.main()
