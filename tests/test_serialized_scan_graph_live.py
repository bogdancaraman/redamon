"""LIVE-Neo4j: serialized_scan candidate write, prune-keep, proof gate, the
deliverable exclusion predicate, and partial-recon idempotency.

The hermetic tests only read the Cypher text / use a fake session. This runs the
real statements against a database:

  * SerializedScanMixin.update_graph_from_serialized_scan writes one candidate
    node, attaches it to an existing Endpoint AND BaseURL via HAS_VULNERABILITY,
    and accepts the flat $props (a nested prop would make Neo4j reject the node).
  * prune_unseen_findings keeps a proof-confirmed candidate (stamps stale_since)
    and deletes an unconfirmed one when a later run stops reporting it.
  * the proof fact query treats a `vulnerability_confirmed` CONFIRMS as proof and
    a `custom` one as not (G2).
  * the report/Insights pending exclusion returns a confirmed candidate and hides
    an unconfirmed one.
  * running the writer twice merges onto one node (no duplicates).

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon_redamon -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo:/repo/agentic -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_serialized_scan_graph_live.py -v

Everything it creates is scoped to a throwaway tenant and deleted in tearDown.
"""

import datetime as _dt
import os
import sys
import unittest
import uuid

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (_REPO, os.path.join(_REPO, "agentic"), os.path.join(_REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

_SKIP_REASON = None
try:
    import neo4j as _neo4j  # noqa: F401
except ImportError:
    _SKIP_REASON = "neo4j driver not installed"

_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
_USER = os.getenv("NEO4J_USER", "neo4j")
_PASSWORD = os.getenv("NEO4J_PASSWORD")
if _SKIP_REASON is None and not _PASSWORD:
    _SKIP_REASON = "NEO4J_PASSWORD not set"


def _probe():
    if _SKIP_REASON:
        return False
    try:
        drv = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))
        with drv.session() as s:
            s.run("RETURN 1").single()
        drv.close()
        return True
    except Exception:
        return False


_ALIVE = _probe()

# The report/Insights pending-candidate exclusion, mirroring graphMute.ts
# agentCandidateConfirmedOrNA('v') so this validates the Cypher semantics.
_EXCLUSION = (
    "NOT (v.source = 'serialized_scan' "
    "AND coalesce(v.needs_agent_confirmation, false) = true "
    "AND NOT EXISTS { (:ChainFinding)-[:CONFIRMS]->(v) })"
)


def _finding(**over):
    base = {
        "endpoint_url": "https://live.test/app",
        "http_method": "POST",
        "baseurl": "https://live.test",
        "path": "/app",
        "confidence": 0.85,
        "source": "serialized_scan",
        "vulnerability_type": "insecure_deserialization",
        "needs_agent_confirmation": True,
        "severity": "info",
        "deser_language": "java",
        "deser_format": "native_java",
        "deser_transport": "cookie",
        "deser_location": "set_cookie",
        "deser_encoding_layers": ["base64"],
        "deser_magic": "base64 rO0AB (AC ED 00 05)",
        "evidence_snippet": "sess=rO0ABXNy",
    }
    base.update(over)
    return base


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestSerializedScanGraphLive(unittest.TestCase):
    def setUp(self):
        run = uuid.uuid4().hex[:8]
        self.uid = f"ser-{run}"
        self.pid = f"SER_{run}"
        self.step_id = f"step-{run}"
        self.driver = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))
        with self.driver.session() as s:
            # anchors the writer's OPTIONAL MATCH attaches to, plus a ChainStep
            # for the CONFIRMS writer.
            s.run(
                """
                CREATE (:ChainStep {step_id: $step, user_id: $u, project_id: $p})
                CREATE (:BaseURL {url: 'https://live.test', user_id: $u, project_id: $p})
                CREATE (:Endpoint {path: '/app', method: 'POST', baseurl: 'https://live.test',
                                   user_id: $u, project_id: $p})
                """,
                step=self.step_id, u=self.uid, p=self.pid,
            )
        from graph_db import Neo4jClient
        self.client = Neo4jClient()

    def tearDown(self):
        try:
            self.client.close()
        except Exception:
            pass
        with self.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id = $u DETACH DELETE n", u=self.uid)
        self.driver.close()

    def _write(self, findings):
        self.client.update_graph_from_serialized_scan(
            {"serialized_scan": {"findings": findings}}, self.uid, self.pid)

    def _candidate_ids(self):
        with self.driver.session() as s:
            return [r["id"] for r in s.run(
                "MATCH (v:Vulnerability {user_id:$u, project_id:$p, source:'serialized_scan'}) "
                "RETURN v.id AS id", u=self.uid, p=self.pid)]

    def _confirm(self, vuln_id, finding_type="vulnerability_confirmed"):
        from orchestrator_helpers.chain_graph_writer import _write_finding
        _write_finding(
            _URI, _USER, _PASSWORD,
            finding_id=f"cf-{uuid.uuid4().hex[:8]}", chain_id="chain",
            step_id=self.step_id, user_id=self.uid, project_id=self.pid,
            finding_type=finding_type, severity="high", title="t", description="",
            evidence="", confidence=90, phase="exploitation", iteration=1,
            related_cves=[], related_ips=[], related_finding_ids=[vuln_id],
        )

    # -- row 2: write + attach + flat props ---------------------------------
    def test_candidate_written_and_attached_to_endpoint_and_baseurl(self):
        self._write([_finding()])
        with self.driver.session() as s:
            rec = s.run(
                """
                MATCH (v:Vulnerability {user_id:$u, project_id:$p, source:'serialized_scan'})
                OPTIONAL MATCH (e:Endpoint)-[:HAS_VULNERABILITY]->(v)
                OPTIONAL MATCH (b:BaseURL)-[:HAS_VULNERABILITY]->(v)
                RETURN count(DISTINCT v) AS vulns, count(DISTINCT e) AS eps,
                       count(DISTINCT b) AS bus,
                       collect(DISTINCT v.needs_agent_confirmation)[0] AS pend,
                       collect(DISTINCT v.deser_encoding_layers)[0] AS layers
                """, u=self.uid, p=self.pid).single()
        self.assertEqual(rec["vulns"], 1)
        self.assertEqual(rec["eps"], 1)          # attached to the Endpoint
        self.assertEqual(rec["bus"], 1)          # and the BaseURL
        self.assertTrue(rec["pend"])
        self.assertEqual(list(rec["layers"]), ["base64"])   # flat list prop stored

    # -- row 10: idempotent re-write ----------------------------------------
    def test_second_write_merges_onto_one_node(self):
        self._write([_finding()])
        self._write([_finding()])
        self.assertEqual(len(self._candidate_ids()), 1)

    # -- row 3: prune keeps proof, deletes unconfirmed ----------------------
    def test_prune_keeps_confirmed_deletes_unconfirmed(self):
        self._write([_finding(deser_location="set_cookie"),
                     _finding(deser_location="other_cookie", deser_transport="header")])
        ids = self._candidate_ids()
        self.assertEqual(len(ids), 2)
        confirmed_id = ids[0]
        self._confirm(confirmed_id)
        future = (_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(hours=1)).isoformat()
        self.client.prune_unseen_findings(self.uid, self.pid, ["serialized_scan"], future)
        with self.driver.session() as s:
            rows = {r["id"]: r["stale"] for r in s.run(
                "MATCH (v:Vulnerability {user_id:$u, project_id:$p, source:'serialized_scan'}) "
                "RETURN v.id AS id, v.stale_since IS NOT NULL AS stale",
                u=self.uid, p=self.pid)}
        self.assertIn(confirmed_id, rows)        # confirmed survived
        self.assertTrue(rows[confirmed_id])       # ... stamped stale_since
        self.assertEqual(len(rows), 1)            # unconfirmed was deleted

    # -- row 4: proof-type gate (G2) ----------------------------------------
    def test_proof_type_gate_vulnerability_confirmed_only(self):
        from cypherfix_triage.fact_queries import PROJECT_FACT_QUERIES
        proof_q = next(q for q in PROJECT_FACT_QUERIES if q["name"] == "proof")["query"]
        self._write([_finding()])
        vid = self._candidate_ids()[0]

        def proven_ids():
            with self.driver.session() as s:
                rows = list(s.run(proof_q, userId=self.uid, projectId=self.pid))
            return {i for r in rows for i in (r["finding_ids"] or []) if i}

        self._confirm(vid, finding_type="custom")
        self.assertNotIn(vid, proven_ids())      # custom does NOT prove
        self._confirm(vid, finding_type="vulnerability_confirmed")
        self.assertIn(vid, proven_ids())         # proof-typed does

    # -- row 5: deliverable exclusion predicate -----------------------------
    def test_exclusion_hides_pending_shows_confirmed(self):
        self._write([_finding(deser_location="pending_cookie"),
                     _finding(deser_location="confirmed_cookie", deser_transport="header")])
        ids = self._candidate_ids()
        confirmed_id = ids[0]
        self._confirm(confirmed_id)
        with self.driver.session() as s:
            visible = {r["id"] for r in s.run(
                f"MATCH (v:Vulnerability {{user_id:$u, project_id:$p}}) "
                f"WHERE {_EXCLUSION} RETURN v.id AS id", u=self.uid, p=self.pid)}
        self.assertIn(confirmed_id, visible)      # confirmed candidate shows
        self.assertEqual(visible, {confirmed_id}) # the pending one is hidden


if __name__ == "__main__":
    unittest.main()
