"""LIVE-Neo4j proof of the false-positive-reduction graph writes.

The unit tests drive the writers through a fake session; only a real database
proves the Cypher is valid on Neo4j 5.x, that every new property is a scalar
or a list of scalars (a map fails the whole node write), and that a re-run
refreshes rather than duplicates:

  * Shodan passive CVEs carry their evidence grade, port, product, version and
    a CVSS-derived severity, refresh on a re-run, keep their evidence through a
    worse-informed run, keep the IP as the board's host, and the Priority
    Board's own fact query + score model read the grade;
  * JS Recon source-map, DOM-sink and developer-reference findings carry their
    new fields and stay linked to their JS file node.

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo:/repo/agentic -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_recon_fp_writers_graph_live.py -v

Everything is scoped to a throwaway project id and DETACH DELETEd in teardown.
"""

import os
import sys
import unittest
import uuid

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (_REPO, os.path.join(_REPO, "agentic")):
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

IP = "45.33.32.40"
BANNER_CVE = "CVE-2021-23017"
CATALOG_CVE = "CVE-2019-11043"


def _shodan_payload(cvss=7.7, product="nginx"):
    return {
        "domain": "fp-itest.test", "domains": ["fp-itest.test"],
        "shodan": {
            "hosts": [{
                "ip": IP, "org": "Example Hosting Ltd", "isp": "Example Hosting Ltd", "os": None,
                "country_name": "Ireland", "city": "Dublin", "ports": [443], "vulns": [BANNER_CVE, CATALOG_CVE],
                "services": [{"port": 443, "transport": "tcp", "product": product, "version": "1.18.0",
                              "banner": "HTTP/1.1 200 OK", "module": "https",
                              "vulns": [{"cve_id": BANNER_CVE, "cvss": cvss, "verified": False}]}],
                "source": "shodan_api",
            }],
            "cves": [
                {"cve_id": BANNER_CVE, "ip": IP, "source": "shodan_api", "port": 443, "product": product,
                 "version": "1.18.0", "cvss": cvss, "verified": False,
                 "detection_method": "passive_version_match"},
                {"cve_id": CATALOG_CVE, "ip": IP, "source": "shodan_api", "port": None, "product": None,
                 "version": None, "cvss": None, "verified": False, "detection_method": "passive_catalog"},
            ],
        },
    }


def _js_payload():
    js = "https://app.fp-itest.test/static/js/main.js"
    return {
        "domain": "fp-itest.test", "domains": ["fp-itest.test"],
        "js_recon": {
            "scan_metadata": {"scan_timestamp": "2026-10-08T00:00:00Z"},
            "dom_sinks": [{
                "id": "itest-sink-1", "finding_type": "dom_sink", "type": "innerHTML",
                "pattern": "…out.innerHTML=location.hash…", "description": "Direct HTML injection (src)",
                "source_url": js, "line": 1, "column": 42, "severity": "high", "confidence": "medium",
                "nominal_severity": "high", "user_source": "location.hash", "vendor": False, "third_party": False,
            }],
            "source_maps": [
                {"id": "itest-map-1", "finding_type": "source_map_exposure", "severity": "high", "js_url": js,
                 "map_url": js + ".map", "accessible": True, "discovery_method": "comment", "files_count": 3,
                 "first_party_files": 2, "has_sources_content": True, "source_files": ["src/App.tsx", "src/api.ts"],
                 "secrets_in_source": 0, "secrets": []},
                {"id": "itest-map-2", "finding_type": "source_map_reference", "severity": "info", "js_url": js,
                 "map_url": js.replace("main", "vendor") + ".map", "accessible": False, "fetch_result": "http_403",
                 "discovery_method": "comment", "files_count": 0, "source_files": [], "secrets_in_source": 0,
                 "secrets": []},
            ],
            "dev_references": [{
                "id": "itest-ref-1", "type": "Localhost with Port", "value": "localhost:8080",
                "source_url": js, "line_number": 7, "context": 'const api = "http://localhost:8080/api";',
            }],
        },
    }


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestReconFpWritersGraphLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)
        cls.user = "fp-itest-user"

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        # One project per test: the evidence grade only rises, so a project
        # shared across tests would carry one test's grade into the next.
        self.pid = "fp-itest-%s" % uuid.uuid4().hex[:10]

    def tearDown(self):
        with self.client.driver.session() as s:
            s.run("MATCH (n) WHERE n.project_id = $pid DETACH DELETE n", pid=self.pid)

    def _one(self, cypher, **params):
        with self.client.driver.session() as s:
            return s.run(cypher, pid=self.pid, **params).single()

    def _vuln(self, cve):
        rec = self._one("MATCH (v:Vulnerability {id: $id, project_id: $pid}) RETURN properties(v) AS p",
                        id=f"shodan-{cve}-{IP}")
        return rec["p"] if rec else None

    # -- Shodan --------------------------------------------------------------
    def test_shodan_cves_carry_their_grade(self):
        self.client.update_graph_from_shodan(_shodan_payload(), self.user, self.pid)

        banner = self._vuln(BANNER_CVE)
        self.assertEqual(banner["detection_method"], "passive_version_match")
        self.assertEqual((banner["target_port"], banner["product"], banner["version"]), (443, "nginx", "1.18.0"))
        self.assertEqual((banner["cvss_score"], banner["severity"], banner["verified"]), (7.7, "high", False))
        self.assertEqual(banner["source"], "shodan_api")
        catalog = self._vuln(CATALOG_CVE)
        self.assertEqual(catalog["detection_method"], "passive_catalog")
        self.assertNotIn("severity", catalog)
        self.assertNotIn("product", catalog)

        self.assertEqual(self._one(
            "MATCH (parent)-[:HAS_VULNERABILITY]->(v:Vulnerability {id: $id}) RETURN count(parent) AS c",
            id=f"shodan-{BANNER_CVE}-{IP}")["c"], 1)
        self.assertEqual(self._one(
            "MATCH (i:IP {address: $ip, project_id: $pid})-[:HAS_VULNERABILITY]->(v:Vulnerability) "
            "WHERE v.source = 'shodan_api' RETURN count(v) AS c", ip=IP)["c"], 2)

        # A re-run refreshes the evidence on the same node; no duplicates.
        self.client.update_graph_from_shodan(_shodan_payload(cvss=9.8), self.user, self.pid)
        banner = self._vuln(BANNER_CVE)
        self.assertEqual((banner["cvss_score"], banner["severity"]), (9.8, "critical"))
        self.assertEqual(self._one(
            "MATCH (v:Vulnerability {project_id: $pid}) WHERE v.source = 'shodan_api' RETURN count(v) AS c")["c"], 2)

    def test_a_worse_informed_run_keeps_the_evidence(self):
        verified = _shodan_payload()
        verified["shodan"]["cves"][0].update(verified=True, detection_method="passive_verified")
        self.client.update_graph_from_shodan(verified, self.user, self.pid)
        # The next run fell back to InternetDB: the same CVE, catalog-only.
        degraded = {"domain": "fp-itest.test", "domains": ["fp-itest.test"], "shodan": {"hosts": [], "cves": [
            {"cve_id": BANNER_CVE, "ip": IP, "source": "internetdb", "detection_method": "passive_catalog"}]}}
        self.client.update_graph_from_shodan(degraded, self.user, self.pid)
        banner = self._vuln(BANNER_CVE)
        self.assertEqual((banner["detection_method"], banner["verified"]), ("passive_verified", True))
        self.assertEqual((banner["product"], banner["cvss_score"], banner["severity"]), ("nginx", 7.7, "high"))

    def test_the_priority_board_reads_the_grade(self):
        from cypherfix_triage import fact_queries, score_model
        self.client.update_graph_from_shodan(_shodan_payload(), self.user, self.pid)
        query = [q for q in fact_queries.FINDING_QUERIES if q["name"] == "vulnerabilities"][0]["query"]
        with self.client.driver.session() as s:
            rows = [dict(r) for r in s.run(query, userId=self.user, projectId=self.pid)]
        by_id = {r["id"]: fact_queries.normalise_finding_row(r) for r in rows}
        banner = by_id[f"shodan-{BANNER_CVE}-{IP}"]
        catalog = by_id[f"shodan-{CATALOG_CVE}-{IP}"]
        self.assertEqual(rows and {r["id"]: r for r in rows}[f"shodan-{BANNER_CVE}-{IP}"]["triage_host"], IP)
        facts = score_model.ProjectFacts()
        self.assertEqual(score_model.confidence(banner, facts).value, 0.4)
        self.assertEqual(score_model.confidence(catalog, facts).value, 0.25)
        self.assertEqual(score_model.score(catalog, facts).tier, "T4")

    # -- JS Recon --------------------------------------------------------------
    def test_js_recon_findings_carry_their_new_fields(self):
        self.client.update_graph_from_js_recon(_js_payload(), self.user, self.pid)

        def props(finding_type):
            rec = self._one(
                "MATCH (f:JsReconFinding {project_id: $pid, finding_type: $t}) RETURN properties(f) AS p", t=finding_type)
            return rec["p"]

        sink = props("dom_sink")
        self.assertEqual((sink["line"], sink["column"], sink["user_source"]), (1, 42, "location.hash"))
        self.assertEqual((sink["vendor"], sink["third_party"], sink["nominal_severity"]), (False, False, "high"))

        exposure = props("source_map_exposure")
        self.assertEqual(exposure["map_url"], "https://app.fp-itest.test/static/js/main.js.map")
        self.assertEqual((exposure["files_count"], exposure["first_party_files"]), (3, 2))
        self.assertEqual(exposure["source_files"], ["src/App.tsx", "src/api.ts"])
        self.assertIs(exposure["has_sources_content"], True)

        reference = props("source_map_reference")
        self.assertEqual((reference["title"], reference["fetch_result"]), ("source_map_reference", "http_403"))
        self.assertIs(reference["accessible"], False)

        ref = props("dev_reference")
        self.assertEqual((ref["title"], ref["evidence"], ref["severity"], ref["line"]),
                         ("Localhost with Port", "localhost:8080", "info", 7))
        self.assertEqual(self._one(
            "MATCH (f:JsReconFinding {project_id: $pid, finding_type: 'dev_reference'}) "
            "OPTIONAL MATCH (s:Secret {project_id: $pid}) RETURN count(s) AS c")["c"], 0)

        # Every finding hangs off the JS file node it came from.
        self.assertEqual(self._one(
            "MATCH (file:JsReconFinding {project_id: $pid, finding_type: 'js_file'})-[:HAS_JS_FINDING]->(f) "
            "WHERE f.finding_type IN ['dom_sink', 'source_map_exposure', 'source_map_reference', 'dev_reference'] "
            "RETURN count(f) AS c")["c"], 4)

        # Idempotent.
        self.client.update_graph_from_js_recon(_js_payload(), self.user, self.pid)
        self.assertEqual(self._one(
            "MATCH (f:JsReconFinding {project_id: $pid}) WHERE f.finding_type <> 'js_file' RETURN count(f) AS c")["c"], 4)


if __name__ == "__main__":
    unittest.main()
