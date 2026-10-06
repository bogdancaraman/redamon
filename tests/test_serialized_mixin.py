"""Unit tests for SerializedScanMixin (plan §5.5, §14).

Hermetic: a fake neo4j session captures the Cypher + params, so we assert the
tenant MERGE key, flat $props, OPTIONAL MATCH attachment (candidate written even
when the endpoint is absent), and the candidate lifecycle fields -- without a
live graph. Plus: the method is reachable from the composed ReconMixin.
"""

import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from graph_db.mixins.recon.serialized_mixin import SerializedScanMixin, _vuln_id


class _FakeSession:
    def __init__(self, calls):
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        return MagicMock()


class _FakeDriver:
    def __init__(self):
        self.calls = []

    def session(self):
        return _FakeSession(self.calls)


class _Harness(SerializedScanMixin):
    def __init__(self):
        self.driver = _FakeDriver()


def _finding(**over):
    base = {
        "endpoint_url": "https://t.example.com/app",
        "http_method": "GET",
        "baseurl": "https://t.example.com",
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


def _is_flat(value) -> bool:
    """Neo4j property rule: scalar, or a list of scalars. No maps anywhere."""
    if isinstance(value, dict):
        return False
    if isinstance(value, (list, tuple)):
        return all(not isinstance(v, (dict, list, tuple)) for v in value)
    return True


class TestSerializedGraphWriter(unittest.TestCase):
    def _run(self, findings):
        h = _Harness()
        stats = h.update_graph_from_serialized_scan(
            {"serialized_scan": {"findings": findings}}, "u1", "p1")
        return h, stats

    def test_writes_one_candidate(self):
        h, stats = self._run([_finding()])
        self.assertEqual(stats["vulnerabilities_created"], 1)
        self.assertEqual(stats["errors"], [])
        self.assertEqual(len(h.driver.calls), 1)

    def test_tenant_key_and_attachment_shape(self):
        h, _ = self._run([_finding()])
        query, params = h.driver.calls[0]
        self.assertIn("MERGE (v:Vulnerability {id: $vuln_id, user_id: $user_id", query)
        self.assertIn("OPTIONAL MATCH (e:Endpoint", query)
        self.assertIn("OPTIONAL MATCH (bu:BaseURL", query)
        # every Endpoint/BaseURL read must be OPTIONAL (no bare MATCH that would
        # drop the candidate when clear_recon_data removed the anchor)
        self.assertEqual(query.count("MATCH (e:Endpoint"),
                         query.count("OPTIONAL MATCH (e:Endpoint"))
        self.assertEqual(query.count("MATCH (bu:BaseURL"),
                         query.count("OPTIONAL MATCH (bu:BaseURL"))
        self.assertEqual(params["user_id"], "u1")
        self.assertEqual(params["project_id"], "p1")
        self.assertEqual(params["baseurl"], "https://t.example.com")
        self.assertEqual(params["path"], "/app")
        self.assertEqual(params["method"], "GET")

    def test_props_are_flat(self):
        h, _ = self._run([_finding()])
        _, params = h.driver.calls[0]
        props = params["props"]
        for k, v in props.items():
            with self.subTest(prop=k):
                self.assertTrue(_is_flat(v), f"prop {k}={v!r} is not a flat Neo4j value")

    def test_candidate_lifecycle_fields(self):
        h, _ = self._run([_finding()])
        _, params = h.driver.calls[0]
        props = params["props"]
        self.assertIs(props["needs_agent_confirmation"], True)
        self.assertEqual(props["severity"], "info")
        self.assertEqual(props["deser_format"], "native_java")
        self.assertEqual(props["type"], "insecure_deserialization")
        # source is set ON CREATE only, so it must NOT be in the SET += props
        self.assertNotIn("source", props)
        self.assertIn("v.source = 'serialized_scan'", h.driver.calls[0][0])
        # created_at is create-only; never rebuilt via SET +=
        self.assertNotIn("created_at", props)

    def test_vuln_id_is_deterministic_and_tenant_scoped(self):
        a = _vuln_id("u1", "p1", "https://t", "/x", "c", "native_java", "m", "cookie")
        b = _vuln_id("u1", "p1", "https://t", "/x", "c", "native_java", "m", "cookie")
        cross = _vuln_id("u2", "p1", "https://t", "/x", "c", "native_java", "m", "cookie")
        self.assertEqual(a, b)
        self.assertNotEqual(a, cross)
        self.assertTrue(a.startswith("serialized_"))

    def test_vuln_id_distinguishes_transport(self):
        # F4: two candidates identical but for transport must NOT collapse onto
        # one node (dedup_key keeps them distinct, so the id must too).
        as_cookie = _vuln_id("u1", "p1", "https://t", "/x", "c", "native_java", "m", "cookie")
        as_param = _vuln_id("u1", "p1", "https://t", "/x", "c", "native_java", "m", "param")
        self.assertNotEqual(as_cookie, as_param)

    def test_candidate_written_even_without_endpoint(self):
        # OPTIONAL MATCH means the node is MERGEd regardless of anchor presence;
        # the fake session always "finds" nothing, yet the write still runs.
        h, stats = self._run([_finding()])
        self.assertEqual(stats["vulnerabilities_created"], 1)

    def test_missing_fields_skipped(self):
        h, stats = self._run([_finding(endpoint_url=""), _finding(deser_format="")])
        self.assertEqual(stats["vulnerabilities_created"], 0)

    def test_empty_findings_no_write(self):
        h, stats = self._run([])
        self.assertEqual(stats["vulnerabilities_created"], 0)
        self.assertEqual(h.driver.calls, [])

    def test_skipped_finding_does_not_block_a_good_one(self):
        h, stats = self._run([_finding(endpoint_url=""), _finding()])
        self.assertEqual(stats["vulnerabilities_created"], 1)


class TestReachableFromReconMixin(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.modules.setdefault("neo4j", MagicMock())
        sys.modules.setdefault("dotenv", MagicMock())
        for k in list(sys.modules):
            if k.startswith("graph_db.mixins.recon"):
                del sys.modules[k]
        from graph_db.mixins.recon_mixin import ReconMixin
        cls.ReconMixin = ReconMixin

    def test_method_resolvable(self):
        self.assertTrue(hasattr(self.ReconMixin, "update_graph_from_serialized_scan"))
        self.assertTrue(callable(getattr(self.ReconMixin, "update_graph_from_serialized_scan")))


if __name__ == "__main__":
    unittest.main()
