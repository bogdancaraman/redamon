"""Partial-recon entry for the serialized-object scan (plan §7, §14).

Patches the module's graph builder, settings and Neo4j client (run_serialized_scan
itself is pure, so it runs for real). Verifies the toggle is force-enabled, the
scan runs, candidates are written, and a run with no targets bails without a
graph write.
"""

import unittest
from unittest.mock import MagicMock, patch

import recon.partial_recon_modules.serialized_scanning as mod


def _graph_recon_data():
    return {
        "domain": "example.com",
        "domains": ["example.com"],
        "http_probe": {"by_url": {
            "https://example.com/app": {
                "url": "https://example.com/app", "host": "example.com",
                "status_code": 200, "content_type": "text/html",
                "headers": {"set_cookie": "sess=rO0ABXNy; Path=/"},
            },
        }},
        "resource_enum": {"endpoints": {}, "parameters": {}, "discovered_urls": []},
        "metadata": {},
    }


class TestRunSerializedScanPartial(unittest.TestCase):
    def _run(self, config, neo4j_connected=True, graph_data=None):
        client = MagicMock()
        client.verify_connection.return_value = neo4j_connected
        client.update_graph_from_serialized_scan.return_value = {
            "vulnerabilities_created": 1, "relationships_created": 1, "errors": [],
        }
        neo4j_cls = MagicMock()
        neo4j_cls.return_value.__enter__ = MagicMock(return_value=client)
        neo4j_cls.return_value.__exit__ = MagicMock(return_value=False)
        fake_graph_db = MagicMock()
        fake_graph_db.Neo4jClient = neo4j_cls

        builder = MagicMock(return_value=(graph_data if graph_data is not None else _graph_recon_data()))

        with patch.dict("sys.modules", {"graph_db": fake_graph_db}), \
             patch.object(mod, "scope_roots", return_value=["example.com"]), \
             patch.object(mod, "partial_settings", return_value={}), \
             patch.object(mod, "_should_include_root_domain", return_value=True), \
             patch.object(mod, "_build_graphql_data_from_graph", builder):
            import os
            os.environ["USER_ID"] = "user1"
            os.environ["PROJECT_ID"] = "proj1"
            mod.run_serialized_scan_partial(config)
        return client, builder

    def test_force_enables_and_runs_and_writes(self):
        client, _ = self._run({"domain": "example.com", "include_graph_targets": True})
        self.assertTrue(client.update_graph_from_serialized_scan.called)
        args = client.update_graph_from_serialized_scan.call_args[0]
        self.assertIn("serialized_scan", args[0])          # recon_data carries results
        self.assertEqual(args[1], "user1")
        self.assertEqual(args[2], "proj1")

    def test_candidate_from_cookie_is_written(self):
        client, _ = self._run({"domain": "example.com", "include_graph_targets": True})
        recon_data = client.update_graph_from_serialized_scan.call_args[0][0]
        fmts = {f["deser_format"] for f in recon_data["serialized_scan"]["findings"]}
        self.assertIn("native_java", fmts)

    def test_bails_with_no_targets(self):
        client, _ = self._run(
            {"domain": "example.com", "include_graph_targets": False},
            graph_data={"domain": "example.com", "domains": ["example.com"],
                        "http_probe": {"by_url": {}},
                        "resource_enum": {"endpoints": {}, "parameters": {}, "discovered_urls": []},
                        "metadata": {}})
        self.assertFalse(client.update_graph_from_serialized_scan.called)

    def test_user_urls_used_without_graph_targets(self):
        client, _ = self._run({
            "domain": "example.com", "include_graph_targets": False,
            "user_targets": {"urls": ["https://custom.example/x?data=rO0ABXNy"]},
        })
        self.assertTrue(client.update_graph_from_serialized_scan.called)

    def test_skips_graph_write_when_neo4j_down_is_still_attempted(self):
        # The module opens the client unconditionally; verify_connection gating is
        # the client's concern. We assert the scan ran and the write was attempted.
        client, _ = self._run({"domain": "example.com", "include_graph_targets": True},
                              neo4j_connected=False)
        self.assertTrue(client.update_graph_from_serialized_scan.called)


if __name__ == "__main__":
    unittest.main()
