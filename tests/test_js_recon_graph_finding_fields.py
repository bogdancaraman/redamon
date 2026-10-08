"""Source-map and DOM-sink fields on JsReconFinding nodes.

The JS Recon table's Source Maps tab has always had Map URL, Accessible and
Files columns, but the writer stored none of them and titled every source-map
row `source_map_exposure`, so a referenced map that 404'd read as a source
disclosure with no URL to check. DOM sinks lost the line, the source found
near the sink and the vendor flag the detector computes.
"""

import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from graph_db.mixins.recon.js_recon_mixin import JsReconMixin  # noqa: E402


class _Result:
    def single(self):
        return {"linked": 0, "created": True, "enriched": 0}


class _Session:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, **kwargs):
        self.calls.append((query, kwargs))
        return _Result()


class _Client(JsReconMixin):
    def __init__(self):
        self.session_obj = _Session()
        self.driver = MagicMock()
        self.driver.session.return_value = self.session_obj


def _written(js_recon: dict) -> dict:
    client = _Client()
    client.update_graph_from_js_recon({
        "domain": "example.com",
        "js_recon": {"scan_metadata": {"scan_timestamp": "2026-10-08T00:00:00Z"}, **js_recon},
    }, "u1", "p1")
    out = {}
    for query, kwargs in client.session_obj.calls:
        if "MERGE (jf:JsReconFinding" in query:
            props = kwargs.get("props") or {}
            out[props.get("finding_type")] = props
    return out


def _assert_flat(test, props):
    for key, value in props.items():
        test.assertNotIsInstance(value, dict, key)
        if isinstance(value, list):
            test.assertTrue(all(not isinstance(v, (dict, list)) for v in value), key)


class TestSourceMapFields(unittest.TestCase):
    def test_exposure_carries_map_url_counts_and_a_readable_detail(self):
        props = _written({"source_maps": [{
            "id": "sm1", "finding_type": "source_map_exposure", "severity": "high",
            "js_url": "https://app.example.com/main.js", "map_url": "https://app.example.com/main.js.map",
            "accessible": True, "discovery_method": "comment", "files_count": 4, "first_party_files": 2,
            "has_sources_content": True, "source_files": ["src/App.tsx", "src/api.ts"],
            "secrets_in_source": 1, "secrets": [{"name": "Generic Secret", "matched_text": "x"}],
        }]})["source_map_exposure"]
        self.assertEqual(props["map_url"], "https://app.example.com/main.js.map")
        self.assertEqual(props["evidence"], "https://app.example.com/main.js.map")
        self.assertEqual((props["accessible"], props["files_count"], props["first_party_files"]), (True, 4, 2))
        self.assertEqual(props["fetch_result"], "ok")
        self.assertEqual(props["source_files"], ["src/App.tsx", "src/api.ts"])
        self.assertEqual(props["secrets_in_source"], 1)
        self.assertIn("2 of them the target's own", props["detail"])
        self.assertIn("source text embedded", props["detail"])
        self.assertEqual(props["source_url"], "https://app.example.com/main.js")
        _assert_flat(self, props)

    def test_reference_row_is_titled_as_a_reference(self):
        props = _written({"source_maps": [{
            "id": "sm2", "finding_type": "source_map_reference", "severity": "info",
            "js_url": "https://app.example.com/main.js", "map_url": "https://app.example.com/main.js.map",
            "accessible": False, "fetch_result": "http_403", "discovery_method": "comment",
            "files_count": 0, "source_files": [], "secrets_in_source": 0, "secrets": [],
        }]})["source_map_reference"]
        self.assertEqual(props["title"], "source_map_reference")
        self.assertFalse(props["accessible"])
        self.assertEqual(props["fetch_result"], "http_403")
        self.assertIn("answered http_403", props["detail"])
        _assert_flat(self, props)


class TestDomSinkFields(unittest.TestCase):
    def test_sink_keeps_location_source_and_vendor_flag(self):
        props = _written({"dom_sinks": [{
            "id": "ds1", "finding_type": "dom_sink", "type": "innerHTML",
            "pattern": "…out.innerHTML=location.hash…", "description": "Direct HTML injection (src)",
            "source_url": "https://app.example.com/main.js", "line": 3, "column": 42,
            "severity": "high", "confidence": "medium", "nominal_severity": "high",
            "user_source": "location.hash", "vendor": False,
        }]})["dom_sink"]
        self.assertEqual((props["title"], props["line"], props["column"]), ("innerHTML", 3, 42))
        self.assertEqual((props["user_source"], props["vendor"], props["nominal_severity"]),
                         ("location.hash", False, "high"))
        self.assertEqual(props["evidence"], "…out.innerHTML=location.hash…")
        _assert_flat(self, props)


class TestDevReferenceNodes(unittest.TestCase):
    def test_localhost_url_is_an_info_js_finding_not_a_secret(self):
        client = _Client()
        client.update_graph_from_js_recon({
            "domain": "example.com",
            "js_recon": {
                "scan_metadata": {"scan_timestamp": "2026-10-08T00:00:00Z"},
                "dev_references": [{
                    "id": "r1", "type": "Localhost with Port", "value": "localhost:8080",
                    "source_url": "https://app.example.com/main.js", "line_number": 12,
                    "context": 'const api = "http://localhost:8080/api";',
                }],
            },
        }, "u1", "p1")
        queries = [q for q, _ in client.session_obj.calls]
        self.assertFalse(any("MERGE (s:Secret" in q for q in queries))
        [props] = [kw["props"] for q, kw in client.session_obj.calls
                   if "MERGE (jf:JsReconFinding" in q and kw["props"].get("finding_type") == "dev_reference"]
        self.assertEqual((props["title"], props["evidence"], props["severity"], props["line"]),
                         ("Localhost with Port", "localhost:8080", "info", 12))
        self.assertTrue(props["id"].startswith("jsrf-u1-p1-devref-"))
        _assert_flat(self, props)


if __name__ == "__main__":
    unittest.main()
