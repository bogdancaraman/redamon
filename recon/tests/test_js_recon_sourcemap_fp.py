"""False-positive regressions for JS Recon source-map discovery.

A field report muted ~95 source-map rows: a single-page app answers the
referenced `.map` URL with its own HTML shell (200 text/html), and vendor
scripts' maps (a marketing loader, a CMS plugin) were reported as the
target's source disclosure. The fetch must prove a v3 source map, an
unreachable reference is reported only when the server refused access, and a
map that holds only library code is low. Every case has a positive twin.
"""

from __future__ import annotations

import base64
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.js_recon import sourcemap as sm
from recon.main_recon_modules import js_recon

JS = "https://app.example.com/static/js/main.4f2a9c.js"
MAP = JS + ".map"

SPA_SHELL = '<!doctype html><html><head><title>App</title></head><body><div id="root"></div></body></html>'
FIRST_PARTY_MAP = {
    "version": 3, "file": "main.js", "mappings": "AAAA,SAASA",
    "sources": ["webpack:///./src/App.tsx", "webpack:///./src/api/client.ts",
                "webpack:///node_modules/react/index.js", "webpack:///webpack/bootstrap"],
    "sourcesContent": ["export const App = () => null;", "const KEY = 'x';",
                       "module.exports = require('./cjs/react.production.min.js');", "(()=>{})()"],
}
VENDOR_ONLY_MAP = {
    "version": 3, "mappings": "AAAA",
    "sources": ["webpack:///node_modules/lodash/lodash.js", "webpack:///webpack/bootstrap",
                "webpack:///(webpack)/buildin/global.js"],
    "sourcesContent": ["/* lodash */", "(()=>{})()", "g = this"],
}


def _resp(status=200, body="", ctype="application/json"):
    r = MagicMock()
    r.status_code = status
    r.headers = {"Content-Type": ctype} if ctype else {}
    r.text = body
    return r


def _fetch(get_resp, head_status=200, url=MAP):
    outcome = {}
    with patch.object(sm, "is_url_safe_to_probe", return_value=True), \
         patch.object(sm.requests, "head", return_value=_resp(head_status)), \
         patch.object(sm.requests, "get", return_value=get_resp):
        data = sm._fetch_sourcemap(url, timeout=5, outcome=outcome)
    return data, outcome


class TestFetchProvesASourceMap(unittest.TestCase):
    def test_spa_shell_with_200_is_not_a_map(self):
        data, out = _fetch(_resp(200, SPA_SHELL, "text/html; charset=utf-8"))
        self.assertIsNone(data)
        self.assertEqual(out["reason"], "html")

    def test_html_body_mislabelled_as_json_is_not_a_map(self):
        data, out = _fetch(_resp(200, "\n  " + SPA_SHELL, "application/json"))
        self.assertIsNone(data)
        self.assertEqual(out["reason"], "html")

    def test_json_catch_all_is_not_a_map(self):
        data, out = _fetch(_resp(200, json.dumps({"error": "not found", "status": 404})))
        self.assertIsNone(data)
        self.assertEqual(out["reason"], "invalid_schema")

    def test_sources_without_mappings_is_not_a_map(self):
        data, out = _fetch(_resp(200, json.dumps({"version": 3, "sources": ["a.js"]})))
        self.assertIsNone(data)
        self.assertEqual(out["reason"], "invalid_schema")

    def test_plain_text_error_is_not_json(self):
        data, out = _fetch(_resp(200, "Not Found", "text/plain"))
        self.assertIsNone(data)
        self.assertEqual(out["reason"], "not_json")

    def test_a_real_map_served_as_octet_stream_is_accepted(self):
        # S3 / CDNs often serve .map files as octet-stream; the old content-type
        # allowlist missed them.
        data, out = _fetch(_resp(200, json.dumps(FIRST_PARTY_MAP), "binary/octet-stream"))
        self.assertEqual(data["sources"], FIRST_PARTY_MAP["sources"])
        self.assertEqual(out["reason"], "ok")

    def test_xssi_prefixed_map_is_accepted(self):
        data, _ = _fetch(_resp(200, ")]}'\n" + json.dumps(FIRST_PARTY_MAP)))
        self.assertIsNotNone(data)

    def test_index_map_is_accepted(self):
        index = {"version": 3, "sections": [{"offset": {"line": 0, "column": 0}, "map": FIRST_PARTY_MAP}]}
        data, _ = _fetch(_resp(200, json.dumps(index)))
        self.assertIsNotNone(data)

    def test_status_outcomes(self):
        self.assertEqual(_fetch(_resp(403, "denied", "text/plain"))[1]["reason"], "http_403")
        self.assertEqual(_fetch(_resp(200), head_status=404)[1]["reason"], "not_found")
        self.assertEqual(_fetch(_resp(404, "", "text/plain"), head_status=405)[1]["reason"], "not_found")

    def test_connection_failure_is_unreachable(self):
        outcome = {}
        with patch.object(sm, "is_url_safe_to_probe", return_value=True), \
             patch.object(sm.requests, "head", side_effect=requests.ConnectionError("x")):
            self.assertIsNone(sm._fetch_sourcemap(MAP, outcome=outcome))
        self.assertEqual(outcome["reason"], "unreachable")

    def test_inline_data_map(self):
        good = "data:application/json;base64," + base64.b64encode(json.dumps(FIRST_PARTY_MAP).encode()).decode()
        self.assertIsNotNone(sm._fetch_sourcemap(good))
        bad = "data:application/json;base64," + base64.b64encode(b"<html>").decode()
        outcome = {}
        self.assertIsNone(sm._fetch_sourcemap(bad, outcome=outcome))
        self.assertEqual(outcome["reason"], "html")

    def test_outcome_is_optional(self):
        data, _ = _fetch(_resp(200, json.dumps(FIRST_PARTY_MAP)))
        self.assertIsNotNone(data)


class TestOwnership(unittest.TestCase):
    def test_vendor_sources(self):
        for s in ("webpack:///node_modules/react/index.js", "webpack:///webpack/bootstrap",
                  "webpack:///(webpack)/buildin/global.js", "../node_modules/core-js/a.js",
                  "webpack:///./node_modules/x/y.js", "external \"React\"", "~/lodash/lodash.js"):
            self.assertTrue(sm._is_vendor_source(s), s)

    def test_first_party_sources(self):
        for s in ("webpack:///./src/App.tsx", "src/api/client.ts", "../../app/models/user.rb.js",
                  "webpack:///./pages/vendor-portal.tsx"):
            self.assertFalse(sm._is_vendor_source(s), s)

    def test_first_party_source_text_is_high(self):
        r = sm.analyze_sourcemap(FIRST_PARTY_MAP, MAP, JS)
        self.assertEqual((r["severity"], r["files_count"], r["first_party_files"]), ("high", 4, 2))
        self.assertTrue(r["has_sources_content"])
        self.assertEqual(r["source_files"], ["webpack:///./src/App.tsx", "webpack:///./src/api/client.ts"])

    def test_first_party_paths_without_text_are_medium(self):
        m = dict(FIRST_PARTY_MAP)
        m.pop("sourcesContent")
        self.assertEqual(sm.analyze_sourcemap(m, MAP, JS)["severity"], "medium")

    def test_library_only_map_is_low(self):
        r = sm.analyze_sourcemap(VENDOR_ONLY_MAP, MAP, JS)
        self.assertEqual((r["severity"], r["first_party_files"]), ("low", 0))
        self.assertFalse(r["has_sources_content"])

    def test_secret_scan_reads_only_first_party_sources(self):
        scanned = []

        def scan(content, url):
            scanned.append(url)
            return []

        sm.analyze_sourcemap(FIRST_PARTY_MAP, MAP, JS, scan)
        self.assertEqual(scanned, [f"{MAP}:webpack:///./src/App.tsx", f"{MAP}:webpack:///./src/api/client.ts"])

    def test_index_map_sources_are_counted(self):
        index = {"version": 3, "sections": [
            {"offset": {"line": 0, "column": 0}, "map": FIRST_PARTY_MAP},
            {"offset": {"line": 9, "column": 0}, "map": VENDOR_ONLY_MAP},
        ]}
        r = sm.analyze_sourcemap(index, MAP, JS)
        self.assertEqual((r["files_count"], r["first_party_files"], r["severity"]), (7, 2, "high"))


class TestDiscovery(unittest.TestCase):
    def _discover(self, fetch_result):
        data, reason = fetch_result

        def fake_fetch(url, timeout=10, outcome=None):
            if outcome is not None:
                outcome["reason"] = reason
            return data

        js_files = [{"url": JS, "content": "console.log(1);\n//# sourceMappingURL=main.4f2a9c.js.map", "headers": {}}]
        with patch.object(sm, "_fetch_sourcemap", side_effect=fake_fetch):
            return sm.discover_and_analyze_sourcemaps(js_files, {"JS_RECON_SOURCE_MAPS": True})

    def test_referenced_map_answered_by_the_spa_shell_reports_nothing(self):
        self.assertEqual(self._discover((None, "html")), [])

    def test_referenced_map_404_or_json_error_reports_nothing(self):
        for reason in ("not_found", "invalid_schema", "not_json", "unreachable", "unsafe"):
            self.assertEqual(self._discover((None, reason)), [], reason)

    def test_referenced_map_behind_auth_is_an_info_reference(self):
        [row] = self._discover((None, "http_403"))
        self.assertEqual((row["finding_type"], row["severity"], row["fetch_result"]),
                         ("source_map_reference", "info", "http_403"))
        self.assertEqual(row["map_url"], MAP)
        self.assertFalse(row["accessible"])

    def test_served_map_is_an_exposure(self):
        [row] = self._discover((FIRST_PARTY_MAP, "ok"))
        self.assertEqual((row["finding_type"], row["severity"], row["discovery_method"]),
                         ("source_map_exposure", "high", "comment"))


class TestThirdPartyHost(unittest.TestCase):
    def test_map_of_a_script_on_a_foreign_host_is_info(self):
        results = {"source_maps": [
            {"js_url": "https://js.marketing-vendor.test/loader.js", "severity": "high"},
            {"js_url": JS, "severity": "high"},
        ]}
        js_recon._downgrade_third_party_findings(results, {"domain": "example.com"})
        vendor, own = results["source_maps"]
        self.assertEqual((vendor["severity"], vendor["third_party"]), ("info", True))
        self.assertEqual(own["severity"], "high")
        self.assertNotIn("third_party", own)


if __name__ == "__main__":
    unittest.main()
