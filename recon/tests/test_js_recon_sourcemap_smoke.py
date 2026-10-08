"""Real-network smoke test for the source-map false-positive fixes.

Runs the REAL discovery (real requests HEAD + GET, real body parsing) against
a local single-page app that answers every unknown path, `.map` included,
with its HTML shell and a 200, next to a bundle whose map is really served
(as application/octet-stream, the way object stores serve it), one whose map
sits behind a 403, and one whose map holds only library code.

The SSRF guard refuses loopback, as it must in a scan; this test lifts it for
its own server only.

Run:
    docker run --rm -v "$PWD:/repo" -w /repo/recon -e PYTHONPATH=/repo/recon:/repo \\
      redamon-recon python -m pytest tests/test_js_recon_sourcemap_smoke.py -v
"""

from __future__ import annotations

import json
import socket
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.js_recon import sourcemap as sm

SHELL = b'<!doctype html><html><head><title>App</title></head><body><div id="root"></div></body></html>'
OWN_MAP = json.dumps({
    "version": 3, "mappings": "AAAA",
    "sources": ["webpack:///./src/App.tsx", "webpack:///node_modules/react/index.js"],
    "sourcesContent": ["export const App = () => null;", "module.exports = {};"],
}).encode()
LIB_MAP = json.dumps({
    "version": 3, "mappings": "AAAA",
    "sources": ["webpack:///node_modules/lodash/lodash.js", "webpack:///webpack/bootstrap"],
}).encode()


class SpaServer(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _send(self, status, body, ctype):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/static/js/own.js.map":
            return self._send(200, OWN_MAP, "application/octet-stream")
        if path == "/static/js/lib.js.map":
            return self._send(200, LIB_MAP, "application/json")
        if path == "/static/js/private.js.map":
            return self._send(403, b"<h1>Forbidden</h1>", "text/html")
        return self._send(200, SHELL, "text/html; charset=utf-8")   # the SPA catch-all


def _js(name):
    return f"console.log('{name}');\n//# sourceMappingURL={name}.js.map\n"


class TestSpaSourceMapsEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        cls.server = ThreadingHTTPServer(("127.0.0.1", port), SpaServer)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{port}/static/js/"
        files = [{"url": base + f"{n}.js", "content": _js(n), "headers": {}}
                 for n in ("own", "lib", "private", "shell")]
        with patch.object(sm, "is_url_safe_to_probe", return_value=True):
            cls.rows = {r["js_url"].rsplit("/", 1)[-1]: r for r in
                        sm.discover_and_analyze_sourcemaps(files, {"JS_RECON_SOURCE_MAPS": True, "JS_RECON_TIMEOUT": 60})}

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_the_spa_shell_answering_for_a_map_reports_nothing(self):
        self.assertNotIn("shell.js", self.rows)

    def test_a_map_served_as_octet_stream_is_an_exposure_of_own_code(self):
        r = self.rows["own.js"]
        self.assertEqual((r["finding_type"], r["severity"], r["first_party_files"]), ("source_map_exposure", "high", 1))

    def test_a_library_only_map_is_low(self):
        r = self.rows["lib.js"]
        self.assertEqual((r["finding_type"], r["severity"], r["first_party_files"]), ("source_map_exposure", "low", 0))

    def test_a_map_behind_a_403_is_an_info_reference(self):
        r = self.rows["private.js"]
        self.assertEqual((r["finding_type"], r["severity"], r["fetch_result"]), ("source_map_reference", "info", "http_403"))

    def test_nothing_else_was_reported(self):
        self.assertEqual(sorted(self.rows), ["lib.js", "own.js", "private.js"])


if __name__ == "__main__":
    unittest.main()
