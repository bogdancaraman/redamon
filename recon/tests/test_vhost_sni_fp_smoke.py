"""Real-network smoke test for the VHost & SNI false-positive fixes.

Runs the REAL module (real curl, real --write-out parsing, real TLS/SNI)
against three local servers that replicate the shared-edge shapes a field
report muted by the hundred:

  * a Fastly-like HTTP edge that answers every unknown Host with a 500 page
    echoing the name twice and naming a different cache node per request,
    hiding two real apps: a JSON admin API and a wiki whose page changes on
    every request (render time, hit counter);
  * a Cloudflare-like HTTPS edge that answers with a block page carrying a
    fresh Ray ID unless the TLS SNI names its one hidden app;
  * a provider redirect that sends every name to https://<name>/.

Exactly the three hidden routes must be reported, nothing from the
catch-alls. Skips when curl or openssl is missing.

Run:
    docker run --rm -v "$PWD:/repo" -w /repo/recon -e PYTHONPATH=/repo/recon:/repo \\
      redamon-recon python -m pytest tests/test_vhost_sni_fp_smoke.py -v
"""

from __future__ import annotations

import itertools
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.main_recon_modules.vhost_sni_enum import _is_curl_available, run_vhost_sni_enrichment

APEX = "edge-fp.test"
_hits = itertools.count(1)

WORDS = [
    "admin", "wiki", "dev", "staging", "jenkins", "portal-internal", "qa", "grafana", "vpn",
    "api-gateway", "kibana", "ci", "sso", "monitoring", "backoffice", "uat", "x1",
    "preprod-eu-west", "status", "mail", "intranet",
]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Base(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _send(self, status, body: bytes, ctype="text/html; charset=utf-8", extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _host(self) -> str:
        return (self.headers.get("Host") or "").split(":")[0].lower()


class FastlyLikeEdge(_Base):
    def do_GET(self):
        host = self._host()
        if host == f"admin.{APEX}":
            return self._send(200, b'{"service":"admin-api","version":"3.2.1"}', "application/json")
        if host == f"wiki.{APEX}":
            n = next(_hits)
            body = (f"<html><head><title>Internal Wiki</title></head><body>Main page."
                    f" Served in 0.0{n % 9 + 1}s, hits={n}</body></html>").encode()
            return self._send(200, body)
        if not host or host[0].isdigit():
            return self._send(421, b"<h1>Misdirected Request</h1>")
        node = f"cache-fra-etou82{next(_hits):05d}-FRA"
        body = (f"<html><body><h1>Fastly error: unknown domain: {host}</h1>"
                f"<p>Please check that this domain has been added to a service: {host}</p>"
                f"<p>Details: {node}</p></body></html>").encode()
        return self._send(500, body)


class RedirectEdge(_Base):
    def do_GET(self):
        host = self._host()
        if not host or host[0].isdigit():
            return self._send(404, b"")
        return self._send(301, b"", extra={"Location": f"https://{host}/"})


class CloudflareLikeEdge(_Base):
    def do_GET(self):
        sni = getattr(self.request, "_sni", None) or ""
        host = self._host()
        if sni == f"admin.{APEX}" and host == sni:
            return self._send(200, b'{"service":"admin-console","build":"7f1c"}', "application/json")
        ray = uuid.uuid4().hex[:16]
        body = (f"<html><head><title>Attention Required! | Cloudflare</title></head><body>"
                f"<h1>Sorry, you have been blocked</h1><p>You are unable to access {host or 'this site'}</p>"
                f"<p>Cloudflare Ray ID: <strong>{ray}</strong></p></body></html>").encode()
        return self._send(403, body)


def _serve(handler, port, tls_ctx=None):
    srv = ThreadingHTTPServer(("127.0.0.1", port), handler)
    if tls_ctx is not None:
        srv.socket = tls_ctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def _tls_context(tmp: str):
    cert, key = os.path.join(tmp, "c.pem"), os.path.join(tmp, "k.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                    "-out", cert, "-days", "1", "-subj", f"/CN=*.{APEX}"],
                   check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)

    def remember_sni(sock, server_name, _ctx):
        sock._sni = (server_name or "").lower()
    ctx.sni_callback = remember_sni
    return ctx


@unittest.skipUnless(_is_curl_available() and shutil.which("openssl"), "curl or openssl missing")
class TestSharedEdgesEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="vhostfp_")
        cls.http_port, cls.redirect_port, cls.https_port = _free_port(), _free_port(), _free_port()
        cls.servers = [
            _serve(FastlyLikeEdge, cls.http_port),
            _serve(RedirectEdge, cls.redirect_port),
            _serve(CloudflareLikeEdge, cls.https_port, _tls_context(cls.tmp)),
        ]
        cr = {
            "domain": APEX,
            "metadata": {"target": APEX},
            "port_scan": {"by_host": {"127.0.0.1": {"ip": "127.0.0.1", "ports": [
                {"port": cls.http_port, "scheme": "http"},
                {"port": cls.redirect_port, "scheme": "http"},
                {"port": cls.https_port, "scheme": "https"},
            ]}}},
        }
        settings = {
            "VHOST_SNI_ENABLED": True, "VHOST_SNI_TEST_L7": True, "VHOST_SNI_TEST_L4": True,
            "VHOST_SNI_TIMEOUT": 3, "VHOST_SNI_CONCURRENCY": 8, "VHOST_SNI_BASELINE_SIZE_TOLERANCE": 50,
            "VHOST_SNI_USE_DEFAULT_WORDLIST": False, "VHOST_SNI_USE_GRAPH_CANDIDATES": False,
            "VHOST_SNI_INJECT_DISCOVERED": False, "VHOST_SNI_MAX_CANDIDATES_PER_IP": 500,
            "VHOST_SNI_CUSTOM_WORDLIST": "\n".join(WORDS),
        }
        run_vhost_sni_enrichment(cr, settings=settings)
        cls.out = cr["vhost_sni"]

    @classmethod
    def tearDownClass(cls):
        for srv in cls.servers:
            srv.shutdown()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _found(self, port):
        return sorted((f["hostname"], f["layer"]) for f in self.out["findings"] if f["port"] == port)

    def test_fastly_like_edge_reports_only_the_two_hidden_apps(self):
        self.assertEqual(self._found(self.http_port), [(f"admin.{APEX}", "L7"), (f"wiki.{APEX}", "L7")])

    def test_cloudflare_like_edge_reports_only_the_sni_routed_app(self):
        self.assertEqual(self._found(self.https_port), [(f"admin.{APEX}", "L4")])

    def test_provider_redirect_reports_nothing(self):
        self.assertEqual(self._found(self.redirect_port), [])

    def test_nothing_is_rated_high(self):
        self.assertEqual(self.out["summary"]["high_severity"], 0)

    def test_the_catch_alls_were_suppressed_by_the_controls(self):
        # Every name on the redirect port, and every name but the two apps on
        # the Fastly-like port. The block page keeps the baseline's status and
        # a size within tolerance, so its names never become anomalies at all.
        ip = self.out["by_ip"]["127.0.0.1"]
        self.assertEqual(ip["suppressed_by_control"], len(WORDS) + (len(WORDS) - 2))
        self.assertEqual(ip["suppressed_unstable"], 0)


if __name__ == "__main__":
    unittest.main()
