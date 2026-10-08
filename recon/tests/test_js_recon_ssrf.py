"""
STRIDE I14 — JS-recon must not probe URLs (extracted from a target's JavaScript)
that resolve to cloud metadata / loopback / RFC-1918 / link-local. Otherwise the
recon container becomes an SSRF probe against internal services.

Pure guard tests run anywhere; the probe-integration test needs the recon image
deps (imported lazily, SKIPs otherwise).

Run in the recon image:
    docker run --rm -v "$PWD/recon:/app/recon" -w /app -e PYTHONPATH=/app \
        --entrypoint python redamon-recon:latest -m unittest recon.tests.test_js_recon_ssrf
"""
import sys
import unittest
from pathlib import Path

# Allow both repo-root (recon.main_recon_modules...) and in-image (ip_filter) imports.
_MRM = str(Path(__file__).resolve().parents[1] / "main_recon_modules")
if _MRM not in sys.path:
    sys.path.insert(0, _MRM)

from ip_filter import is_url_safe_to_probe  # noqa: E402

PUBLIC = "http://93.184.216.34/api/x"
METADATA = "http://169.254.169.254/latest/meta-data/"


class GuardPolicy(unittest.TestCase):
    def test_allows_public_literal_ip(self):
        self.assertTrue(is_url_safe_to_probe(PUBLIC))

    def test_blocks_ssrf_targets(self):
        for bad in [
            METADATA,
            "http://10.0.0.5/",
            "http://127.0.0.1/",
            "http://192.168.1.1/",
            "http://172.16.9.9/",
            "http://100.100.100.200/",           # CGNAT
            "http://[::ffff:169.254.169.254]/",   # IPv4-mapped IPv6
        ]:
            self.assertFalse(is_url_safe_to_probe(bad), bad)

    def test_blocks_scheme_metadata_host_and_unresolvable(self):
        self.assertFalse(is_url_safe_to_probe("file:///etc/passwd"))
        self.assertFalse(is_url_safe_to_probe("ws://x/"))
        self.assertFalse(is_url_safe_to_probe("http://metadata.google.internal/"))
        self.assertFalse(is_url_safe_to_probe("http://does-not-exist.invalid.example/"))


try:
    from recon.main_recon_modules.js_recon import _validate_extracted_endpoints
    _HAVE = True
except Exception:
    try:
        from js_recon import _validate_extracted_endpoints  # type: ignore
        _HAVE = True
    except Exception:
        _HAVE = False


class _Spy:
    def __init__(self):
        self.urls = []

    def __call__(self, method, url, **_kw):
        self.urls.append(url)

        class _R:
            status_code = 200
        return _R()


@unittest.skipUnless(_HAVE, "recon image deps unavailable")
class ProbeSkipsSSRF(unittest.TestCase):
    def test_metadata_endpoint_is_never_probed(self):
        spy = _Spy()
        endpoints = [
            {"full_url": METADATA, "method": "GET"},
            {"full_url": PUBLIC, "method": "GET"},
        ]
        # Both hosts in scope, so only the SSRF guard decides.
        scope = ([], {"169.254.169.254", "93.184.216.34"})
        _validate_extracted_endpoints(
            endpoints, {"JS_RECON_VALIDATE_ENDPOINTS": True}, scope, request_func=spy
        )
        by_url = {e["full_url"]: e for e in endpoints}
        # Metadata: blocked, never sent to the requester.
        self.assertEqual(by_url[METADATA]["validation_status"], "unvalidated")
        self.assertEqual(by_url[METADATA]["validation_error"], "ssrf_blocked")
        self.assertNotIn(METADATA, spy.urls)
        # Public: probed normally.
        self.assertIn(PUBLIC, spy.urls)
        self.assertEqual(by_url[PUBLIC]["validation_status"], "hittable")


if __name__ == "__main__":
    unittest.main(verbosity=2)


@unittest.skipUnless(_HAVE, "recon image deps unavailable")
class SafeRedirectGetBlocksInternal(unittest.TestCase):
    """I14 — the JS-download helper validates every redirect hop."""

    def _patch_requests(self, routes):
        import recon.main_recon_modules.js_recon as jr

        class _R:
            def __init__(self, status, headers):
                self.status_code = status
                self.headers = headers
        calls = []

        def fake_get(url, **kw):
            calls.append(url)
            status, headers = routes[url]
            return _R(status, headers)

        return jr, fake_get, calls

    def test_redirect_into_metadata_blocked(self):
        from unittest.mock import patch
        jr, fake_get, calls = self._patch_requests({
            PUBLIC: (302, {"Location": METADATA}),
        })
        with patch.object(jr.requests, "get", fake_get):
            resp = jr._safe_redirect_get(PUBLIC, timeout=5, headers={})
        self.assertIsNone(resp)
        self.assertNotIn(METADATA, calls)  # internal hop never fetched
        self.assertEqual(calls, [PUBLIC])

    def test_public_download_succeeds(self):
        from unittest.mock import patch
        jr, fake_get, calls = self._patch_requests({
            PUBLIC: (200, {"Content-Type": "application/javascript"}),
        })
        with patch.object(jr.requests, "get", fake_get):
            resp = jr._safe_redirect_get(PUBLIC, timeout=5, headers={})
        self.assertIsNotNone(resp)
        self.assertEqual(resp.status_code, 200)


try:
    from recon.helpers.js_recon.sourcemap import _fetch_sourcemap
    _HAVE_SM = True
except Exception:
    _HAVE_SM = False


@unittest.skipUnless(_HAVE_SM, "recon image deps unavailable")
class SourcemapGuard(unittest.TestCase):
    """I14 — source-map fetch refuses internal targets before any request."""

    def test_metadata_sourcemap_not_fetched(self):
        from unittest.mock import patch
        import recon.helpers.js_recon.sourcemap as sm
        head = patch.object(sm.requests, "head")
        get = patch.object(sm.requests, "get")
        with head as h, get as g:
            result = _fetch_sourcemap("http://169.254.169.254/app.js.map", timeout=5)
        self.assertIsNone(result)
        h.assert_not_called()
        g.assert_not_called()
