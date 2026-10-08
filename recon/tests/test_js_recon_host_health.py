"""HostHealth gates on JS recon (js_recon.py, #24 download and #27 endpoints).

JS lives on the target host and on CDNs. A host another module already found
unreachable is skipped both when downloading JS and when validating extracted
endpoints, and each fetch records what it saw. js_recon findings carry a host
field (source_url/base_url), so a skip is reported per host and the prune keeps
that host's previous findings.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from unittest import mock

import requests

from recon.helpers import circuit_breaker as cb
from recon.main_recon_modules import js_recon as jr


def _mark_down(host):
    for scheme in ("https", "http"):
        for _ in range(3):
            cb.host_health.record_failure(f"{scheme}://{host}", requests.ConnectionError("x"))


def _resp(status=200, text="var x=1;", headers=None):
    r = mock.MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


class TestDownloadGate:
    def test_a_down_host_is_not_fetched(self):
        _mark_down("dead.example.test")
        urls = ["https://dead.example.test/a.js", "https://live.example.test/b.js"]
        fetched = []

        def fake_get(url, **kw):
            fetched.append(url)
            return _resp()

        with tempfile.TemporaryDirectory() as d, \
             mock.patch.object(jr, "_safe_redirect_get", side_effect=fake_get):
            out = jr._download_js_files(urls, Path(d), max_files=10, concurrency=1, timeout=100)
        assert fetched == ["https://live.example.test/b.js"]
        assert [f["url"] for f in out] == ["https://live.example.test/b.js"]

    def test_connection_failures_mark_the_host_down(self):
        urls = [f"https://slow.example.test/{i}.js" for i in range(3)]
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.object(jr, "_safe_redirect_get",
                               side_effect=requests.ConnectionError("refused")):
            jr._download_js_files(urls, Path(d), max_files=10, concurrency=1, timeout=100)
        assert cb.host_health.is_down("https://slow.example.test/x.js")


class TestEndpointValidationGate:
    def _settings(self):
        return {"JS_RECON_VALIDATE_ENDPOINTS": True, "JS_RECON_ENDPOINT_CONCURRENCY": 1}

    def test_an_endpoint_on_a_down_host_is_not_probed(self):
        _mark_down("dead.example.test")
        endpoints = [
            {"full_url": "https://dead.example.test/api"},
            {"full_url": "https://live.example.test/api"},
        ]
        probed = []

        def requester(method, url, **kw):
            probed.append(url)
            return _resp(200)

        # The SSRF guard resolves DNS; pin it True so the live host reaches the
        # requester (the gate for the dead host runs before this check anyway).
        with mock.patch.object(jr, "is_url_safe_to_probe", return_value=True):
            out = jr._validate_extracted_endpoints(
                endpoints, self._settings(), (["example.test"], set()), request_func=requester,
            )
        by_url = {e["full_url"]: e for e in out}
        assert by_url["https://dead.example.test/api"]["validation_error"] == "host_unreachable"
        assert by_url["https://dead.example.test/api"]["validation_status"] == "unvalidated"
        assert probed == ["https://live.example.test/api"]


class TestSourceMapGate:
    def test_a_down_host_skips_the_guessed_map_probes(self):
        from recon.helpers.js_recon import sourcemap as sm
        _mark_down("dead.example.test")
        js_files = [{"url": "https://dead.example.test/app.js", "content": "var x=1;",
                     "headers": {}}]
        with mock.patch.object(sm, "_fetch_sourcemap") as fetch:
            out = sm.discover_and_analyze_sourcemaps(js_files, {"JS_RECON_SOURCE_MAPS": True})
        assert out == []
        fetch.assert_not_called()


class TestRunLevelReporting:
    def test_a_down_host_is_reported_per_host_and_kept_by_the_prune(self):
        _mark_down("dead.example.test")
        combined = {
            "metadata": {"project_id": "p1"},
            "resource_enum": {"by_base_url": {}},
            "http_probe": {"by_url": {}},
        }
        urls = ["https://dead.example.test/a.js"]
        with mock.patch.object(jr, "_collect_js_urls", return_value=urls), \
             mock.patch.object(jr, "_load_uploaded_files", return_value=[]), \
             mock.patch.object(jr, "_safe_redirect_get", return_value=_resp()):
            out = jr.run_js_recon(combined, {"JS_RECON_MAX_FILES": 10})
        payload = out["js_recon"]
        assert "dead.example.test:443" in payload.get("unreachable_hosts", [])
        report = cb.coverage_report()
        assert "dead.example.test" in report.skipped_hostnames()
        # Host-level, not source-level: js_recon still prunes for other hosts.
        assert "js_recon" not in report.degraded_sources
