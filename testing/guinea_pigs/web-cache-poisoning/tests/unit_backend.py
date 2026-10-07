"""
Unit tests for the guinea-pig ORIGIN logic (Flask app, via test_client).

Runs INSIDE the backend container (the only place Flask + app.py live):

    docker compose exec backend python tests/unit_backend.py

test_client passes headers straight to the app (no waitress header-stripping, no
nginx caching), so these isolate the *response-shaping* logic of every endpoint:
reflection, differential behaviour, oracle headers, framework reactions, negative
controls, and the frozen-Date silent cache.
"""
import sys
import unittest

sys.path.insert(0, "/app")
import app as guinea  # noqa: E402


def client():
    guinea.app.testing = True
    return guinea.app.test_client()


def cc(resp) -> str:
    return resp.headers.get("Cache-Control", "")


class TestSmokeApp(unittest.TestCase):
    def setUp(self):
        self.c = client()

    def test_landing_lists_every_registered_endpoint(self):
        r = self.c.get("/")
        self.assertEqual(r.status_code, 200)
        body = r.get_data(as_text=True)
        for path, _, _ in guinea.REGISTRY:
            self.assertIn(f'href="{path}"', body, f"{path} missing from landing page")
        self.assertIn("public", cc(r))  # landing is cacheable

    def test_health(self):
        r = self.c.get("/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_data(as_text=True), "ok")

    def test_registry_paths_unique(self):
        paths = [p for p, _, _ in guinea.REGISTRY]
        self.assertEqual(len(paths), len(set(paths)))


class TestOracleSignals(unittest.TestCase):
    def setUp(self):
        self.c = client()

    def test_cache_control_eligible(self):
        self.assertIn("public", cc(self.c.get("/oracle/cache-control")))

    def test_age_present(self):
        self.assertEqual(self.c.get("/oracle/age").headers.get("Age"), "137")

    def test_cf_cache_status(self):
        self.assertEqual(self.c.get("/oracle/cf-cache-status").headers.get("CF-Cache-Status"), "HIT")

    def test_x_cache(self):
        self.assertEqual(self.c.get("/oracle/x-cache").headers.get("X-Cache"), "HIT")

    def test_via_presence(self):
        self.assertIn("varnish", self.c.get("/oracle/via").headers.get("Via", ""))

    def test_fastly_headers(self):
        r = self.c.get("/oracle/x-served-by")
        self.assertTrue(r.headers.get("X-Served-By"))
        self.assertEqual(r.headers.get("X-Cache-Hits"), "2")

    def test_vary_keyed_header(self):
        self.assertEqual(self.c.get("/oracle/vary").headers.get("Vary"), "X-Forwarded-Host")

    def test_negative_no_store(self):
        self.assertIn("no-store", cc(self.c.get("/oracle/no-store")))

    def test_negative_cf_dynamic(self):
        r = self.c.get("/oracle/cf-dynamic")
        self.assertEqual(r.headers.get("CF-Cache-Status"), "DYNAMIC")
        self.assertIn("private", cc(r))


class TestReflected(unittest.TestCase):
    def setUp(self):
        self.c = client()

    def test_xfh_redirect_reflects_into_location(self):
        r = self.c.get("/poison/xfh-redirect", headers={"X-Forwarded-Host": "evil.unit"})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers["Location"], "https://evil.unit/welcome")
        self.assertIn("public", cc(r))

    def test_xfh_script_reflects_into_body(self):
        r = self.c.get("/poison/xfh-script", headers={"X-Forwarded-Host": "evil.unit"})
        self.assertIn("https://evil.unit/static/app.js", r.get_data(as_text=True))

    def test_x_host_reflects_into_link(self):
        r = self.c.get("/poison/x-host-link", headers={"X-Host": "assets.unit"})
        self.assertIn("https://assets.unit/style.css", r.get_data(as_text=True))

    def test_x_forwarded_server_reflects(self):
        r = self.c.get("/poison/x-forwarded-server", headers={"X-Forwarded-Server": "origin.unit"})
        self.assertIn("origin.unit", r.get_data(as_text=True))

    def test_x_original_url_reflects(self):
        r = self.c.get("/poison/x-original-url", headers={"X-Original-URL": "/secret-admin"})
        self.assertIn("/secret-admin", r.get_data(as_text=True))

    def test_x_rewrite_url_reflects(self):
        r = self.c.get("/poison/x-rewrite-url", headers={"X-Rewrite-URL": "/rew"})
        self.assertIn("/rew", r.get_data(as_text=True))

    def test_clean_request_has_no_attacker_value(self):
        self.assertNotIn("evil", self.c.get("/poison/xfh-script").get_data(as_text=True))


class TestDifferential(unittest.TestCase):
    def setUp(self):
        self.c = client()

    def test_proto_https_flips_to_redirect(self):
        clean = self.c.get("/diff/proto-redirect")
        self.assertEqual(clean.status_code, 200)
        pois = self.c.get("/diff/proto-redirect", headers={"X-Forwarded-Proto": "https"})
        self.assertEqual(pois.status_code, 301)
        self.assertIn("secure.guinea.local", pois.headers["Location"])

    def test_host_header_triggers_403(self):
        self.assertEqual(self.c.get("/diff/status-dos").status_code, 200)
        self.assertEqual(self.c.get("/diff/status-dos", headers={"X-Forwarded-Host": "x"}).status_code, 403)

    def test_host_header_swaps_body(self):
        self.assertIn("live shop", self.c.get("/diff/body-banner").get_data(as_text=True))
        self.assertIn("MAINTENANCE",
                      self.c.get("/diff/body-banner", headers={"X-Forwarded-Host": "x"}).get_data(as_text=True))

    def test_no_marker_echoed_in_differential(self):
        # The canary host is NOT reflected for status/body diffs (truly non-reflective).
        r = self.c.get("/diff/status-dos", headers={"X-Forwarded-Host": "rdmncanary.invalid"})
        self.assertNotIn("rdmncanary", r.get_data(as_text=True))


class TestFrameworkPacks(unittest.TestCase):
    def setUp(self):
        self.c = client()

    def test_nextjs_fingerprint(self):
        r = self.c.get("/fw/nextjs")
        self.assertEqual(r.headers.get("X-Powered-By"), "Next.js")
        self.assertIn("__NEXT_DATA__", r.get_data(as_text=True))

    def test_nextjs_token_invoke_status_triggers_cpdos(self):
        # The module sends a non-numeric token; presence alone must trip the error.
        r = self.c.get("/fw/nextjs", headers={"x-invoke-status": "rdmntok"})
        self.assertEqual(r.status_code, 503)

    def test_nextjs_numeric_invoke_status_honoured(self):
        self.assertEqual(self.c.get("/fw/nextjs", headers={"x-invoke-status": "404"}).status_code, 404)

    def test_nuxt_fingerprint(self):
        self.assertIn("__NUXT__", self.c.get("/fw/nuxt").get_data(as_text=True))

    def test_remix_data_reflects(self):
        self.assertIn("routes/admin", self.c.get("/fw/remix?_data=routes/admin").get_data(as_text=True))


class TestNegativeControls(unittest.TestCase):
    def setUp(self):
        self.c = client()

    def test_no_reflect_ignores_headers(self):
        r = self.c.get("/safe/no-reflect", headers={"X-Forwarded-Host": "evil"})
        self.assertNotIn("evil", r.get_data(as_text=True))

    def test_dynamic_body_changes_each_request(self):
        a = self.c.get("/safe/dynamic").get_data(as_text=True)
        b = self.c.get("/safe/dynamic").get_data(as_text=True)
        self.assertNotEqual(a, b)

    def test_reflect_no_store_is_uncacheable(self):
        r = self.c.get("/safe/reflect-no-store", headers={"X-Forwarded-Host": "evil.ns"})
        self.assertIn("evil.ns", r.get_data(as_text=True))  # reflects
        self.assertIn("no-store", cc(r))                    # but never cached

    def test_keyed_xfh_reflects_at_origin(self):
        # The origin reflects; the cache-key isolation is enforced by nginx (integration).
        r = self.c.get("/safe/keyed-xfh", headers={"X-Forwarded-Host": "evil.k"})
        self.assertIn("evil.k", r.get_data(as_text=True))


class TestSilentCache(unittest.TestCase):
    def setUp(self):
        self.c = client()

    def test_frozen_date_and_single_date_header(self):
        r1 = self.c.get("/silent/page?rdmncb=u1")
        r2 = self.c.get("/silent/page?rdmncb=u1")
        # Same body and the SAME replayed Date -> a silent (Date-replaying) cache.
        self.assertEqual(r1.get_data(as_text=True), r2.get_data(as_text=True))
        self.assertEqual(r1.headers.get("Date"), r2.headers.get("Date"))
        self.assertEqual(len(r1.headers.get_all("Date")), 1)
        # No recognised cache-status header -> stays "silent".
        self.assertEqual(r1.headers.get("Cache-Control"), None)

    def test_distinct_buster_distinct_entry(self):
        d1 = self.c.get("/silent/page?rdmncb=a").headers.get("Date")
        # A different buster is a different cache key -> may differ; same buster is frozen.
        d1b = self.c.get("/silent/page?rdmncb=a").headers.get("Date")
        self.assertEqual(d1, d1b)


class TestFalsePositiveTraps(unittest.TestCase):
    def setUp(self):
        self.c = client()
        guinea._RENDERS.clear()
        guinea._WAF_BLOCK_UNTIL.clear()

    def test_drift_changes_with_the_clock(self):
        from unittest.mock import patch
        with patch.object(guinea.time, "time", return_value=1000.0):
            a = self.c.get("/safe/drift").get_data(as_text=True)
        with patch.object(guinea.time, "time", return_value=1001.0):
            b = self.c.get("/safe/drift").get_data(as_text=True)
        self.assertNotEqual(a, b)
        self.assertIn("public", cc(self.c.get("/safe/drift")))

    def test_ab_variant_serves_both_variants(self):
        bodies = {self.c.get("/safe/ab-variant").get_data(as_text=True) for _ in range(60)}
        self.assertEqual(len(bodies), 2)

    def test_rare_banner_is_rare(self):
        shown = sum("SUMMER SALE" in self.c.get("/safe/rare-banner").get_data(as_text=True)
                    for _ in range(500))
        self.assertTrue(10 <= shown <= 120, shown)

    def test_utm_cookie_sets_on_query_and_replays_from_cookie(self):
        r = self.c.get("/safe/utm-cookie?utm_source=rdmnab")
        self.assertIn("rdmnab", r.get_data(as_text=True))
        self.assertIn("utm_source=rdmnab", r.headers.get("Set-Cookie", ""))
        self.c.set_cookie("utm_source", "rdmncd")
        r = self.c.get("/safe/utm-cookie")
        self.assertIn("rdmncd", r.get_data(as_text=True))
        self.assertIsNone(r.headers.get("Set-Cookie"))  # cookie-sourced: cacheable

    def test_flaky_fails_every_seventh_render(self):
        codes = [self.c.get("/safe/flaky").status_code for _ in range(14)]
        self.assertEqual([i + 1 for i, s in enumerate(codes) if s == 503], [7, 14])

    def test_waf_blocks_after_a_spoofed_client_ip(self):
        from unittest.mock import patch
        with patch.object(guinea.time, "time", return_value=1000.0):
            self.assertEqual(self.c.get("/safe/waf").status_code, 200)
            r = self.c.get("/safe/waf", headers={"X-Forwarded-For": "127.0.0.1"})
            self.assertEqual(r.status_code, 403)
            self.assertIn("no-store", cc(r))
            self.assertEqual(self.c.get("/safe/waf").status_code, 403)  # still blocked
        with patch.object(guinea.time, "time", return_value=1009.0):
            self.assertEqual(self.c.get("/safe/waf").status_code, 200)

    def test_query_ignored_reflects_xfh(self):
        r = self.c.get("/safe/query-ignored", headers={"X-Forwarded-Host": "evil.q"})
        self.assertIn("evil.q", r.get_data(as_text=True))


class TestHelpers(unittest.TestCase):
    def test_first_host_header_priority(self):
        with guinea.app.test_request_context(headers={"X-Host": "h2"}):
            self.assertEqual(guinea.first_host_header(), "h2")
        with guinea.app.test_request_context(headers={"X-Forwarded-Host": "h1", "X-Host": "h2"}):
            self.assertEqual(guinea.first_host_header(), "h1")  # XFH has priority
        with guinea.app.test_request_context():
            self.assertIsNone(guinea.first_host_header())


if __name__ == "__main__":
    unittest.main(verbosity=2)
