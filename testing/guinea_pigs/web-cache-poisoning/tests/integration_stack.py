"""
Integration / smoke / regression tests for the FULL guinea-pig stack
(nginx real cache + waitress + Flask), driven over HTTP from the host.

    python3 tests/integration_stack.py            # needs the stack up (docker compose up -d)

Env overrides: WCP_BASE (default http://localhost:9090), WCP_DIRECT (http://localhost:9091).

Covers what the unit tests can't: the real cache (HIT/MISS, poison persistence),
the two fixes this harness needed (waitress header passthrough, nginx error caching),
and a regression lock on the baseline-warming finding.
"""
import os
import re
import sys
import time
import unittest
import urllib.error
import urllib.request

BASE = os.environ.get("WCP_BASE", "http://localhost:9090")
DIRECT = os.environ.get("WCP_DIRECT", "http://localhost:9091")

_n = 0


def buster() -> str:
    """A unique cache-buster per call so tests never share a cache slot."""
    global _n
    _n += 1
    return f"t{_n}_{int(time.time() * 1000) % 100000}"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None  # don't follow -> 3xx surfaces as HTTPError


_opener = urllib.request.build_opener(_NoRedirect)


def get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        r = _opener.open(req, timeout=15)
        return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read().decode("utf-8", "replace")


def _stack_up() -> bool:
    try:
        return get(f"{BASE}/health")[0] == 200
    except Exception:
        return False


@unittest.skipUnless(_stack_up(), f"guinea-pig stack not reachable at {BASE} (docker compose up -d)")
class TestSmoke(unittest.TestCase):
    def test_landing_and_health(self):
        self.assertEqual(get(f"{BASE}/health")[0], 200)
        st, _, body = get(f"{BASE}/")
        self.assertEqual(st, 200)
        self.assertIn("Guinea Pig", body)

    def test_every_linked_endpoint_reachable(self):
        _, _, body = get(f"{BASE}/")
        paths = sorted(set(re.findall(r'href="(/[^"]+)"', body)))
        self.assertGreaterEqual(len(paths), 20, "landing page should link the full endpoint set")
        for p in paths:
            st, _, _ = get(f"{BASE}{p}?rdmncb={buster()}")
            # Clean GET (no poison header): everything is 200 except the static redirect.
            ok = st in (200, 301, 302)
            self.assertTrue(ok, f"{p} returned {st} on a clean GET")


@unittest.skipUnless(_stack_up(), "stack not up")
class TestCacheBehaviour(unittest.TestCase):
    def test_cacheable_endpoint_miss_then_hit(self):
        u = f"{BASE}/oracle/cache-control?rdmncb={buster()}"
        self.assertEqual(get(u)[1].get("x-cache-status"), "MISS")
        self.assertEqual(get(u)[1].get("x-cache-status"), "HIT")

    def test_no_store_never_caches(self):
        u = f"{BASE}/oracle/no-store?rdmncb={buster()}"
        get(u)
        self.assertEqual(get(u)[1].get("x-cache-status"), "MISS")  # still MISS == never stored

    def test_buster_isolates_into_separate_slots(self):
        a = f"{BASE}/oracle/cache-control?rdmncb={buster()}"
        b = f"{BASE}/oracle/cache-control?rdmncb={buster()}"
        get(a)  # warm a
        self.assertEqual(get(b)[1].get("x-cache-status"), "MISS")  # b is a fresh slot


@unittest.skipUnless(_stack_up(), "stack not up")
class TestPoisoningPersists(unittest.TestCase):
    """Attacker order (poison first): the poisoned response is cached and served
    to a header-less victim -> the harness is a genuine WCP target."""

    def test_reflected_redirect_persists(self):
        u = f"{BASE}/poison/xfh-redirect?rdmncb={buster()}"
        get(u, {"X-Forwarded-Host": "evil.itest"})
        st, hdr, _ = get(u)
        self.assertEqual(hdr.get("location"), "https://evil.itest/welcome")
        self.assertEqual(hdr.get("x-cache-status"), "HIT")

    def test_reflected_script_persists(self):
        u = f"{BASE}/poison/xfh-script?rdmncb={buster()}"
        get(u, {"X-Forwarded-Host": "evil.itest"})
        self.assertIn("https://evil.itest/static/app.js", get(u)[2])

    def test_differential_cpdos_persists(self):
        u = f"{BASE}/diff/status-dos?rdmncb={buster()}"
        get(u, {"X-Forwarded-Host": "x"})
        st, hdr, _ = get(u)
        self.assertEqual(st, 403)                       # victim gets the cached error
        self.assertEqual(hdr.get("x-cache-status"), "HIT")

    def test_differential_proto_redirect_persists(self):
        u = f"{BASE}/diff/proto-redirect?rdmncb={buster()}"
        get(u, {"X-Forwarded-Proto": "https"})
        self.assertEqual(get(u)[0], 301)

    def test_differential_body_persists(self):
        u = f"{BASE}/diff/body-banner?rdmncb={buster()}"
        get(u, {"X-Forwarded-Host": "x"})
        self.assertIn("MAINTENANCE", get(u)[2])

    def test_nextjs_token_cpdos_persists(self):
        u = f"{BASE}/fw/nextjs?rdmncb={buster()}"
        get(u, {"x-invoke-status": "rdmntok"})          # module-style token value
        self.assertEqual(get(u)[0], 503)


@unittest.skipUnless(_stack_up(), "stack not up")
class TestNegativeControls(unittest.TestCase):
    def test_keyed_header_not_served_to_victim(self):
        u = f"{BASE}/safe/keyed-xfh?rdmncb={buster()}"
        get(u, {"X-Forwarded-Host": "evil.keyed"})
        self.assertNotIn("evil.keyed", get(u)[2])  # different key -> victim never sees it

    def test_no_store_reflection_never_persists(self):
        u = f"{BASE}/safe/reflect-no-store?rdmncb={buster()}"
        get(u, {"X-Forwarded-Host": "evil.ns"})
        self.assertNotIn("evil.ns", get(u)[2])

    def test_dynamic_body_differs(self):
        # Distinct busters -> distinct origin renders -> different bodies (FP-guard fuel).
        self.assertNotEqual(
            get(f"{BASE}/safe/dynamic?rdmncb={buster()}")[2],
            get(f"{BASE}/safe/dynamic?rdmncb={buster()}")[2],
        )


@unittest.skipUnless(_stack_up(), "stack not up")
class TestFalsePositiveTraps(unittest.TestCase):
    """The cache behaviour each trap depends on, through the real nginx."""

    def test_query_ignored_busters_share_one_entry(self):
        get(f"{BASE}/safe/query-ignored?rdmncb={buster()}")
        hdr = get(f"{BASE}/safe/query-ignored?rdmncb={buster()}")[1]
        self.assertEqual(hdr.get("x-cache-status"), "HIT")  # a fresh buster still HITs

    def test_flaky_error_is_cached_for_its_slot(self):
        for _ in range(7):  # one of any 7 consecutive origin renders is the 503
            u = f"{BASE}/safe/flaky?rdmncb={buster()}"
            if get(u)[0] == 503:
                st, hdr, _ = get(u)
                self.assertEqual((st, hdr.get("x-cache-status")), (503, "HIT"))
                return
        self.fail("no 503 in 7 consecutive renders")

    def test_utm_cookie_response_with_set_cookie_is_not_cached(self):
        u = f"{BASE}/safe/utm-cookie?rdmncb={buster()}&utm_source=rdmntrap"
        get(u)
        self.assertNotEqual(get(u)[1].get("x-cache-status"), "HIT")
        # ...while a client replaying the cookie gets its value back from the origin.
        v = f"{BASE}/safe/utm-cookie?rdmncb={buster()}"
        self.assertIn("rdmntrap", get(v, {"Cookie": "utm_source=rdmntrap"})[2])

    def test_waf_block_is_uncached(self):
        u = f"{BASE}/safe/waf?rdmncb={buster()}"
        st, hdr, _ = get(u, {"X-Forwarded-For": "127.0.0.1"})
        self.assertEqual(st, 403)
        self.assertIn("no-store", hdr.get("cache-control", ""))
        # The block is per path and time-boxed; let it lapse so later tests see 200.
        deadline = time.time() + 12
        while get(f"{BASE}/safe/waf?rdmncb={buster()}")[0] == 403 and time.time() < deadline:
            time.sleep(0.5)


@unittest.skipUnless(_stack_up(), "stack not up")
class TestRegressions(unittest.TestCase):
    """Lock the findings/fixes this harness produced."""

    def test_baseline_warming_defeats_same_buster_poison(self):
        # THE finding: baseline-first on the SAME buster warms the cache clean, so the
        # later poison HITs clean and never lands. This MUST stay reproducible until the
        # confirmer is changed to poison-first.
        u = f"{BASE}/poison/xfh-redirect?rdmncb={buster()}"
        _, base_hdr, _ = get(u)                                   # baseline (no header) -> caches clean
        self.assertEqual(base_hdr.get("location"), "https://guinea.local/welcome")
        _, pois_hdr, _ = get(u, {"X-Forwarded-Host": "evil.warm"})  # poison -> HIT cached clean
        self.assertEqual(pois_hdr.get("location"), "https://guinea.local/welcome")
        self.assertEqual(pois_hdr.get("x-cache-status"), "HIT")

    def test_waitress_forwards_x_forwarded_headers(self):
        # Regression: waitress strips X-Forwarded-* by default; we disabled that so the
        # vectors reach the app. A fresh-buster poison MUST reflect the attacker value.
        u = f"{BASE}/poison/xfh-script?rdmncb={buster()}"
        self.assertIn("evil.fwd", get(u, {"X-Forwarded-Host": "evil.fwd"})[2])

    def test_nginx_caches_error_status_for_cpdos(self):
        # Regression: proxy_cache_valid must include 403 so CPDoS actually persists.
        u = f"{BASE}/diff/status-dos?rdmncb={buster()}"
        self.assertEqual(get(u, {"X-Forwarded-Host": "x"})[1].get("x-cache-status"), "MISS")
        self.assertEqual(get(u)[1].get("x-cache-status"), "HIT")


@unittest.skipUnless(_stack_up(), "stack not up")
class TestSilentCacheDirect(unittest.TestCase):
    def test_frozen_date_via_direct_port(self):
        try:
            u = f"{DIRECT}/silent/page?rdmncb={buster()}"
            d1 = get(u)[1].get("date")
            time.sleep(1.1)
            d2 = get(u)[1].get("date")
        except Exception as e:  # pragma: no cover
            self.skipTest(f"direct port {DIRECT} unreachable: {e}")
        self.assertIsNotNone(d1)
        self.assertEqual(d1, d2, "silent cache must replay a frozen Date")


if __name__ == "__main__":
    unittest.main(verbosity=2)
